#!/usr/bin/env python3
"""Compile isolated fixtures and check their actual sing-box binary matches."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("merge_filter", ROOT / "scripts/merge-filter.py")
merge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge)
spec = importlib.util.spec_from_file_location("native_domain_sync", ROOT / "scripts/sync-domain-sets.py")
domain_sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(domain_sync)
spec = importlib.util.spec_from_file_location("native_apnic", ROOT / "scripts/sync-apnic-cn.py")
apnic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apnic)
from domain_keywords import read_inline_keywords
from filter_exclusions import read_domain_exclusions, remove_domain_exclusions
from ip_rulesets import read_networks, subtract, write_ip_source
from ruleset_format import RULE_SET_VERSION, compile_ruleset

CASES = [
    ("0.0.0.0 ads.example.com", {
        "ads.example.com": True, "child.ads.example.com": False,
        "example.com": False}),
    ("||ads.example.com^", {
        "ads.example.com": True, "child.ads.example.com": True,
        "notads.example.com": False}),
    ("-ad123-", {"x-ad123-y.example": True, "ad123.example": False}),
    ("-applog*.fqnovel.com^", {
        "api-applog.fqnovel.com": True, "x.api-applog.foo.fqnovel.com": True,
        "applog.fqnovel.com": False, "www.fqnovel.com": False,
        "api-applog.fqnovel.com.evil.net": False}),
    ("||ad*.example.com^", {
        "ad.example.com": True, "x.ads.example.com": True,
        "bad.example.com": False, "ads.example.com.evil": False}),
    (r"/^(a|c)\.[0-9a-f]{56}\.com$/", {
        "a." + "a0" * 28 + ".com": True,
        "c." + "af" * 28 + ".com": True,
        "b." + "a0" * 28 + ".com": False,
        "a." + "a0" * 27 + ".com": False}),
    (r"/^94\.242\.247\.(2[0-9]|3[0-2])/", {
        "94.242.247.20": True, "94.242.247.200": True,
        "94.242.247.32": True, "94.242.247.33": False,
        "94.242.248.20": False}),
    ("||194.63.143.96^", {"194.63.143.96": True, "194.63.143.97": False}),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", default="sing-box")
    args = parser.parse_args()
    tested = 0
    with tempfile.TemporaryDirectory(prefix="native-filter-") as directory:
        root = Path(directory)
        for text, cases in CASES:
            entries, reason = merge.domain_rule(text)
            if entries is None:
                raise AssertionError((text, reason))
            suffix = {v for k, v in entries if k == "domain_suffix"}
            exact = {v for k, v in entries if k == "domain"}
            patterns = {(k, v) for k, v in entries if k not in {"domain", "domain_suffix"}}
            merge.write_filter_partitions(suffix, exact, patterns, root)
            for name in merge.PARTITIONS:
                compile_ruleset(root / f"{name}.json", root / f"{name}.srs", args.sing_box)
            for host, expected in cases.items():
                outputs = []
                for name in merge.PARTITIONS:
                    result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                             str(root/f"{name}.srs"), host],
                                            text=True, capture_output=True, check=True)
                    outputs.append(result.stdout + result.stderr)
                actual = any("match rules." in output for output in outputs)
                if actual != expected:
                    raise AssertionError((text, host, expected, outputs))
                tested += 1
        # The reviewed SDK exclusion must survive compilation without allowing reports.
        suffix, exact, _ = remove_domain_exclusions(
            {"beacon.cdn.qq.com", "otheve.beacon.qq.com", "h.trace.qq.com"},
            {"beacon.cdn.qq.com"}, read_domain_exclusions())
        merge.write_filter_partitions(suffix, exact, set(), root)
        for name in merge.PARTITIONS:
            compile_ruleset(root / f"{name}.json", root / f"{name}.srs", args.sing_box)
        for host, expected in {"beacon.cdn.qq.com": False,
                               "child.beacon.cdn.qq.com": False,
                               "otheve.beacon.qq.com": True,
                               "child.otheve.beacon.qq.com": True,
                               "h.trace.qq.com": True,
                               "beacon.cdn.qq.com.evil.net": False,
                               "safe.qq.com": False}.items():
            matched = False
            for name in merge.PARTITIONS:
                result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                         str(root / f"{name}.srs"), host],
                                        text=True, capture_output=True, check=True)
                matched |= "match rules." in (result.stdout + result.stderr)
            if matched != expected:
                raise AssertionError(("reviewed domain exclusion", host, expected, matched))
            tested += 1
        # Parent pruning must preserve the combined domain/pattern behavior.
        suffix = {"example.com"}
        exact = {"exact.example.net"}
        patterns = {("domain_wildcard", "*-ad-*.example.com"),
                    ("domain_wildcard", "*.example.com"),
                    ("domain_wildcard", "*example.com"),
                    ("domain_wildcard", "*.example.com*"),
                    ("domain_wildcard", "*.exact.example.net")}
        cases = {"example.com": True, "x-ad-y.example.com": True,
                 "deep.ads.example.com": True, "notexample.com": True,
                 "ads.example.com.invalid": True, "exact.example.net": True,
                 "child.exact.example.net": True, "safe.example.net": False,
                 "ads.example.org": False}
        for label, entries in (("before", patterns),
                               ("after", merge.prune_patterns(suffix, patterns))):
            candidate = root / label
            merge.write_filter_partitions(suffix, exact, entries, candidate)
            for name in merge.PARTITIONS:
                compile_ruleset(candidate / f"{name}.json", candidate / f"{name}.srs", args.sing_box)
            for host, expected in cases.items():
                actual = False
                for name in merge.PARTITIONS:
                    result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                             str(candidate / f"{name}.srs"), host],
                                            text=True, capture_output=True, check=True)
                    actual |= "match rules." in (result.stdout + result.stderr)
                if actual != expected:
                    raise AssertionError(("parent-pruning", label, host, expected, actual))
                tested += 1

        # Suffixes and exact hosts go through the actual list-to-SRS compiler.
        (root / "PROXY_SET.list").write_text("# TLDs\n// Surge comments\n.ai\n.app\nuse.fortawesome.com\n", encoding="utf-8")
        (root / "DIRECT_SET.list").write_text(".cn\n.amap.com\n.qq.com\n", encoding="utf-8")
        subprocess.run([sys.executable, str(ROOT / "scripts/verify-all.py"),
                        "--compile-tld", "--root", str(root), "--sing-box", args.sing_box], check=True)
        tld_cases = {
            "PROXY_SET": {"ai": True, "example.ai": True, "deep.example.ai": True,
                          "example.app": True, "notai": False, "example.ai.invalid": False,
                          "example.com": False, "example.cn": False,
                          "use.fortawesome.com": True, "child.use.fortawesome.com": False,
                          "fortawesome.com": False, "use.fortawesome.com.invalid": False},
            "DIRECT_SET": {"cn": True, "example.cn": True, "example.com.cn": True,
                           "amap.com": True, "restapi.amap.com": True,
                           "qq.com": True, "www.qq.com": True, "deep.api.qq.com": True,
                           "notamap.com": False, "amap.com.invalid": False,
                           "notqq.com": False, "qq.com.invalid": False,
                           "notcn": False, "example.cn.invalid": False,
                           "example.ai": False, "192.0.2.1": False},
        }
        for name, cases in tld_cases.items():
            for host, expected in cases.items():
                result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                         str(root / f"{name}.srs"), host],
                                        text=True, capture_output=True, check=True)
                actual = "match rules." in (result.stdout + result.stderr)
                if actual != expected:
                    raise AssertionError((name, host, expected, result.stdout, result.stderr))
                tested += 1
        # An exact-only list must not acquire suffix or match-all behavior.
        (root / "PROXY_SET.list").write_text("exact.example.com\n", encoding="utf-8")
        subprocess.run([sys.executable, str(ROOT / "scripts/verify-all.py"),
                        "--compile-tld", "--root", str(root), "--sing-box", args.sing_box], check=True)
        for host, expected in {"exact.example.com": True, "child.exact.example.com": False,
                               "example.com": False, "unrelated.example.net": False}.items():
            result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                     str(root / "PROXY_SET.srs"), host],
                                    text=True, capture_output=True, check=True)
            actual = "match rules." in (result.stdout + result.stderr)
            if actual != expected:
                raise AssertionError(("exact-only", host, expected, result.stdout, result.stderr))
            tested += 1
        # Removing fixed domain entries covered by same-policy inline keywords
        # must preserve the combined routing language, including substring matches.
        policies = read_inline_keywords(ROOT)
        for policy, keywords in policies.items():
            word = keywords[0]
            other_word = policies["direct" if policy == "proxy" else "proxy"][0]
            custom = {".keep.example.com", "exact.safe.example.net",
                      f".{word}.example.org", f"prefix-{word}-cdn.example.net",
                      f".{other_word}.retained.example.net"}
            empty = {"domain": set(), "domain_suffix": set(), "domain_regex": set()}
            before, _ = domain_sync.merge_entries(custom, set(), empty)
            after, audit = domain_sync.merge_entries(custom, set(), empty, keywords)
            if audit["keyword_covered_entries_removed"] != 2:
                raise AssertionError((policy, audit))
            cases = {
                "keep.example.com": True, "child.keep.example.com": True,
                "notkeep.example.com": False, "keep.example.com.invalid": False,
                "exact.safe.example.net": True, "child.exact.safe.example.net": False,
                f"{word}.example.org": True, f"child.{word}.example.org": True,
                f"prefix-{word}-cdn.example.net": True, f"child.prefix-{word}-cdn.example.net": True,
                f"unlisted-{word}-host.example.invalid": True,
                f"{other_word}.retained.example.net": True,
                f"child.{other_word}.retained.example.net": True,
                f"unlisted-{other_word}-host.example.invalid": False,
                "unrelated.example.invalid": False,
            }
            for label, entries in (("before", before), ("after", after)):
                path = root / f"keyword-{policy}-{label}"
                rule = {"domain_suffix": sorted(entry[1:] for entry in entries if entry.startswith(".")),
                        "domain": sorted(entry for entry in entries if not entry.startswith(".")),
                        "domain_keyword": list(keywords)}
                path.with_suffix(".json").write_text(json.dumps({"version": RULE_SET_VERSION, "rules": [rule]}))
                compile_ruleset(path.with_suffix(".json"), path.with_suffix(".srs"), args.sing_box)
                for host, expected in cases.items():
                    result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                             str(path.with_suffix(".srs")), host], text=True, capture_output=True, check=True)
                    actual = "match rules." in result.stdout + result.stderr
                    if actual != expected:
                        raise AssertionError(("inline-keyword", policy, label, host, expected, actual))
                    tested += 1
        # Removing wholly proxy-covered direct rules preserves proxy-first routing.
        # Exact proxy hosts must leave direct suffix descendants available.
        proxy_entries = {".hk", ".proxy.example.net", "exact.example.com",
                         "exact-only.example.org", ".child.partial.example.org"}
        direct_before = {".school.hk", ".proxy.example.net", ".exact.example.com",
                         "exact-only.example.org", ".partial.example.org",
                         ".keep.example.org", ".notproxy.example.net"}
        direct_after, removed = domain_sync.prune_direct_entries(direct_before, proxy_entries)
        if len(removed) != 3:
            raise AssertionError(("cross-set removal audit", removed))
        paths = {}
        for label, entries in (("proxy", proxy_entries), ("direct-before", direct_before),
                               ("direct-after", direct_after)):
            path = root / f"cross-set-{label}"
            rule = {"domain_suffix": sorted(entry[1:] for entry in entries if entry.startswith(".")),
                    "domain": sorted(entry for entry in entries if not entry.startswith("."))}
            path.with_suffix(".json").write_text(json.dumps({"version": RULE_SET_VERSION, "rules": [rule]}))
            paths[label] = path.with_suffix(".srs")
            compile_ruleset(path.with_suffix(".json"), paths[label], args.sing_box)
        cases = {"school.hk": "proxy", "child.school.hk": "proxy",
                 "proxy.example.net": "proxy", "child.proxy.example.net": "proxy",
                 "exact.example.com": "proxy", "child.exact.example.com": "direct",
                 "exact-only.example.org": "proxy", "child.exact-only.example.org": None,
                 "partial.example.org": "direct", "child.partial.example.org": "proxy",
                 "other.partial.example.org": "direct", "keep.example.org": "direct",
                 "notproxy.example.net": "direct", "proxy.example.net.invalid": None}
        for host, expected in cases.items():
            matches = {}
            for label, path in paths.items():
                result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary", str(path), host],
                                        text=True, capture_output=True, check=True)
                matches[label] = "match rules." in result.stdout + result.stderr
            for label in ("before", "after"):
                actual = ("proxy" if matches["proxy"] else
                          "direct" if matches["direct-" + label] else None)
                if actual != expected:
                    raise AssertionError(("cross-set routing", label, host, expected, actual))
                tested += 1
        # APNIC IPv4 values are counts, IPv6 values are prefix lengths. Exercise
        # CN/status selection and exact range boundaries through the generated SRS.
        rows = ["apnic|CN|ipv4|192.0.2.1|3|20200101|allocated",
                "apnic|CN|ipv4|192.0.2.4|4|20200101|assigned",
                "apnic|CN|ipv4|192.0.2.8|8|20200101|available",
                "apnic|US|ipv4|192.0.2.128|128|20200101|allocated",
                "apnic|CN|ipv6|2001:db8::|127|20200101|allocated",
                "apnic|CN|ipv6|2001:db8::2|127|20200101|assigned",
                "apnic|CN|ipv6|2001:db8:1::|48|20200101|reserved",
                "apnic|HK|ipv6|2001:db8:2::|48|20200101|allocated"]
        counts = Counter(row.split("|")[2] for row in rows)
        source = [f"2|apnic|20261015|{len(rows)}|19830613|20261014|+1000"]
        source.extend(f"apnic|*|{kind}|*|{count}|summary" for kind, count in sorted(counts.items()))
        networks, _ = apnic.parse_delegated("\n".join([*source, *rows]) + "\n")
        candidate = root / "apnic"
        apnic.write_ip_source(networks, candidate)
        compile_ruleset(candidate / "DIRECT-IP-SET.json", candidate / "DIRECT-IP-SET.srs", args.sing_box)
        cases = {"192.0.2.0": False, "192.0.2.1": True, "192.0.2.3": True,
                 "192.0.2.4": True, "192.0.2.7": True, "192.0.2.8": False,
                 "192.0.2.128": False, "192.0.2.255": False,
                 "2001:db8::": True, "2001:db8::1": True, "2001:db8::3": True,
                 "2001:db8::4": False, "2001:db8:1::": False, "2001:db8:2::": False,
                 "example.com": False}
        for host, expected in cases.items():
            result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                     str(candidate / "DIRECT-IP-SET.srs"), host], text=True, capture_output=True, check=True)
            actual = "match rules." in result.stdout + result.stderr
            if actual != expected:
                raise AssertionError(("APNIC", host, expected, actual))
            tested += 1
        # Cut inline holes out of larger sources, then test compiled boundaries.
        import ipaddress
        networks = [ipaddress.ip_network(cidr) for cidr in (
            "16.0.0.0/7", "91.104.0.0/13", "2001:b28::/32", "2403::/16", "8.8.8.0/24")]
        exclusions = read_networks(ROOT / "source/proxy-ip-inline.list")
        exclusions.append(ipaddress.ip_network("8.8.8.64/26"))
        candidate = root / "proxy-ip"
        write_ip_source(subtract(networks, exclusions), candidate, "PROXY-IP-SET", [])
        compile_ruleset(candidate / "PROXY-IP-SET.json", candidate / "PROXY-IP-SET.srs", args.sing_box)
        cases = {"16.0.0.0": True, "16.255.255.255": True, "17.0.0.0": False, "17.255.255.255": False,
                 "91.108.7.255": False, "91.108.8.0": False, "91.108.23.255": False, "91.108.24.0": True,
                 "2001:b28:f23c::": False, "2001:b28:f23d::1": False, "2001:b28:f23e::1": True,
                 "2403:300::1": False, "2403:301::1": True,
                 "8.8.8.63": True, "8.8.8.64": False, "8.8.8.127": False, "8.8.8.128": True,
                 "8.8.9.0": False, "example.com": False}
        for host, expected in cases.items():
            result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                     str(candidate / "PROXY-IP-SET.srs"), host], text=True, capture_output=True, check=True)
            actual = "match rules." in result.stdout + result.stderr
            if actual != expected:
                raise AssertionError(("proxy-IP-exclusions", host, expected, actual))
            tested += 1
    print(f"native sing-box matching: {tested}/{tested} passed")


if __name__ == "__main__":
    main()
