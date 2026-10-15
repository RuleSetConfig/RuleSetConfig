#!/usr/bin/env python3
"""Compile isolated fixtures and check their actual sing-box binary matches."""
import argparse
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
from domain_keywords import read_inline_keywords

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
                subprocess.run([args.sing_box, "rule-set", "compile", "-o",
                                str(root/f"{name}.srs"), str(root/f"{name}.json")], check=True)
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
                subprocess.run([args.sing_box, "rule-set", "compile", "-o",
                                str(candidate / f"{name}.srs"),
                                str(candidate / f"{name}.json")], check=True)
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
                path.with_suffix(".json").write_text(json.dumps({"version": 2, "rules": [rule]}))
                subprocess.run([args.sing_box, "rule-set", "compile", "-o", str(path.with_suffix(".srs")),
                                str(path.with_suffix(".json"))], check=True)
                for host, expected in cases.items():
                    result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                             str(path.with_suffix(".srs")), host], text=True, capture_output=True, check=True)
                    actual = "match rules." in result.stdout + result.stderr
                    if actual != expected:
                        raise AssertionError(("inline-keyword", policy, label, host, expected, actual))
                    tested += 1
    print(f"native sing-box matching: {tested}/{tested} passed")


if __name__ == "__main__":
    main()
