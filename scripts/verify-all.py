#!/usr/bin/env python3
"""Verify rule pairs and manifests, or compile the two manually maintained domain sets."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from filter_patterns import (wildcard_regex, covering_domain_entry, covering_suffix,
                             wildcard_covering_suffix)
from filter_ips import collapse_ip_rules, read_ip_rules
from rule_sorting import check_ruleset_order, domain_sort_key
from domain_keywords import KEYWORD_SOURCE, covering_keyword, read_inline_keywords
from ip_rulesets import intersection, read_networks, subtract

TLD_SETS = ("PROXY_SET", "DIRECT_SET")


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def verify_tld_set(path):
    """Validate suffixes and exact hosts in the two Surge DOMAIN-SET files."""
    seen = set()
    entries = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        entry = line.strip()
        if not entry or entry.startswith(("#", "//")):
            continue
        domain = entry[1:] if entry.startswith(".") else entry
        if (not domain or len(domain) > 253
                or (not entry.startswith(".") and "." not in domain)
                or not all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in domain.split(".")
                )):
            fail(f"{path}:{number}: expected a DOMAIN-SET suffix (.cn, .example.com) or exact host (example.com)")
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            fail(f"{path}:{number}: IP addresses are not DOMAIN-SET entries")
        if entry in seen:
            fail(f"{path}:{number}: duplicate domain entry {entry}")
        seen.add(entry)
        entries.append(entry)
    if not seen:
        fail(f"{path}: empty domain set")
    print(f"{path}: {len(seen)} Surge domain entries verified")
    return entries


def verify_domain_set_parent_pruning(path, entries):
    """Reject manual entries already covered by another suffix in the same set."""
    suffixes = {entry[1:] for entry in entries if entry.startswith(".")}
    redundant = []
    for entry in entries:
        domain = entry[1:] if entry.startswith(".") else entry
        parent = covering_suffix(domain, suffixes, include_self=not entry.startswith("."))
        if parent:
            redundant.append(f"{entry} covered by .{parent}")
    if redundant:
        fail(f"{path}: {len(redundant)} parent-covered domain entries remain: "
             + "; ".join(redundant[:5]))
    print(f"{path}: parent-pruning verified: no covered domain entries")
    return 0


def verify_domain_set_keyword_pruning(path, entries, keywords):
    redundant = [(entry, covering_keyword(entry, keywords)) for entry in entries
                 if covering_keyword(entry, keywords)]
    if redundant:
        fail(f"{path}: {len(redundant)} entries already covered by same-policy inline keywords: "
             + "; ".join(f"{entry} covered by {word}" for entry, word in redundant[:5]))
    print(f"{path}: inline keyword pruning verified")
    return 0


def verify_domain_set_proxy_pruning(proxy_entries, direct_entries):
    """Reject direct rules that the published proxy domain set fully covers."""
    suffixes = {entry[1:] for entry in proxy_entries if entry.startswith(".")}
    exact = {entry for entry in proxy_entries if not entry.startswith(".")}
    redundant = [
        (entry, covering)
        for entry in direct_entries
        if (covering := covering_domain_entry(entry, suffixes, exact)) is not None
    ]
    if redundant:
        fail(f"DIRECT_SET.list: {len(redundant)} entries fully covered by PROXY_SET.list: "
             + "; ".join(f"{entry} covered by {covering}" for entry, covering in redundant[:5]))
    print("cross-set pruning verified: no direct entries fully covered by the proxy set")
    return 0


def ranges(cidrs):
    """CIDRs -> the disjoint ranges they cover, keyed by address family."""
    intervals = {4: [], 6: []}
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        intervals[net.version].append((int(net.network_address), int(net.broadcast_address)))
    out = {}
    for version, items in intervals.items():
        items.sort()
        acc = []
        for start, end in items:
            if acc and start <= acc[-1][1] + 1:
                acc[-1] = (acc[-1][0], max(acc[-1][1], end))
            else:
                acc.append((start, end))
        out[version] = acc
    return out


def parse_cidr(value):
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        fail(f"invalid CIDR in the list: {value}")


def parse_list(path):
    """Surge rule lines -> {"kind": {values}}."""
    out = {"domain_suffix": set(), "domain": set(), "domain_keyword": set(), "domain_regex": set(),
           "ip_cidr": set(), "logical_and": []}
    with open(path, encoding="utf-8", errors="ignore") as f:
        for number, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith(("#", "//")):
                continue
            upper = s.upper()
            if upper.startswith("AND,("):
                terms = [t.strip() for t in s[5:].rstrip(")").split("),(")]
                keys = []
                for term in terms:
                    parts = [p.strip() for p in term.strip("()").split(",")]
                    if len(parts) < 2 or parts[0].upper() != "DOMAIN-KEYWORD":
                        fail(f"{path}:{number}: only DOMAIN-KEYWORD is supported inside AND")
                    keys.append(parts[1].lower())
                if tuple(keys) not in out["logical_and"]:
                    # Kept in source order so that rebuilding an unchanged list
                    # produces a byte-identical .srs.
                    out["logical_and"].append(tuple(keys))
            elif upper.startswith("IP-CIDR6,") or upper.startswith("IP-CIDR,"):
                out["ip_cidr"].add(parse_cidr(s.split(",", 1)[1]))
            elif s.startswith("."):
                # Domain set style: ".example.com" covers example.com and its subdomains.
                out["domain_suffix"].add(s[1:].strip(".").lower())
            elif "," not in s:
                out["domain"].add(s.lower())
            else:
                kind, value = s.split(",", 1)
                kind, value = kind.strip().upper(), value.strip().lower()
                if kind == "DOMAIN":
                    out["domain"].add(value)
                elif kind == "DOMAIN-SUFFIX":
                    out["domain_suffix"].add(value)
                elif kind == "DOMAIN-KEYWORD":
                    out["domain_keyword"].add(value)
                elif kind == "DOMAIN-WILDCARD":
                    out["domain_regex"].add(wildcard_regex(value))
                elif kind == "IP-CIDR" or kind == "IP-CIDR6":
                    out["ip_cidr"].add(parse_cidr(value))
                else:
                    fail(f"{path}:{number}: unsupported rule type {kind}")
    return out


def verify_filter_parent_pruning(root):
    """Reject child domains and globs already covered by a filter suffix."""
    domain_path = root / "REJECT-DOMAIN-SET.list"
    rule_path = root / "REJECT-RULE-SET.list"
    if not domain_path.is_file() or not rule_path.is_file():
        fail("filter parent-pruning check requires both reject domain and rule lists")
    domains = parse_list(domain_path)
    suffixes = domains["domain_suffix"]
    redundant = []
    for domain in sorted(suffixes):
        parent = covering_suffix(domain, suffixes, include_self=False)
        if parent:
            redundant.append(f".{domain} covered by .{parent}")
    for domain in sorted(domains["domain"]):
        parent = covering_suffix(domain, suffixes)
        if parent:
            redundant.append(f"{domain} covered by .{parent}")
    for number, raw in enumerate(rule_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        kind, value = (part.strip() for part in line.split(",", 1))
        value = value.lower()
        if kind.upper() == "DOMAIN-WILDCARD":
            parent = wildcard_covering_suffix(value, suffixes)
        elif kind.upper() in {"DOMAIN", "DOMAIN-SUFFIX"}:
            parent = covering_suffix(value, suffixes)
        else:
            continue
        if parent:
            redundant.append(f"{rule_path.name}:{number}: {line} covered by .{parent}")
    if redundant:
        fail(f"{len(redundant)} parent-covered filter rules remain: " + "; ".join(redundant[:5]))
    print("filter parent-pruning verified: no covered child domains or wildcard rules")
    return 0


def verify_supplemental_ips(root):
    """Keep supplementary address coverage in the generated IP rule set."""
    source = root / "source/reject-ip-extra.list"
    if not source.is_file():
        return 0
    expected = read_ip_rules(source)
    actual = [ipaddress.ip_network(cidr) for _, cidr in
              collapse_ip_rules(read_ip_rules(root / "REJECT-IP-SET.list"))]
    for _, cidr in sorted(expected):
        network = ipaddress.ip_network(cidr)
        if not any(network.version == covered.version and network.subnet_of(covered)
                   for covered in actual):
            fail(f"supplementary IP coverage missing: {cidr}")
    print(f"supplementary IP rules verified: {len(expected)} entries")
    return 0


def verify_canonical_ip_set(root, name):
    path = root / (name + ".list")
    if not path.is_file():
        return 0
    try:
        rules = read_ip_rules(path)
    except ValueError as error:
        fail(str(error))
    rows = [line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith(("#", "//"))]
    if len(rows) != len(rules) or rules != collapse_ip_rules(rules):
        fail(f"{path}: duplicate, overlapping or adjacent unmerged IP ranges remain")
    if {ipaddress.ip_network(cidr).version for _, cidr in rules} != {4, 6}:
        fail(f"{path}: both IPv4 and IPv6 are required")
    print(f"{path}: {len(rules)} canonical IPv4/IPv6 IP rules verified")
    return 0


def verify_direct_ip_set(root):
    return verify_canonical_ip_set(root, "DIRECT-IP-SET")


def verify_proxy_ip_set(root):
    if not (root / "PROXY-IP-SET.list").is_file():
        return 0
    verify_canonical_ip_set(root, "PROXY-IP-SET")
    try:
        actual = read_networks(root / "PROXY-IP-SET.list")
        inline = read_networks(root / "source/proxy-ip-inline.list")
        if intersection(actual, inline):
            fail("PROXY-IP-SET includes coverage already provided by client inline IP rules")
        expected = subtract(read_networks(root / "source/proxy-ip-extra.list"), inline)
        if subtract(expected, actual):
            fail("PROXY-IP-SET is missing curated proxy IP coverage")
    except ValueError as error:
        fail(str(error))
    print("proxy IP coverage verified: curated hosts retained; inline ranges excluded")
    return 0


def walk_decompiled(doc, collector):
    for rule in doc.get("rules", []):
        if rule.get("type") == "logical":
            if rule.get("mode") != "and":
                fail("only 'and' logical rules are supported")
            keys = []
            for sub in rule.get("rules", []):
                values = sub.get("domain_keyword")
                if values is None:
                    fail("only DOMAIN-KEYWORD is supported inside AND")
                if isinstance(values, str):
                    values = [values]
                keys.extend(v.lower() for v in values)
            collector["logical_and"].append(tuple(keys))
            continue
        for key, values in rule.items():
            if key not in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"):
                fail(f"unsupported field in the compiled rule set: {key}")
            if isinstance(values, str):
                values = [values]
            if key == "ip_cidr":
                collector["ip_cidr"].update(parse_cidr(v) for v in values)
            elif key == "domain_regex":
                collector[key].update(values)
            else:
                collector[key].update(v.lower() for v in values)


def verify(list_path, decompiled_path):
    listed = parse_list(list_path)
    with open(decompiled_path, encoding="utf-8") as f:
        doc = json.load(f)
    compiled = {"domain_suffix": set(), "domain": set(), "domain_keyword": set(), "domain_regex": set(),
                "ip_cidr": set(), "logical_and": []}
    walk_decompiled(doc, compiled)

    problems = []
    for kind in ("domain_suffix", "domain", "domain_keyword", "domain_regex"):
        only_list = sorted(listed[kind] - compiled[kind])
        only_srs = sorted(compiled[kind] - listed[kind])
        if only_list or only_srs:
            problems.append(f"{kind}: only in the list {only_list[:5]}, only in the .srs {only_srs[:5]}")
    # The order of the keywords inside an AND rule does not matter.
    listed_and = {tuple(sorted(keys)) for keys in listed["logical_and"]}
    compiled_and = {tuple(sorted(keys)) for keys in compiled["logical_and"]}
    if listed_and != compiled_and:
        problems.append(f"logical_and: only in the list {sorted(listed_and - compiled_and)}, "
                        f"only in the .srs {sorted(compiled_and - listed_and)}")
    if listed["ip_cidr"] or compiled["ip_cidr"]:
        if ranges(listed["ip_cidr"]) != ranges(compiled["ip_cidr"]):
            problems.append("ip_cidr: the covered address space differs")
    if problems:
        for problem in problems:
            print(f"error: {list_path}: {problem}", file=sys.stderr)
        return 1
    total = sum(len(v) for v in listed.values())
    print(f"{list_path}: {total} rules match the compiled rule set")
    return 0


def verify_manifests(root):
    manifests = sorted((root / "metadata").glob("*.json"))
    for manifest in manifests:
        document = json.loads(manifest.read_text(encoding="utf-8"))
        if document.get("schema") != 1:
            sys.exit(f"error: unsupported manifest schema in {manifest}")
        for name, expected in document.get("sources", {}).items():
            url = expected.get("url", "")
            if not url.startswith("repository:"):
                continue
            relative = url[len("repository:"):]
            path = (root / relative).resolve()
            if not path.is_relative_to(root.resolve()) or not path.is_file():
                sys.exit(f"error: invalid repository source in {manifest}: {relative}")
            data = path.read_bytes()
            if (len(data) != expected.get("bytes")
                    or hashlib.sha256(data).hexdigest() != expected.get("sha256")):
                sys.exit(f"error: repository source does not match {manifest}: {name}")
        for relative, expected in document.get("outputs", {}).items():
            path = root / relative
            if not path.is_file():
                sys.exit(f"error: manifest output does not exist: {relative}")
            data = path.read_bytes()
            actual_hash = hashlib.sha256(data).hexdigest()
            if len(data) != expected.get("bytes") or actual_hash != expected.get("sha256"):
                sys.exit(f"error: output does not match {manifest}: {relative}")
        print(f"verified output hashes in {manifest.relative_to(root)}")


def compile_tld_sets(root, output_dir, sing_box):
    """Compile and round-trip both domain lists before copying any binary output."""
    with tempfile.TemporaryDirectory(prefix="tld-build-") as temp:
        candidate = Path(temp)
        domain_entries = {}
        for name in TLD_SETS:
            list_path = root / f"{name}.list"
            entries = verify_tld_set(list_path)
            verify_domain_set_parent_pruning(list_path, entries)
            entries = sorted(entries, key=domain_sort_key)
            domain_entries[name] = entries
            source = candidate / f"{name}.json"
            rule = {}
            suffixes = [entry[1:] for entry in entries if entry.startswith(".")]
            exact = [entry for entry in entries if not entry.startswith(".")]
            if suffixes:
                rule["domain_suffix"] = suffixes
            if exact:
                rule["domain"] = exact
            source.write_text(json.dumps({"version": 2, "rules": [rule]},
                                         separators=(",", ":")) + "\n", encoding="utf-8")
            binary = candidate / f"{name}.srs"
            decompiled = candidate / f"{name}.compiled.json"
            subprocess.run([sing_box, "rule-set", "compile", "-o", str(binary), str(source)], check=True)
            subprocess.run([sing_box, "rule-set", "decompile", "-o", str(decompiled), str(binary)], check=True)
            if verify(list_path, decompiled):
                fail(f"{name}: compiled domain coverage differs from the list")
        verify_domain_set_proxy_pruning(domain_entries["PROXY_SET"], domain_entries["DIRECT_SET"])
        output_dir.mkdir(parents=True, exist_ok=True)
        for name in TLD_SETS:
            shutil.copyfile(candidate / f"{name}.srs", output_dir / f"{name}.srs")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--root", default=".")
    parser.add_argument("--compile-tld", action="store_true", help="compile PROXY_SET and DIRECT_SET from their .list files")
    parser.add_argument("--check-filter-pruning", action="store_true", help="check filter lists for parent-covered domains and wildcards without compiling")
    parser.add_argument("--output-dir", help="binary output directory for --compile-tld; defaults to --root")
    parser.add_argument("--list", help="verify one candidate .list against decompiled JSON")
    parser.add_argument("--decompiled", help="JSON for --list; skips repository-wide checks")
    args = parser.parse_args()

    if args.check_filter_pruning:
        if args.compile_tld or args.output_dir or args.list or args.decompiled:
            parser.error("--check-filter-pruning cannot be combined with other modes")
        return verify_filter_parent_pruning(Path(args.root).resolve())

    if args.compile_tld:
        if args.list or args.decompiled:
            parser.error("--compile-tld cannot be combined with candidate verification")
        return compile_tld_sets(Path(args.root).resolve(),
                                Path(args.output_dir or args.root).resolve(), args.sing_box)
    if args.output_dir:
        parser.error("--output-dir requires --compile-tld")
    if bool(args.list) != bool(args.decompiled):
        parser.error("--list and --decompiled must be supplied together")
    if args.list:
        return verify(args.list, args.decompiled)

    root = Path(args.root).resolve()
    lists = {path.stem: path for path in root.glob("*.list")}
    binaries = {path.stem: path for path in root.glob("*.srs")}
    keywords = read_inline_keywords(root) if (root / KEYWORD_SOURCE).is_file() else None
    domain_entries = {}
    for name in TLD_SETS:
        if name in lists:
            entries = verify_tld_set(lists[name])
            domain_entries[name] = entries
            verify_domain_set_parent_pruning(lists[name], entries)
            if keywords is not None:
                verify_domain_set_keyword_pruning(lists[name], entries, keywords[name.removesuffix("_SET").lower()])
    if all(name in domain_entries for name in TLD_SETS):
        verify_domain_set_proxy_pruning(domain_entries["PROXY_SET"], domain_entries["DIRECT_SET"])
    if lists.keys() != binaries.keys():
        missing_srs = sorted(lists.keys() - binaries.keys())
        missing_list = sorted(binaries.keys() - lists.keys())
        sys.exit(f"error: unpaired rule sets; missing .srs={missing_srs}, missing .list={missing_list}")
    if not lists:
        sys.exit("error: no rule-set pairs found")

    if {"REJECT-DOMAIN-SET", "REJECT-RULE-SET"} <= lists.keys():
        verify_filter_parent_pruning(root)

    with tempfile.TemporaryDirectory(prefix="ruleset-verify-") as temp:
        for name in sorted(lists):
            decompiled = Path(temp) / f"{name}.json"
            subprocess.run(
                [args.sing_box, "rule-set", "decompile", "-o", str(decompiled), str(binaries[name])],
                check=True,
            )
            if verify(lists[name], decompiled):
                return 1
    verify_supplemental_ips(root)
    verify_direct_ip_set(root)
    verify_proxy_ip_set(root)
    try:
        ordered = check_ruleset_order(root)
    except ValueError as error:
        fail(str(error))
    print(f"ascending order verified for {ordered} rule lists")
    verify_manifests(root)
    print(f"verified all {len(lists)} committed rule-set pairs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
