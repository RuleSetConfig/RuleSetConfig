#!/usr/bin/env python3
"""Verify committed rule pairs, or compare one candidate with decompiled JSON."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import ipruleset as ip
from filter_patterns import wildcard_regex


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


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
            if not s or s.startswith("#"):
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
        if ip.ranges(listed["ip_cidr"]) != ip.ranges(compiled["ip_cidr"]):
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
        for relative, expected in document.get("outputs", {}).items():
            path = root / relative
            if not path.is_file():
                sys.exit(f"error: manifest output does not exist: {relative}")
            data = path.read_bytes()
            actual_hash = hashlib.sha256(data).hexdigest()
            if len(data) != expected.get("bytes") or actual_hash != expected.get("sha256"):
                sys.exit(f"error: output does not match {manifest}: {relative}")
        print(f"verified output hashes in {manifest.relative_to(root)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--root", default=".")
    parser.add_argument("--list", help="verify one candidate .list against decompiled JSON")
    parser.add_argument("--decompiled", help="JSON for --list; skips repository-wide checks")
    args = parser.parse_args()

    if bool(args.list) != bool(args.decompiled):
        parser.error("--list and --decompiled must be supplied together")
    if args.list:
        return verify(args.list, args.decompiled)

    root = Path(args.root).resolve()
    lists = {path.stem: path for path in root.glob("*.list")}
    binaries = {path.stem: path for path in root.glob("*.srs")}
    if lists.keys() != binaries.keys():
        missing_srs = sorted(lists.keys() - binaries.keys())
        missing_list = sorted(binaries.keys() - lists.keys())
        sys.exit(f"error: unpaired rule sets; missing .srs={missing_srs}, missing .list={missing_list}")
    if not lists:
        sys.exit("error: no rule-set pairs found")

    with tempfile.TemporaryDirectory(prefix="ruleset-verify-") as temp:
        for name in sorted(lists):
            decompiled = Path(temp) / f"{name}.json"
            subprocess.run(
                [args.sing_box, "rule-set", "decompile", "-o", str(decompiled), str(binaries[name])],
                check=True,
            )
            if verify(lists[name], decompiled):
                return 1
    verify_manifests(root)
    print(f"verified all {len(lists)} committed rule-set pairs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
