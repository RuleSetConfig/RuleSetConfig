#!/usr/bin/env python3
"""Verify the committed rule sets.

Every committed .list has a .srs next to it and the two have to agree. The
workflows decompile the .srs and run:

  sing-box rule-set decompile -o /tmp/filter.compiled.json filter.srs
  build-filter-rulesets.py verify --list filter.list --decompiled /tmp/filter.compiled.json

`verify` compares the decompiled .srs against the .list it was generated from
and fails when either side carries an entry the other one does not.
"""

import argparse
import ipaddress
import json
import sys

import ipruleset as ip


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
    out = {"domain_suffix": set(), "domain": set(), "domain_keyword": set(),
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
            if key not in ("domain", "domain_suffix", "domain_keyword", "ip_cidr"):
                fail(f"unsupported field in the compiled rule set: {key}")
            if isinstance(values, str):
                values = [values]
            if key == "ip_cidr":
                collector["ip_cidr"].update(parse_cidr(v) for v in values)
            else:
                collector[key].update(v.lower() for v in values)


def verify(list_path, decompiled_path):
    listed = parse_list(list_path)
    with open(decompiled_path, encoding="utf-8") as f:
        doc = json.load(f)
    compiled = {"domain_suffix": set(), "domain": set(), "domain_keyword": set(),
                "ip_cidr": set(), "logical_and": []}
    walk_decompiled(doc, compiled)

    problems = []
    for kind in ("domain_suffix", "domain", "domain_keyword"):
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


def main():
    parser = argparse.ArgumentParser(description="Verify the committed rule sets")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("verify", help="compare a decompiled .srs against its .list")
    check.add_argument("--list", required=True, help="path of the Surge style .list")
    check.add_argument("--decompiled", required=True, help="path of the decompiled .srs JSON")

    args = parser.parse_args()
    return verify(args.list, args.decompiled)


if __name__ == "__main__":
    sys.exit(main())
