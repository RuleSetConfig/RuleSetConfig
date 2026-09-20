#!/usr/bin/env python3
"""Build and verify the hand-maintained rule sets.

`filter-set` and `filter-ip` are edited by hand, so the .srs next to each .list
has to be regenerated and checked whenever the .list changes:

  build-filter-rulesets.py build  --list filter-set.list --json-out /tmp/filter-set.json
  sing-box rule-set compile --output filter-set.srs /tmp/filter-set.json
  sing-box rule-set decompile -o /tmp/filter-set.compiled.json filter-set.srs
  build-filter-rulesets.py verify --list filter-set.list --decompiled /tmp/filter-set.compiled.json

`build` turns the Surge style .list into the sing-box rule set JSON, `verify`
compares a decompiled .srs back against the .list it came from.
"""

import argparse
import ipaddress
import json
import sys


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


def build_rules(parsed):
    """Parsed list -> rule set rules, in the order sing-box expects them."""
    rules = []
    for kind, key in (("domain_suffix", "domain_suffix"), ("domain", "domain"),
                      ("domain_keyword", "domain_keyword"), ("ip_cidr", "ip_cidr")):
        if parsed[kind]:
            rules.append({key: sorted(parsed[kind])})
    for keys in sorted(parsed["logical_and"]):
        rules.append({"type": "logical", "mode": "and",
                      "rules": [{"domain_keyword": key} for key in keys]})
    return rules


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


def coverage(entries):
    """Merge ip_cidr entries into disjoint intervals, per address family."""
    merged = {4: [], 6: []}
    for value in entries:
        net = ipaddress.ip_network(value, strict=False)
        merged[net.version].append((int(net.network_address), int(net.broadcast_address)))
    out = {}
    for version, items in merged.items():
        items.sort()
        acc = []
        for start, end in items:
            if acc and start <= acc[-1][1] + 1:
                acc[-1] = (acc[-1][0], max(acc[-1][1], end))
            else:
                acc.append((start, end))
        out[version] = acc
    return out


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
        if coverage(listed["ip_cidr"]) != coverage(compiled["ip_cidr"]):
            problems.append("ip_cidr: the covered address space differs")
    if problems:
        for problem in problems:
            print(f"error: {list_path}: {problem}", file=sys.stderr)
        return 1
    total = sum(len(v) for v in listed.values())
    print(f"{list_path}: {total} rules match the compiled rule set")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Build and verify the hand-maintained rule sets")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="convert a .list into sing-box rule set JSON")
    build.add_argument("--list", required=True, help="path of the Surge style .list")
    build.add_argument("--json-out", required=True, help="path of the JSON to write")

    check = sub.add_parser("verify", help="compare a decompiled .srs against its .list")
    check.add_argument("--list", required=True, help="path of the Surge style .list")
    check.add_argument("--decompiled", required=True, help="path of the decompiled .srs JSON")

    args = parser.parse_args()
    if args.command == "build":
        rules = build_rules(parse_list(args.list))
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"version": 2, "rules": rules}, f, indent=2, ensure_ascii=False)
            f.write("\n")
        total = sum(len(rule[next(iter(rule))]) for rule in rules if rule.get("type") != "logical")
        print(f"{args.list}: wrote {total} rules to {args.json_out}")
        return 0
    return verify(args.list, args.decompiled)


if __name__ == "__main__":
    sys.exit(main())
