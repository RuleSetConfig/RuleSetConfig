#!/usr/bin/env python3
"""Build direct-ip.list (Surge) and the sing-box rule set source file.

Data sources
    --chnroute      chnroute.txt from mayaxcn/china-ip-list (IPv4)
    --chnroute-v6   chnroute_v6.txt from mayaxcn/china-ip-list (IPv6)
    --asn           also merge every announced prefix of this ASN, default
                    AS132203, fetched from RouteViews

RouteViews data is licensed CC BY 4.0 and may be redistributed, which is why it is
used here instead of RIPEstat (whose terms forbid redistributing its data).

What it does
    1. Merge the three sources and deduplicate by CIDR.
    2. Drop entries fully contained in a larger prefix (the same idea as "drop child
       rules when the parent rule exists"); the covered addresses do not change.
    3. Optional --collapse: merge adjacent ranges into the minimal CIDR set, again
       without changing the covered addresses.

Usage
    build-direct-ip.py build  --chnroute v4.txt --chnroute-v6 v6.txt \
                              --list-out direct-ip.list --json-out /tmp/direct-ip.json
    build-direct-ip.py verify --source /tmp/direct-ip.json --decompiled /tmp/compiled.json
"""

import argparse
import ipaddress
import json
import sys
import urllib.request

ROUTEVIEWS = "https://api.routeviews.org/asn/{asn}"

# Refuse to write a result that looks like a truncated download
MIN_V4 = 5000
MIN_V6 = 1000
MIN_ASN = 500


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def parse_cidrs(path, version):
    out = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                continue
            if net.version == version:
                out.add(net)
    return out


def fetch_asn(asn):
    with urllib.request.urlopen(ROUTEVIEWS.format(asn=asn), timeout=60) as response:
        items = json.load(response)
    v4, v6 = set(), set()
    for item in items:
        try:
            net = ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).add(net)
    if len(v4) + len(v6) < MIN_ASN:
        fail(f"RouteViews returned only {len(v4) + len(v6)} prefixes for AS{asn}")
    return v4, v6


def drop_contained(nets):
    """Drop entries contained in a larger prefix: a scan by start address is enough."""
    kept, max_end = [], -1
    for net in sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen)):
        end = int(net.broadcast_address)
        if end <= max_end:
            continue
        kept.append(net)
        max_end = end
    return kept


def collapse(nets):
    """Merge adjacent ranges into the minimal CIDR set (same covered addresses)."""
    intervals = sorted((int(n.network_address), int(n.broadcast_address)) for n in nets)
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    out = []
    for start, end in merged:
        out.extend(ipaddress.summarize_address_range(
            ipaddress.ip_address(start), ipaddress.ip_address(end)))
    return out


def ranges(cidrs):
    """Turn CIDRs into disjoint intervals per IP version, for equivalence checks."""
    intervals = {4: [], 6: []}
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        intervals[net.version].append((int(net.network_address), int(net.broadcast_address)))
    merged = {}
    for version, items in intervals.items():
        items.sort()
        out = []
        for start, end in items:
            if out and start <= out[-1][1] + 1:
                out[-1] = (out[-1][0], max(out[-1][1], end))
            else:
                out.append((start, end))
        merged[version] = out
    return merged


def cmd_build(args):
    src4 = parse_cidrs(args.chnroute, 4)
    src6 = parse_cidrs(args.chnroute_v6, 6)
    if len(src4) < MIN_V4:
        fail(f"chnroute has only {len(src4)} IPv4 prefixes, looks incomplete")
    if len(src6) < MIN_V6:
        fail(f"chnroute_v6 has only {len(src6)} IPv6 prefixes, looks incomplete")
    asn4, asn6 = fetch_asn(args.asn)

    raw4, raw6 = src4 | asn4, src6 | asn6
    dup = (len(src4) + len(asn4) - len(raw4)) + (len(src6) + len(asn6) - len(raw6))

    keep4, keep6 = drop_contained(raw4), drop_contained(raw6)
    contained = (len(raw4) - len(keep4)) + (len(raw6) - len(keep6))

    if args.collapse:
        keep4, keep6 = collapse(keep4), collapse(keep6)

    v4 = sorted(keep4, key=lambda n: (int(n.network_address), n.prefixlen))
    v6 = sorted(keep6, key=lambda n: (int(n.network_address), n.prefixlen))

    # Surge rule file: IP-CIDR / IP-CIDR6
    with open(args.list_out, "w", encoding="utf-8") as f:
        for net in v4:
            f.write(f"IP-CIDR,{net}\n")
        for net in v6:
            f.write(f"IP-CIDR6,{net}\n")

    # sing-box rule set source (IPv4 and IPv6 share one ip_cidr rule)
    doc = {"version": 2, "rules": [{"ip_cidr": [str(n) for n in v4 + v6]}]}
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))

    print(f"chnroute v4 {len(src4)}, chnroute v6 {len(src6)}, "
          f"AS{args.asn} v4 {len(asn4)} / v6 {len(asn6)}")
    print(f"deduplicated {dup} entries, dropped {contained} contained prefixes"
          + (", adjacent ranges merged" if args.collapse else ""))
    print(f"wrote {args.list_out}: {len(v4)} IPv4 + {len(v6)} IPv6 "
          f"({len(v4) + len(v6)} total)")
    return 0


def cmd_verify(args):
    source = json.load(open(args.source, encoding="utf-8"))
    decompiled = json.load(open(args.decompiled, encoding="utf-8"))
    src = ranges([c for rule in source["rules"] for c in rule.get("ip_cidr", [])])
    dec = ranges([c for rule in decompiled["rules"] for c in rule.get("ip_cidr", [])])
    if src != dec:
        fail("the compiled rule set does not cover the same addresses as the source")
    print(f"verified: {len(src[4])} IPv4 ranges, {len(src[6])} IPv6 ranges, "
          f"address coverage identical")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--chnroute", required=True)
    build.add_argument("--chnroute-v6", required=True)
    build.add_argument("--asn", default="132203")
    build.add_argument("--list-out", required=True)
    build.add_argument("--json-out", required=True)
    build.add_argument("--collapse", action="store_true",
                       help="also merge adjacent ranges into the minimal CIDR set")
    build.set_defaults(func=cmd_build)

    verify = sub.add_parser("verify")
    verify.add_argument("--source", required=True)
    verify.add_argument("--decompiled", required=True)
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
