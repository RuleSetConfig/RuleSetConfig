#!/usr/bin/env python3
"""Build the geoip-cn rule set used by this repository.

The rule set has two rules (rules are OR-ed), so the origin of every entry
stays visible:

  rules[0]  upstream SagerNet/sing-geoip geoip-cn, untouched
  rules[1]  announced prefixes of an ASN (default AS132203), from RIPE Stat

sing-box has no ASN matching, so Surge's `IP-ASN,132203` can only be
reproduced by expanding the ASN into its prefixes.

Usage:
  build-geoip-cn.py build  --upstream upstream.json --output geoip-cn.json [--asn 132203]
  build-geoip-cn.py verify --source geoip-cn.json --decompiled compiled.json
"""

import argparse
import bisect
import ipaddress
import json
import sys
import urllib.request

RIPE_STAT = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

# Refuse to write a result that looks like a truncated upstream response.
MIN_UPSTREAM = 5000
MIN_ASN = 500


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def fetch_asn(asn):
    url = RIPE_STAT.format(asn=asn)
    with urllib.request.urlopen(url, timeout=60) as response:
        payload = json.load(response)
    prefixes = payload.get("data", {}).get("prefixes")
    if not prefixes:
        fail(f"RIPE Stat returned no prefixes for AS{asn}")
    out = set()
    for item in prefixes:
        prefix = item["prefix"].strip()
        try:
            ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        out.add(prefix)
    if len(out) < MIN_ASN:
        fail(f"only {len(out)} prefixes for AS{asn}, expected at least {MIN_ASN}")
    return sorted(out)


def upstream_cidrs(path):
    doc = json.load(open(path, encoding="utf-8"))
    cidrs = [c for rule in doc["rules"] for c in rule.get("ip_cidr", [])]
    if len(cidrs) < MIN_UPSTREAM:
        fail(f"upstream has only {len(cidrs)} CIDRs, expected at least {MIN_UPSTREAM}")
    return cidrs


def ranges(doc):
    """Collapse a rule set into disjoint address ranges, per IP version."""
    intervals = {4: [], 6: []}
    for rule in doc["rules"]:
        for cidr in rule.get("ip_cidr", []):
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
    cidrs = upstream_cidrs(args.upstream)
    asn = fetch_asn(args.asn)

    doc = {"version": 1, "rules": [{"ip_cidr": cidrs}, {"ip_cidr": asn}]}
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")

    print(f"upstream geoip-cn: {len(cidrs)} CIDRs")
    print(f"AS{args.asn}: {len(asn)} prefixes")
    print(f"wrote {args.output} ({len(cidrs) + len(asn)} entries in 2 rules)")


def cmd_verify(args):
    source = json.load(open(args.source, encoding="utf-8"))
    decompiled = json.load(open(args.decompiled, encoding="utf-8"))

    src, dec = ranges(source), ranges(decompiled)
    if src != dec:
        fail("compiled rule set does not cover the same addresses as the source")
    print(f"verified: v4 {len(src[4])} ranges, v6 {len(src[6])} ranges, "
          f"address sets identical")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="merge RIPE Stat ASN prefixes into upstream geoip-cn")
    build.add_argument("--upstream", required=True, help="decompiled upstream geoip-cn.json")
    build.add_argument("--output", required=True, help="rule set source to write")
    build.add_argument("--asn", default="132203")
    build.set_defaults(func=cmd_build)

    verify = sub.add_parser("verify", help="check compiled output against the source")
    verify.add_argument("--source", required=True)
    verify.add_argument("--decompiled", required=True)
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
