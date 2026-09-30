#!/usr/bin/env python3
"""Build direct-ip.list from chnroute plus the prefixes of one ASN."""

import argparse
import sys

import ipruleset as ip

MIN_V4 = 5000
MIN_V6 = 1000
MIN_ASN = 500


def fetch_asn(asn):
    """The prefixes RouteViews reports for AS<asn>, split per address family."""
    nets = ip.routeviews_prefixes(asn)
    v4 = {n for n in nets if n.version == 4}
    v6 = {n for n in nets if n.version == 6}
    if len(v4) + len(v6) < MIN_ASN:
        ip.fail(f"RouteViews returned only {len(v4) + len(v6)} prefixes for AS{asn}")
    return v4, v6


def cmd_build(args):
    src4 = {n for n in ip.read_cidrs(args.chnroute) if n.version == 4}
    src6 = {n for n in ip.read_cidrs(args.chnroute_v6) if n.version == 6}
    if len(src4) < MIN_V4:
        ip.fail(f"chnroute has only {len(src4)} IPv4 prefixes, looks incomplete")
    if len(src6) < MIN_V6:
        ip.fail(f"chnroute_v6 has only {len(src6)} IPv6 prefixes, looks incomplete")
    asn4, asn6 = fetch_asn(args.asn)

    raw4, raw6 = src4 | asn4, src6 | asn6
    dup = (len(src4) + len(asn4) - len(raw4)) + (len(src6) + len(asn6) - len(raw6))

    v4, v6, contained, _ = ip.finalize(raw4 | raw6, merge_adjacent=args.collapse)
    ip.write_rulesets(v4, v6, args.list_out, args.json_out)

    print(f"chnroute v4 {len(src4)}, chnroute v6 {len(src6)}, "
          f"AS{args.asn} v4 {len(asn4)} / v6 {len(asn6)}")
    print(f"deduplicated {dup} entries, dropped {contained} contained prefixes"
          + (", adjacent ranges merged" if args.collapse else ""))
    print(f"wrote {args.list_out}: {len(v4)} IPv4 + {len(v6)} IPv6 "
          f"({len(v4) + len(v6)} total)")
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
    verify.set_defaults(func=ip.cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
