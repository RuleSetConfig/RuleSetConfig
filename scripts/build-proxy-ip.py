#!/usr/bin/env python3
"""Build proxy-ip.list from the official service lists, ASN prefixes and local rules."""

import argparse
import ipaddress
import json
import sys

import ipruleset as ip

CLOUDFLARE = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
TELEGRAM = "https://core.telegram.org/resources/cidr.txt"
GOOGLE = "https://www.gstatic.com/ipranges/goog.json"
GITHUB = "https://api.github.com/meta"

MIN_GOOGLE = 80
MIN_CLOUDFLARE = 20
MIN_TELEGRAM = 10
MIN_TOTAL = 50


def asn_list(path):
    out = []
    with open(path, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            s = s.split()[0]
            if s[:2].upper() == "AS":
                s = s[2:]
            if s.isdigit():
                out.append(int(s))
    return out


def fetch_asn(asn):
    """Prefixes for one ASN; a failing lookup is reported and skipped."""
    try:
        return ip.routeviews_prefixes(asn)
    except Exception as exc:
        print(f"warning: query for AS{asn} failed ({exc}), skipping", file=sys.stderr)
        return set()


def cloudflare():
    return ip.parse_cidr_lines(ip.fetch_text(CLOUDFLARE[0])) | \
        ip.parse_cidr_lines(ip.fetch_text(CLOUDFLARE[1]))


def telegram():
    return ip.parse_cidr_lines(ip.fetch_text(TELEGRAM))


def google():
    doc = json.loads(ip.fetch_text(GOOGLE))
    out = set()
    for item in doc.get("prefixes", []):
        for key in ("ipv4Prefix", "ipv6Prefix"):
            if key in item:
                out.add(ipaddress.ip_network(item[key], strict=False))
    if len(out) < MIN_GOOGLE:
        ip.fail(f"Google list has only {len(out)} entries, looks incomplete")
    return out


def github():
    doc = json.loads(ip.fetch_text(GITHUB))
    out = set()
    for key in ("git", "web", "api", "hooks", "pages"):
        for item in doc.get(key, []):
            try:
                out.add(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
    if not out:
        ip.fail("no networks parsed out of the GitHub meta response")
    return out


def cmd_build(args):
    sources = {"local": ip.read_cidrs(args.local)}
    if args.cloudflare:
        sources["cloudflare"] = cloudflare()
    if args.telegram:
        sources["telegram"] = telegram()
    if args.google:
        sources["google"] = google()
    if args.github:
        sources["github"] = github()

    asn_prefixes, asn_report = set(), []
    for asn in asn_list(args.asn_file):
        nets = fetch_asn(asn)
        asn_report.append((asn, len(nets)))
        asn_prefixes |= nets

    if len(sources["local"]) < 5:
        ip.fail(f"local rule file has only {len(sources['local'])} entries")
    if args.cloudflare and len(sources["cloudflare"]) < MIN_CLOUDFLARE:
        ip.fail(f"Cloudflare list has only {len(sources['cloudflare'])} entries, looks incomplete")
    if args.telegram and len(sources["telegram"]) < MIN_TELEGRAM:
        ip.fail(f"Telegram list has only {len(sources['telegram'])} entries, looks incomplete")
    if not asn_prefixes:
        ip.fail("no prefixes were fetched for any ASN")

    all_nets = set()
    for nets in sources.values():
        all_nets |= nets
    merged_count = len(all_nets)
    all_nets |= asn_prefixes
    dup = merged_count + len(asn_prefixes) - len(all_nets)

    v4, v6, contained, local_covered = ip.finalize(
        all_nets,
        exclude=sources["local"] if args.upstream_only else None,
        merge_adjacent=args.collapse,
    )

    if len(v4) + len(v6) < MIN_TOTAL:
        ip.fail(f"result has only {len(v4) + len(v6)} entries, looks wrong")

    ip.write_rulesets(v4, v6, args.list_out, args.json_out)

    for name, nets in sources.items():
        print(f"source {name:11} {len(nets):6} entries")
    for asn, count in asn_report:
        print(f"source AS{asn:<8} {count:6} entries")
    print(f"deduplicated {dup} entries, dropped {contained} contained prefixes"
          + (", adjacent ranges merged" if args.collapse else ""))
    if args.upstream_only:
        print(f"upstream-only: dropped {local_covered} entries covered by the local rules")
    print(f"wrote {args.list_out}: {len(v4)} IPv4 + {len(v6)} IPv6 "
          f"({len(v4) + len(v6)} total)")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--local", required=True)
    build.add_argument("--asn-file", required=True,
                       help="one ASN per line, expanded via RouteViews")
    build.add_argument("--cloudflare", action="store_true")
    build.add_argument("--telegram", action="store_true")
    build.add_argument("--google", action="store_true")
    build.add_argument("--github", action="store_true")
    build.add_argument("--list-out", required=True)
    build.add_argument("--json-out", required=True)
    build.add_argument("--collapse", action="store_true",
                       help="also merge adjacent ranges into the minimal CIDR set")
    build.add_argument("--upstream-only", action="store_true",
                       help="write upstream entries only; the local rules still steer the "
                            "priority and the pruning")
    build.set_defaults(func=cmd_build)

    verify = sub.add_parser("verify")
    verify.add_argument("--source", required=True)
    verify.add_argument("--decompiled", required=True)
    verify.set_defaults(func=ip.cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
