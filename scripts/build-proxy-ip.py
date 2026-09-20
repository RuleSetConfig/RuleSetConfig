#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.request

ROUTEVIEWS = "https://api.routeviews.org/asn/{asn}"
CLOUDFLARE = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
TELEGRAM = "https://core.telegram.org/resources/cidr.txt"
GOOGLE = "https://www.gstatic.com/ipranges/goog.json"
GITHUB = "https://api.github.com/meta"

MIN_GOOGLE = 80
MIN_CLOUDFLARE = 20
MIN_TELEGRAM = 10
MIN_TOTAL = 50


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def fetch(url, timeout=60):
    headers = {"User-Agent": "RuleSetConfig/1.0"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "ignore")


def cidrs_from_lines(text):
    out = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.upper().startswith("IP-CIDR"):
            parts = s.split(",")
            if len(parts) >= 2:
                s = parts[1].strip()
        m = re.match(r"^([0-9a-fA-F:.]+/\d{1,3})$", s)
        if not m:
            continue
        try:
            out.add(ipaddress.ip_network(m.group(1), strict=False))
        except ValueError:
            continue
    return out


def local_rules(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        return cidrs_from_lines(f.read())


def asn_list(path):
    out = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            s = re.sub(r"^(AS|as)", "", s.split()[0])
            if s.isdigit():
                out.append(int(s))
    return out


def fetch_asn(asn):
    try:
        data = json.loads(fetch(ROUTEVIEWS.format(asn=asn)))
    except Exception as exc:
        print(f"warning: query for AS{asn} failed ({exc}), skipping", file=sys.stderr)
        return set()
    out = set()
    for item in data:
        try:
            out.add(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            continue
    return out


def cloudflare():
    return cidrs_from_lines(fetch(CLOUDFLARE[0])) | cidrs_from_lines(fetch(CLOUDFLARE[1]))


def telegram():
    return cidrs_from_lines(fetch(TELEGRAM))


def google():
    doc = json.loads(fetch(GOOGLE))
    out = set()
    for item in doc.get("prefixes", []):
        for key in ("ipv4Prefix", "ipv6Prefix"):
            if key in item:
                out.add(ipaddress.ip_network(item[key], strict=False))
    if len(out) < MIN_GOOGLE:
        fail(f"Google list has only {len(out)} entries, looks incomplete")
    return out


def github():
    doc = json.loads(fetch(GITHUB))
    out = set()
    for key in ("git", "web", "api", "hooks", "pages"):
        for item in doc.get(key, []):
            try:
                out.add(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
    if not out:
        fail("no networks parsed out of the GitHub meta response")
    return out


def drop_contained(nets):
    kept = []
    for version in (4, 6):
        max_end = -1
        for net in sorted((n for n in nets if n.version == version),
                          key=lambda n: (int(n.network_address), n.prefixlen)):
            end = int(net.broadcast_address)
            if end <= max_end:
                continue
            kept.append(net)
            max_end = end
    return kept


def covered_by(net, pool):
    return any(net.version == other.version and net.subnet_of(other) for other in pool)


def collapse(nets):
    out = []
    for version in (4, 6):
        items = sorted((int(n.network_address), int(n.broadcast_address))
                       for n in nets if n.version == version)
        merged = []
        for start, end in items:
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        for start, end in merged:
            out.extend(ipaddress.summarize_address_range(
                ipaddress.ip_address(start), ipaddress.ip_address(end)))
    return out


def ranges(cidrs):
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
    sources = {}
    sources["local"] = local_rules(args.local)
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
        fail(f"local rule file has only {len(sources['local'])} entries")
    if args.cloudflare and len(sources["cloudflare"]) < MIN_CLOUDFLARE:
        fail(f"Cloudflare list has only {len(sources['cloudflare'])} entries, looks incomplete")
    if args.telegram and len(sources["telegram"]) < MIN_TELEGRAM:
        fail(f"Telegram list has only {len(sources['telegram'])} entries, looks incomplete")
    if not asn_prefixes:
        fail("no prefixes were fetched for any ASN")

    all_nets = set()
    for nets in sources.values():
        all_nets |= nets
    merged_count = len(all_nets)
    all_nets |= asn_prefixes
    dup = merged_count + len(asn_prefixes) - len(all_nets)

    keep = drop_contained(all_nets)
    contained = len(all_nets) - len(keep)

    local_covered = 0
    if args.upstream_only:
        local_nets = sources["local"]
        before = len(keep)
        keep = [n for n in keep if not covered_by(n, local_nets)]
        local_covered = before - len(keep)

    if args.collapse:
        keep = collapse(keep)

    v4 = sorted((n for n in keep if n.version == 4),
                key=lambda n: (int(n.network_address), n.prefixlen))
    v6 = sorted((n for n in keep if n.version == 6),
                key=lambda n: (int(n.network_address), n.prefixlen))

    if len(v4) + len(v6) < MIN_TOTAL:
        fail(f"result has only {len(v4) + len(v6)} entries, looks wrong")

    with open(args.list_out, "w", encoding="utf-8") as f:
        for net in v4:
            f.write(f"IP-CIDR,{net}\n")
        for net in v6:
            f.write(f"IP-CIDR6,{net}\n")

    doc = {"version": 2, "rules": [{"ip_cidr": [str(n) for n in v4 + v6]}]}
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))

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
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
