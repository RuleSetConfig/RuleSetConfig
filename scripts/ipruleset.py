#!/usr/bin/env python3
"""Helpers shared by the IP rule set builders.

build-direct-ip.py and build-proxy-ip.py both collect CIDRs from several
sources, drop the ones already covered by a wider prefix, optionally merge
adjacent ranges, write the .list and its sing-box JSON, and then compare the
compiled .srs with the source. build-filter-rulesets.py compares address
coverage the same way. That code lives here so the three scripts cannot drift
apart.
"""

import ipaddress
import json
import os
import re
import sys
import urllib.request

ROUTEVIEWS = "https://api.routeviews.org/asn/{asn}"


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def fetch_text(url, timeout=60):
    """GET a URL as text, authenticating the api.github.com calls when possible."""
    headers = {"User-Agent": "RuleSetConfig/1.0"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "ignore")


def parse_cidr_lines(text):
    """CIDRs out of a plain one-per-line list or a Surge style .list."""
    out = set()
    for line in text.splitlines():
        current = line.strip()
        if not current or current.startswith("#"):
            continue
        if current.upper().startswith("IP-CIDR"):
            parts = current.split(",")
            if len(parts) >= 2:
                current = parts[1].strip()
        match = re.match(r"^([0-9a-fA-F:.]+/\d{1,3})$", current)
        if not match:
            continue
        try:
            out.add(ipaddress.ip_network(match.group(1), strict=False))
        except ValueError:
            continue
    return out


def read_cidrs(path):
    with open(path, encoding="utf-8", errors="ignore") as handle:
        return parse_cidr_lines(handle.read())


def routeviews_prefixes(asn, timeout=60):
    """Every prefix RouteViews reports for AS<asn>."""
    data = json.loads(fetch_text(ROUTEVIEWS.format(asn=asn), timeout=timeout))
    out = set()
    for item in data:
        try:
            out.add(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            continue
    return out


def sort_key(net):
    return (int(net.network_address), net.prefixlen)


def drop_contained(nets):
    """Drop every prefix that a wider one already covers, per address family."""
    kept = []
    for version in (4, 6):
        max_end = -1
        for net in sorted((n for n in nets if n.version == version), key=sort_key):
            end = int(net.broadcast_address)
            if end <= max_end:
                continue
            kept.append(net)
            max_end = end
    return kept


def covered_by(net, pool):
    return any(net.version == other.version and net.subnet_of(other) for other in pool)


def collapse(nets):
    """Merge adjacent ranges into the minimal set of CIDRs, per family."""
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


def finalize(nets, exclude=None, merge_adjacent=False):
    """Drop contained prefixes, prune against `exclude`, split by family.

    Returns (v4, v6, contained, covered): the two sorted lists to write, how many
    prefixes a wider one already covered, and how many were dropped because
    `exclude` holds them.
    """
    keep = drop_contained(nets)
    contained = len(nets) - len(keep)
    covered = 0
    if exclude:
        before = len(keep)
        keep = [n for n in keep if not covered_by(n, exclude)]
        covered = before - len(keep)
    if merge_adjacent:
        keep = collapse(keep)
    v4 = sorted((n for n in keep if n.version == 4), key=sort_key)
    v6 = sorted((n for n in keep if n.version == 6), key=sort_key)
    return v4, v6, contained, covered


def write_rulesets(v4, v6, list_path, json_path):
    """Write the Surge style .list and the sing-box rule set JSON."""
    with open(list_path, "w", encoding="utf-8") as handle:
        for net in v4:
            handle.write(f"IP-CIDR,{net}\n")
        for net in v6:
            handle.write(f"IP-CIDR6,{net}\n")
    doc = {"version": 2, "rules": [{"ip_cidr": [str(n) for n in v4 + v6]}]}
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, ensure_ascii=False, separators=(",", ":"))


def cmd_verify(args):
    """Shared verify body: source and compiled .srs must cover the same addresses."""
    source = json.load(open(args.source, encoding="utf-8"))
    decompiled = json.load(open(args.decompiled, encoding="utf-8"))
    src = ranges([c for rule in source["rules"] for c in rule.get("ip_cidr", [])])
    dec = ranges([c for rule in decompiled["rules"] for c in rule.get("ip_cidr", [])])
    if src != dec:
        fail("the compiled rule set does not cover the same addresses as the source")
    print(f"verified: {len(src[4])} IPv4 ranges, {len(src[6])} IPv6 ranges, "
          f"address coverage identical")
    return 0
