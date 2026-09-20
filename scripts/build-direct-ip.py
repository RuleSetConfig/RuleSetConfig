#!/usr/bin/env python3
"""生成 direct-ip.list（Surge）与 sing-box 规则集源文件。

数据来源
    --chnroute      mayaxcn/china-ip-list 的 chnroute.txt（IPv4）
    --chnroute-v6   mayaxcn/china-ip-list 的 chnroute_v6.txt（IPv6）
    --asn           额外并入某个 ASN 的全部宣告前缀，默认 AS132203，取自 RouteViews

RouteViews 数据按 CC BY 4.0 授权、允许再分发，因此这里用 RouteViews 而不是 RIPEstat
（RIPEstat 的服务条款禁止再分发其数据）。

处理内容
    1. 合并三个来源，按 CIDR 去重复。
    2. 去掉被更大前缀完全包含的条目（等价于「含父域的去掉子域」，覆盖范围不变）。
    3. 可选 --collapse：把相邻区间也合并成最小 CIDR 集合，覆盖范围同样不变。

用法
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

# 数据看起来被截断时拒绝写出结果
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
        fail(f"RouteViews 只返回了 {len(v4) + len(v6)} 条 AS{asn} 前缀，疑似异常")
    return v4, v6


def drop_contained(nets):
    """去掉被更大前缀包含的条目：按起始地址排序后扫描即可。"""
    kept, max_end = [], -1
    for net in sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen)):
        end = int(net.broadcast_address)
        if end <= max_end:
            continue
        kept.append(net)
        max_end = end
    return kept


def collapse(nets):
    """把相邻区间也合并成最小 CIDR 集合（覆盖范围不变）。"""
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
    """把一组 CIDR 折算成互不相交的区间，按 IP 版本分组，用于等价性校验。"""
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
        fail(f"chnroute 只有 {len(src4)} 条 IPv4 前缀，疑似下载不完整")
    if len(src6) < MIN_V6:
        fail(f"chnroute_v6 只有 {len(src6)} 条 IPv6 前缀，疑似下载不完整")
    asn4, asn6 = fetch_asn(args.asn)

    raw4, raw6 = src4 | asn4, src6 | asn6
    dup = (len(src4) + len(asn4) - len(raw4)) + (len(src6) + len(asn6) - len(raw6))

    keep4, keep6 = drop_contained(raw4), drop_contained(raw6)
    contained = (len(raw4) - len(keep4)) + (len(raw6) - len(keep6))

    if args.collapse:
        keep4, keep6 = collapse(keep4), collapse(keep6)

    v4 = sorted(keep4, key=lambda n: (int(n.network_address), n.prefixlen))
    v6 = sorted(keep6, key=lambda n: (int(n.network_address), n.prefixlen))

    # Surge 规则文件：IP-CIDR / IP-CIDR6
    with open(args.list_out, "w", encoding="utf-8") as f:
        for net in v4:
            f.write(f"IP-CIDR,{net}\n")
        for net in v6:
            f.write(f"IP-CIDR6,{net}\n")

    # sing-box 规则集源文件（v4 与 v6 放在同一个 ip_cidr 规则里）
    doc = {"version": 2, "rules": [{"ip_cidr": [str(n) for n in v4 + v6]}]}
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))

    print(f"chnroute v4 {len(src4)}、chnroute v6 {len(src6)}、"
          f"AS{args.asn} v4 {len(asn4)} / v6 {len(asn6)}")
    print(f"合并去重复 {dup} 条、去掉被包含的前缀 {contained} 条"
          + ("、相邻合并" if args.collapse else ""))
    print(f"写出 {args.list_out}: IPv4 {len(v4)} 条、IPv6 {len(v6)} 条"
          f"（合计 {len(v4) + len(v6)}）")
    return 0


def cmd_verify(args):
    source = json.load(open(args.source, encoding="utf-8"))
    decompiled = json.load(open(args.decompiled, encoding="utf-8"))
    src = ranges([c for rule in source["rules"] for c in rule.get("ip_cidr", [])])
    dec = ranges([c for rule in decompiled["rules"] for c in rule.get("ip_cidr", [])])
    if src != dec:
        fail("编译后的规则集覆盖范围与源文件不一致")
    print(f"校验通过：IPv4 {len(src[4])} 段、IPv6 {len(src[6])} 段，地址覆盖完全一致")
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
                       help="额外把相邻区间合并成最小 CIDR 集合（覆盖范围不变）")
    build.set_defaults(func=cmd_build)

    verify = sub.add_parser("verify")
    verify.add_argument("--source", required=True)
    verify.add_argument("--decompiled", required=True)
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
