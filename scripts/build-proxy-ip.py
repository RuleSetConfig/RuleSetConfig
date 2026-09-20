#!/usr/bin/env python3
"""生成 proxy-ip.list（Surge）与 sing-box 规则集源文件。

数据来源
    --local       本地手工维护的规则（Surge 语法 IP-CIDR / IP-CIDR6），优先级最高
    --asn-file    每行一个 ASN，用 RouteViews 展开成该 ASN 的全部宣告前缀
    --cloudflare  拉 Cloudflare 官方清单 https://www.cloudflare.com/ips-v4 / ips-v6
    --telegram    拉 Telegram 官方清单 https://core.telegram.org/resources/cidr.txt
    --google      拉 Google 官方清单 https://www.gstatic.com/ipranges/goog.json
    --github      拉 GitHub 官方清单 https://api.github.com/meta

处理内容
    1. 合并所有来源，按 CIDR 去重复。
    2. 去掉被更大前缀完全包含的条目（冗余删除，覆盖范围不变）。
    3. 可选 --collapse：把相邻区间也合并成最小 CIDR 集合，覆盖范围同样不变。

RouteViews 数据按 CC BY 4.0 授权、允许再分发（RIPEstat 的服务条款禁止再分发）。

用法
    build-proxy-ip.py build  --local source/proxy-ip.local.list --asn-file source/proxy-ip.asn \
                             --cloudflare --telegram --google --github \
                             --list-out proxy-ip.list --json-out /tmp/proxy-ip.json
    build-proxy-ip.py verify --source /tmp/proxy-ip.json --decompiled /tmp/compiled.json
"""

import argparse
import ipaddress
import json
import re
import sys
import urllib.request

ROUTEVIEWS = "https://api.routeviews.org/asn/{asn}"
CLOUDFLARE = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
TELEGRAM = "https://core.telegram.org/resources/cidr.txt"
GOOGLE = "https://www.gstatic.com/ipranges/goog.json"
GITHUB = "https://api.github.com/meta"

# 数据看起来被截断时拒绝写出结果
MIN_GOOGLE = 80
MIN_CLOUDFLARE = 20
MIN_TELEGRAM = 10
MIN_TOTAL = 50


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def fetch(url, timeout=60):
    request = urllib.request.Request(url, headers={"User-Agent": "RuleSetConfig/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "ignore")


def cidrs_from_lines(text):
    """从任意文本里挑出 CIDR（Surge 规则行、纯 CIDR 行都能处理）。"""
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
    except Exception as exc:  # 单个 ASN 失败不应该让整个任务失败
        print(f"warning: AS{asn} 查询失败（{exc}），跳过", file=sys.stderr)
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
        fail(f"Google 清单只有 {len(out)} 条，疑似下载不完整")
    return out


def github():
    doc = json.loads(fetch(GITHUB))
    out = set()
    # git / web / api / hooks 是访问 github.com 的核心段，pages 是 Pages 的独立地址
    for key in ("git", "web", "api", "hooks", "pages"):
        for item in doc.get(key, []):
            try:
                out.add(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
    if not out:
        fail("GitHub meta 里没解析到任何网段")
    return out


def drop_contained(nets):
    """去掉被更大前缀包含的条目：按起始地址排序后扫描即可。"""
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


def collapse(nets):
    """把相邻区间也合并成最小 CIDR 集合（覆盖范围不变）。"""
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
    """折算成互不相交的区间，按版本分组，用于等价性校验。"""
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
        fail(f"本地规则只有 {len(sources['local'])} 条，疑似文件有问题")
    if args.cloudflare and len(sources["cloudflare"]) < MIN_CLOUDFLARE:
        fail(f"Cloudflare 清单只有 {len(sources['cloudflare'])} 条，疑似下载不完整")
    if args.telegram and len(sources["telegram"]) < MIN_TELEGRAM:
        fail(f"Telegram 清单只有 {len(sources['telegram'])} 条，疑似下载不完整")
    if args.asn_file and not asn_prefixes:
        fail("所有 ASN 都没有取到前缀")

    all_nets = set()
    for nets in sources.values():
        all_nets |= nets
    merged_count = len(all_nets)
    all_nets |= asn_prefixes
    dup = merged_count + len(asn_prefixes) - len(all_nets)

    keep = drop_contained(all_nets)
    contained = len(all_nets) - len(keep)
    if args.collapse:
        keep = collapse(keep)

    v4 = sorted((n for n in keep if n.version == 4),
                key=lambda n: (int(n.network_address), n.prefixlen))
    v6 = sorted((n for n in keep if n.version == 6),
                key=lambda n: (int(n.network_address), n.prefixlen))

    if len(v4) + len(v6) < MIN_TOTAL:
        fail(f"结果只有 {len(v4) + len(v6)} 条，疑似异常")

    with open(args.list_out, "w", encoding="utf-8") as f:
        for net in v4:
            f.write(f"IP-CIDR,{net}\n")
        for net in v6:
            f.write(f"IP-CIDR6,{net}\n")

    doc = {"version": 2, "rules": [{"ip_cidr": [str(n) for n in v4 + v6]}]}
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))

    for name, nets in sources.items():
        print(f"来源 {name:11} {len(nets):6} 条")
    for asn, count in asn_report:
        print(f"来源 AS{asn:<8} {count:6} 条")
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
    build.add_argument("--local", required=True)
    build.add_argument("--asn-file")
    build.add_argument("--cloudflare", action="store_true")
    build.add_argument("--telegram", action="store_true")
    build.add_argument("--google", action="store_true")
    build.add_argument("--github", action="store_true")
    build.add_argument("--list-out", required=True)
    build.add_argument("--json-out", required=True)
    build.add_argument("--collapse", action="store_true")
    build.set_defaults(func=cmd_build)

    verify = sub.add_parser("verify")
    verify.add_argument("--source", required=True)
    verify.add_argument("--decompiled", required=True)
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
