#!/usr/bin/env python3
"""合并「本地规则 + 远程规则」生成 proxy.list / direct.list 以及 sing-box 源文件。

输入
    --local-proxy   本地 PROXY 规则（Surge 规则语法，一行一条，可含注释）
    --local-direct  本地 DIRECT 规则（同上）
    --remote-proxy  Loyalsoldier/surge-rules 的 proxy.txt（domain-set 风格）
    --remote-direct 同上，direct.txt

优先级（从高到低）
    本地 PROXY > 本地 DIRECT > 远程 proxy > 远程 direct

处理规则
    1. 去重复：同类型同取值的规则只保留优先级最高的一条。
    2. 含父域的去子域：父后缀规则的后代（子域后缀、子域精确项、同名精确项）全部删除。
    3. proxy 与 direct 同名：以 proxy 为准，从 direct 删除。
    4. 本地 DIRECT 覆盖的 proxy 规则删除（DOMAIN-SUFFIX,cn → .cn 一律直连）。
    5. 被保留的 proxy 规则覆盖的 direct 规则删除（proxy 优先，避免出现死规则）。
"""

import argparse
import json
import os
import sys


def parse_line(line):
    """解析一行规则 -> (kind, value)，返回 None 表示忽略该行。

    远程文件是 domain-set 风格：'.d' 后缀匹配，'d' 精确匹配。
    本地文件是 Surge 规则语法：DOMAIN-SUFFIX,d / DOMAIN,d / DOMAIN-KEYWORD,k。
    """
    s = line.strip()
    if not s or s.startswith("#") or s.startswith("//") or s.startswith(";"):
        return None
    if s.startswith("."):
        return ("DOMAIN-SUFFIX", s[1:].strip().lower())
    if "," not in s:
        return ("DOMAIN", s.lower())
    kind, value = s.split(",", 1)
    kind = kind.strip().upper()
    value = value.strip().lower()
    if kind in ("DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD"):
        return (kind, value)
    return (kind, value)


def load(path, origin):
    rules, seen = [], set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            r = parse_line(line)
            if r is None:
                continue
            if r in seen:
                continue
            seen.add(r)
            rules.append((r[0], r[1], origin))
    return rules


def merge(*rule_lists):
    """按优先级合并，同类型同取值只保留最先出现的一条。"""
    out, seen = [], set()
    for rules in rule_lists:
        for kind, value, origin in rules:
            if (kind, value) in seen:
                continue
            seen.add((kind, value))
            out.append((kind, value, origin))
    return out


def ancestors(domain):
    labels = domain.split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


def find_parent(suffixes, kind, value):
    """返回覆盖该规则的父后缀规则，没有则返回 None。"""
    if kind == "DOMAIN-SUFFIX":
        candidates = [a for a in ancestors(value) if a != value]
    elif kind == "DOMAIN":
        candidates = list(ancestors(value))
    else:
        return None
    return next((c for c in candidates if c in suffixes), None)


def prune_by_parents(rules):
    """删除被父后缀规则覆盖的子规则。"""
    suffixes = {v for k, v, _ in rules if k == "DOMAIN-SUFFIX"}
    kept, removed = [], []
    for rule in rules:
        parent = find_parent(suffixes, rule[0], rule[1])
        if parent:
            removed.append((rule, "父域 ." + parent))
        else:
            kept.append(rule)
    return kept, removed


def covered_by(rules, other):
    """找出被 other 覆盖的规则（后缀父域 / 同名精确 / 关键字）。"""
    suffixes = {v for k, v, _ in other if k == "DOMAIN-SUFFIX"}
    exacts = {v for k, v, _ in other if k == "DOMAIN"}
    keywords = sorted({v for k, v, _ in other if k == "DOMAIN-KEYWORD"},
                      key=len, reverse=True)
    hits = []
    for rule in rules:
        kind, value = rule[0], rule[1]
        if kind not in ("DOMAIN-SUFFIX", "DOMAIN"):
            continue
        parent = find_parent(suffixes, kind, value)
        if parent:
            hits.append((rule, "后缀 ." + parent))
        elif kind == "DOMAIN" and value in exacts:
            hits.append((rule, "精确 " + value))
        else:
            kw = next((k for k in keywords if k in value), None)
            if kw:
                hits.append((rule, "关键字 " + kw))
    return hits


def drop(rules, drops):
    names = {(r[0], r[1]) for r in drops}
    return [r for r in rules if (r[0], r[1]) not in names]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local-proxy", required=True)
    ap.add_argument("--local-direct", required=True)
    ap.add_argument("--remote-proxy", required=True)
    ap.add_argument("--remote-direct", required=True)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--json-dir", default="/tmp")
    args = ap.parse_args()

    lp = load(args.local_proxy, "local")
    ld = load(args.local_direct, "local")
    rp = load(args.remote_proxy, "remote")
    rd = load(args.remote_direct, "remote")

    proxy = merge(lp, rp)
    direct = merge(ld, rd)
    raw = {"proxy": len(proxy), "direct": len(direct)}

    proxy, proxy_parent = prune_by_parents(proxy)
    direct, direct_parent = prune_by_parents(direct)

    # proxy 与 direct 同名：proxy 优先
    proxy_names = {(p[0], p[1]) for p in proxy}
    direct_drop = [r for r in direct if (r[0], r[1]) in proxy_names]
    direct = drop(direct, direct_drop)

    # 本地 DIRECT 规则覆盖的 proxy 规则删除（.cn 一律直连）
    proxy_cut = [r for r, _ in covered_by(proxy, ld)]
    proxy = drop(proxy, proxy_cut)

    # 被保留的 proxy 规则覆盖的 direct 规则删除
    direct_cut = [r for r, _ in covered_by(direct, proxy)]
    direct = drop(direct, direct_cut)

    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(args.json_dir, exist_ok=True)
    for name, rules in (("proxy", proxy), ("direct", direct)):
        with open(os.path.join(args.outdir, name + ".list"), "w", encoding="utf-8") as f:
            f.write("\n".join(f"{k},{v}" for k, v, _ in rules) + "\n")

        # sing-box 规则集源文件。注意 domain_suffix 前导点语义与 Surge 相反：
        #   'd' 匹配 d 及其所有子域（等价 Surge 的 DOMAIN-SUFFIX,d），'.d' 只匹配子域。
        # 各字段写在不同的 rule 里（rule 之间是「或」的关系）。
        bundle = []
        exact = sorted(v for k, v, _ in rules if k == "DOMAIN")
        suffix = sorted(v for k, v, _ in rules if k == "DOMAIN-SUFFIX")
        keyword = sorted(v for k, v, _ in rules if k == "DOMAIN-KEYWORD")
        if exact:
            bundle.append({"domain": exact})
        if suffix:
            bundle.append({"domain_suffix": suffix})
        if keyword:
            bundle.append({"domain_keyword": keyword})
        with open(os.path.join(args.json_dir, name + ".json"), "w", encoding="utf-8") as f:
            json.dump({"version": 2, "rules": bundle}, f,
                      ensure_ascii=False, separators=(",", ":"))

        print(f"{name}: 最终 {len(rules)} 条 "
              f"(后缀 {len(suffix)} / 精确 {len(exact)} / 关键字 {len(keyword)})")

    print(f"输入：本地 PROXY {len(lp)}、本地 DIRECT {len(ld)}、"
          f"远程 proxy {len(rp)}、远程 direct {len(rd)}")
    print(f"合并去重后：proxy {raw['proxy']}、direct {raw['direct']}")
    print(f"其中：proxy 父域去子域 {len(proxy_parent)}、direct 父域去子域 {len(direct_parent)}、"
          f"直接与 proxy 同名 {len(direct_drop)}、"
          f"proxy 被本地 direct 覆盖 {len(proxy_cut)}、"
          f"direct 被 proxy 覆盖 {len(direct_cut)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
