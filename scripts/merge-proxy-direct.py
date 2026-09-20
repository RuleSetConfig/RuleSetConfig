#!/usr/bin/env python3
"""Merge local rules with remote rules into proxy-set/direct-set lists and sing-box sources.

Inputs
    --local-proxy   local PROXY rules (Surge syntax, one per line, comments allowed)
    --local-direct  local DIRECT rules (same format)
    --remote-proxy  proxy.txt from Loyalsoldier/surge-rules (domain-set style)
    --remote-direct direct.txt from the same source

Priority (highest first)
    local PROXY > local DIRECT > remote proxy > remote direct

Steps
    1. Deduplicate: identical rules keep only the highest priority copy.
    2. Parent/child: drop every descendant of a parent suffix rule (subdomain
       suffixes, subdomain exact entries, and the same-name exact entry).
    3. Same rule in proxy and direct: proxy wins, the direct copy is removed.
    4. Drop proxy rules covered by the local DIRECT rules (DOMAIN-SUFFIX,cn keeps
       every .cn domain direct).
    5. Drop direct rules covered by the surviving proxy rules, so no dead rules remain.
"""

import argparse
import json
import os
import sys


def parse_line(line):
    """Parse one rule line into (kind, value); None means the line is skipped.

    Remote files use the domain-set style: '.d' is a suffix match, 'd' is exact.
    Local files use Surge rule syntax: DOMAIN-SUFFIX,d / DOMAIN,d / DOMAIN-KEYWORD,k.
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
    """Merge by priority, keeping the first occurrence of every kind/value pair."""
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
    """Return the parent suffix rule covering this rule, or None."""
    if kind == "DOMAIN-SUFFIX":
        candidates = [a for a in ancestors(value) if a != value]
    elif kind == "DOMAIN":
        candidates = list(ancestors(value))
    else:
        return None
    return next((c for c in candidates if c in suffixes), None)


def prune_by_parents(rules):
    """Drop child rules covered by a parent suffix rule."""
    suffixes = {v for k, v, _ in rules if k == "DOMAIN-SUFFIX"}
    kept, removed = [], []
    for rule in rules:
        parent = find_parent(suffixes, rule[0], rule[1])
        if parent:
            removed.append((rule, "parent ." + parent))
        else:
            kept.append(rule)
    return kept, removed


def covered_by(rules, other):
    """Find rules covered by other (suffix parent / same-name exact / keyword)."""
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
            hits.append((rule, "suffix ." + parent))
        elif kind == "DOMAIN" and value in exacts:
            hits.append((rule, "exact " + value))
        else:
            kw = next((k for k in keywords if k in value), None)
            if kw:
                hits.append((rule, "keyword " + kw))
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
    ap.add_argument("--name-suffix", default="",
                    help="output name suffix, e.g. -set produces proxy-set.list / proxy-set.json")
    ap.add_argument("--upstream-only", action="store_true",
                    help="generated lists contain upstream rules only; the local rules are "
                         "still used for priority, dedupe and coverage pruning")
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

    # the same rule in proxy and direct: proxy wins
    proxy_names = {(p[0], p[1]) for p in proxy}
    direct_drop = [r for r in direct if (r[0], r[1]) in proxy_names]
    direct = drop(direct, direct_drop)

    # drop proxy rules covered by the local DIRECT rules (.cn stays direct)
    proxy_cut = [r for r, _ in covered_by(proxy, ld)]
    proxy = drop(proxy, proxy_cut)

    # drop direct rules covered by the surviving proxy rules
    direct_cut = [r for r, _ in covered_by(direct, proxy)]
    direct = drop(direct, direct_cut)

    # optional: keep upstream rules only, so the generated lists hold nothing but
    # Loyalsoldier data. Local rules still shaped the result above (priority, dedupe,
    # .cn stays direct, proxy beats direct) but are not written out.
    if args.upstream_only:
        remote_names = {(k, v) for k, v, _ in rp}
        direct_remote_names = {(k, v) for k, v, _ in rd}
        proxy_local_dropped = [r for r in proxy if (r[0], r[1]) not in remote_names]
        direct_local_dropped = [r for r in direct if (r[0], r[1]) not in direct_remote_names]
        proxy = [r for r in proxy if (r[0], r[1]) in remote_names]
        direct = [r for r in direct if (r[0], r[1]) in direct_remote_names]

    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(args.json_dir, exist_ok=True)
    for name, rules in (("proxy", proxy), ("direct", direct)):
        stem = name + args.name_suffix
        with open(os.path.join(args.outdir, stem + ".list"), "w", encoding="utf-8") as f:
            f.write("\n".join(f"{k},{v}" for k, v, _ in rules) + "\n")

        # sing-box rule set source. Note that domain_suffix treats the leading dot the
        # other way round: 'd' matches d and all of its subdomains (equivalent to Surge's
        # DOMAIN-SUFFIX,d), while '.d' matches subdomains only. Each field lives in its
        # own rule object because separate rules are OR-ed together.
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
        with open(os.path.join(args.json_dir, stem + ".json"), "w", encoding="utf-8") as f:
            json.dump({"version": 2, "rules": bundle}, f,
                      ensure_ascii=False, separators=(",", ":"))

        print(f"{stem}: {len(rules)} rules "
              f"({len(suffix)} suffix / {len(exact)} exact / {len(keyword)} keyword)")

    print(f"input: local PROXY {len(lp)}, local DIRECT {len(ld)}, "
          f"remote proxy {len(rp)}, remote direct {len(rd)}")
    print(f"after merge/dedupe: proxy {raw['proxy']}, direct {raw['direct']}")
    print(f"dropped: proxy parent/child {len(proxy_parent)}, "
          f"direct parent/child {len(direct_parent)}, "
          f"direct duplicated in proxy {len(direct_drop)}, "
          f"proxy covered by local direct {len(proxy_cut)}, "
          f"direct covered by proxy {len(direct_cut)}")
    if args.upstream_only:
        print(f"local rules kept out of the generated lists: "
              f"proxy {len(proxy_local_dropped)}, direct {len(direct_local_dropped)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
