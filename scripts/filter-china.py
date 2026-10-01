#!/usr/bin/env python3
"""Keep only the domestic entries of a blocklist.

A host counts as domestic when either of these holds:

  1. its registrable domain sits under a Chinese country code top level
     domain (`.cn`, `.com.cn`, `.net.cn`, `.org.cn`, `.gov.cn`, `.edu.cn`,
     `.ac.cn`, or the punycode forms of `.中国`), or
  2. one of the labels of its registrable domain carries a token listed in
     `source/china-brands.txt`.

The brand match deliberately looks at the registrable domain only. Subdomains
are ignored, because a host like `163.red-88-22-98.staticip.rima-tde.net` is a
Spanish address that merely happens to have `163` as a subdomain label; the
NetEase domain we want to keep is `163.com`, whose registrable domain matches.

The kept lines are written back verbatim, so `||host^` stays a suffix rule and
a hosts style `0.0.0.0 host` stays an exact one.

Usage:
    filter-china.py --in /tmp/oisd_big.txt --out /tmp/oisd_big_cn.txt \
        --brands source/china-brands.txt
"""

import argparse
import re
import sys

MULTI_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "xn--fiqs8s", "xn--fiqz9s",
}

CN_SUFFIXES = tuple("." + suffix for suffix in MULTI_SUFFIXES) + (".cn",)


def registrable(host):
    labels = host.strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def load_brands(path):
    brands = set()
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip().lower()
            if line:
                brands.add(line)
    return brands


def brand_hit(host, brands):
    """Brand tokens carried by the registrable domain, if any."""
    hits = set()
    for label in registrable(host).split("."):
        for token in re.split(r"[-_]", label):
            if not token:
                continue
            if token in brands:
                hits.add(token)
                continue
            stripped = re.sub(r"\d+$", "", token)
            if stripped and stripped in brands:
                hits.add(stripped)
    return hits


def is_domestic(host, brands):
    return registrable(host).endswith(CN_SUFFIXES) or bool(brand_hit(host, brands))

# `||host^`, `||host`, `0.0.0.0 host`, `host`, `#`/`!` comments.
RULE_RE = re.compile(r"^(?P<prefix>\|\|)(?P<host>[^/^$*|]+)(?P<suffix>\^?)$")
HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(?P<host>\S+)\s*$")


def extract_host(line):
    """Return the host a rule line refers to, or None when it is not a rule."""
    stripped = line.strip()
    if not stripped or stripped.startswith(("!", "#", "[")):
        return None
    match = RULE_RE.match(stripped)
    if match:
        return match.group("host").lower()
    match = HOSTS_RE.match(stripped)
    if match:
        return match.group("host").lower()
    if re.fullmatch(r"[A-Za-z0-9._\-\u0080-\uffff]+", stripped):
        return stripped.lower()
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Keep the domestic entries of a blocklist")
    parser.add_argument("--in", dest="source", required=True, help="input list")
    parser.add_argument("--out", dest="target", required=True, help="output list")
    parser.add_argument("--brands", required=True, help="brand token file")
    args = parser.parse_args(argv)

    brands = load_brands(args.brands)
    if not brands:
        sys.exit(f"error: {args.brands} holds no brand tokens")

    kept, total, by_brand = [], 0, 0
    with open(args.source, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            host = extract_host(line)
            if host is None:
                continue
            total += 1
            if not is_domestic(host, brands):
                continue
            if brand_hit(host, brands):
                by_brand += 1
            kept.append(line if line.endswith("\n") else line + "\n")

    with open(args.target, "w", encoding="utf-8") as handle:
        handle.write(f"! Domestic entries of {args.source}\n")
        handle.writelines(kept)

    print(f"{args.source}: kept {len(kept)} of {total} rules "
          f"({by_brand} by brand token, {len(kept) - by_brand} by country code)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
