#!/usr/bin/env python3
"""Select OISD rules by Chinese-use reference coverage OR CN suffix OR brand.

This is not geolocation: popular Chinese-use lists also contain global services.
Reference lists are selection-only; their complete content is never merged.
Brand matching uses a registrable-domain approximation, not the full PSL.
Selected OISD lines are retained verbatim and an optional JSON audit records why.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
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


def selection_reasons(host, brands, reference_suffix):
    why = []
    if registrable(host).endswith(CN_SUFFIXES):
        why.append("cn-suffix")
    if brand_hit(host, brands):
        why.append("domestic-brand")
    labels = host.split(".")
    if any(".".join(labels[i:]) in reference_suffix for i in range(len(labels))):
        why.append("reference-covered")
    return why


def main(argv=None):
    parser = argparse.ArgumentParser(description="Keep the domestic entries of a blocklist")
    parser.add_argument("--in", dest="source", required=True, help="input list")
    parser.add_argument("--out", dest="target", required=True, help="output list")
    parser.add_argument("--brands", required=True, help="brand token file")
    parser.add_argument("--reference", action="append", default=[],
                        help="Chinese-use DNS reference; retain OISD domains covered by its suffix rules")
    parser.add_argument("--audit", help="write selection reasons and source counts as JSON")
    args = parser.parse_args(argv)
    reference_suffix = set()
    reference_counts = {}
    for filename in args.reference:
        lines = Path(filename).read_text(encoding="utf-8").splitlines()
        domains = set()
        disabled = {line.removesuffix("$badfilter") for line in lines if line.endswith("$badfilter")}
        for line in lines:
            if line in disabled:
                continue
            match = re.fullmatch(r"\|\|([a-zA-Z0-9_.-]+)\^", line.strip())
            if match:
                domains.add(match[1].lower())
        floor = {"antiad_reference.txt": 50000, "adrules_reference.txt": 100000,
                 "awavenue.txt": 500}.get(Path(filename).name, 500)
        if len(domains) < floor:
            sys.exit(f"error: reference {filename} has only {len(domains)} suffix rules")
        reference_counts[Path(filename).name] = len(domains)
        reference_suffix.update(domains)

    brands = load_brands(args.brands)
    if not brands:
        sys.exit(f"error: {args.brands} holds no brand tokens")

    kept, total = [], 0
    reasons = Counter()
    selections = []
    with open(args.source, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            host = extract_host(line)
            if host is None:
                continue
            total += 1
            why = selection_reasons(host, brands, reference_suffix)
            if not why:
                continue
            reasons.update(why)
            selections.append({"host": host, "reasons": why})
            kept.append(line if line.endswith("\n") else line + "\n")

    if total < 150000 or len(kept) < 500:
        sys.exit(f"error: incomplete OISD input/selection: {total}/{len(kept)}")
    with open(args.target, "w", encoding="utf-8") as handle:
        handle.write("! OISD selection: Chinese-use reference coverage OR Chinese suffix OR domestic brand.\n")
        handle.writelines(kept)

    report = {"policy": "reference-coverage-or-cn-suffix-or-domestic-brand",
              "note": "Chinese-use references also contain global services; this is not geolocation.",
              "input_rules": total, "selected_rules": len(kept),
              "reference_counts": reference_counts, "reasons": dict(reasons),
              "selections": selections}
    if args.audit:
        Path(args.audit).parent.mkdir(parents=True, exist_ok=True)
        Path(args.audit).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"OISD: kept {len(kept)} of {total}; {dict(reasons)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
