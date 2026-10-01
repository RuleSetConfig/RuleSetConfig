#!/usr/bin/env python3
"""Build the block set and routed direct/proxy exception sets.

Usage:
  merge-filter.py build \
    --adblock /tmp/adguard_dns.txt --adblock /tmp/awavenue.txt \
    --domain-list /tmp/antiad_anv.txt \
    --brands source/china-brands.txt \
    --list-out filter.list --json-out /tmp/filter.json \
    --allow-direct-list-out filter-allow-direct.list \
    --allow-direct-json-out /tmp/filter-allow-direct.json \
    --allow-proxy-list-out filter-allow-proxy.list \
    --allow-proxy-json-out /tmp/filter-allow-proxy.json

The Adblock style files are merged as domain rules plus the small number of
hosts style entries they carry, and the plain domain lists are merged as suffix
rules. Every 'what to keep' exception (@@) is removed from the block set and
published in exactly one routed allow set: domestic entries go direct and all
others go through the proxy. Child rules are dropped when a parent covers them.
"""

import argparse
import json
from pathlib import Path
import re
import sys

from domainclass import is_domestic, load_brands

# Refuse to publish a list that shrank past these floors: an upstream that
# changes format, serves an error page or returns a truncated file would
# otherwise be committed silently.
#
# MIN_SUFFIX is tied to the sources listed in sync-filter.yml: that set lands
# around 185k suffix rules, so the floor sits below it with roughly 20% of
# headroom while still catching the order-of-magnitude drop that a broken
# upstream produces. MIN_ADBLOCK and MIN_DOMAIN_LIST guard each individual
# source, so a single upstream going empty is caught before the merge.
MIN_ADBLOCK = 500
MIN_DOMAIN_LIST = 10
MIN_SUFFIX = 150000
MIN_EXACT = 20

# Floors for the named inputs used by sync-filter.yml. The generic floors above
# still apply to ad-hoc inputs. These tighter limits stop one large healthy list
# from hiding a badly truncated peer.
SOURCE_FLOORS = {
    "adguard_dns.txt": 150000,
    "adaway.txt": 5000,
    "peter_lowe.txt": 2500,
    "oisd_big_cn.txt": 500,
    "awavenue.txt": 700,
    "adguard_popup.txt": 700,
    "antiad_anv.txt": 10,
}


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def valid_domain(d):
    if not d or len(d) > 253 or d.startswith(".") or d.endswith("."):
        return False
    if "*" in d or " " in d or "/" in d or "#" in d:
        return False
    labels = d.split(".")
    if len(labels) < 2:
        return False
    return all(lab and len(lab) <= 63 and re.fullmatch(r"[a-z0-9_\-]+", lab) for lab in labels)


def clean(d):
    d = d.strip().lower()
    d = d.split("^", 1)[0].split("/", 1)[0].split("#", 1)[0]
    return d.strip(".")


def parse_domain_suffix_list(path):
    """Plain domain lists (anti-AD anv.txt and friends): the whole line is a
    domain and is treated as a suffix match."""
    out = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for raw in f:
            s = raw.strip()
            if not s or s.startswith("#") or s.startswith("!"):
                continue
            d = clean(s)
            if valid_domain(d):
                out.add(d)
    minimum = SOURCE_FLOORS.get(Path(path).name, MIN_DOMAIN_LIST)
    if len(out) < minimum:
        fail(f"{path} holds only {len(out)} rules, below its floor of {minimum}")
    return out


def parse_adblock(path):
    suffix, exact = set(), set()
    exc_suffix, exc_exact = set(), set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for raw in f:
            s = raw.strip()
            if not s or s.startswith("!") or s.startswith("["):
                continue
            if s.startswith("/") and s.endswith("/"):
                continue
            is_exc = s.startswith("@@")
            if is_exc:
                s = s[2:]
            if "$" in s:
                s = s.split("$", 1)[0].strip()
            # hosts style: 0.0.0.0 domain / 127.0.0.1 domain / ::1 domain
            m = re.match(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+(\S+)", s)
            if m:
                d = clean(m.group(1))
                suffix_match = False
            elif s.startswith("||"):
                d = clean(s[2:])
                suffix_match = True
            elif s.startswith("|"):
                d = clean(s[1:])
                suffix_match = False
            else:
                d = clean(s)
                suffix_match = False
            if not valid_domain(d):
                continue
            if is_exc:
                (exc_suffix if suffix_match else exc_exact).add(d)
            else:
                (suffix if suffix_match else exact).add(d)
    minimum = SOURCE_FLOORS.get(Path(path).name, MIN_ADBLOCK)
    if len(suffix) + len(exact) < minimum:
        fail(f"{path} holds only {len(suffix) + len(exact)} rules, below its floor of {minimum}")
    return suffix, exact, exc_suffix, exc_exact


def parent_of(d, pool):
    """Return the parent suffix rule covering d, or None."""
    labels = d.split(".")
    for i in range(1, len(labels)):
        p = ".".join(labels[i:])
        if p in pool:
            return p
    return None


def prune_domains(suffix, exact):
    """Remove suffix children and exact domains already covered by a suffix."""
    suffix = {d for d in suffix if parent_of(d, suffix) is None}
    exact = {d for d in exact if d not in suffix and parent_of(d, suffix) is None}
    return suffix, exact


def write_domain_rulesets(suffix, exact, list_path, json_path):
    """Write equivalent Surge DOMAIN-SET and sing-box source JSON files."""
    lines = ["." + d for d in sorted(suffix)] + sorted(exact)
    with open(list_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    rules = []
    if exact:
        rules.append({"domain": sorted(exact)})
    if suffix:
        rules.append({"domain_suffix": sorted(suffix)})
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump({"version": 2, "rules": rules}, handle, ensure_ascii=False, separators=(",", ":"))
    return len(lines)


def build(args):
    suffix, exact = set(), set()
    exc_suffix, exc_exact = set(), set()

    for path in args.adblock:
        s, e, es, ee = parse_adblock(path)
        suffix |= s
        exact |= e
        exc_suffix |= es
        exc_exact |= ee

    for path in args.domain_list:
        suffix |= parse_domain_suffix_list(path)

    # Preserve every exception in one of two routed allow rule sets. A positive-only
    # block list cannot express "block example.com except safe.example.com",
    # so consumers must match both allow sets before the block set.
    brands = load_brands(args.brands)
    if not brands:
        fail(f"{args.brands} holds no brand tokens")
    direct_suffix_raw = {domain for domain in exc_suffix if is_domestic(domain, brands)}
    direct_exact_raw = {domain for domain in exc_exact if is_domestic(domain, brands)}
    direct_suffix, direct_exact = prune_domains(direct_suffix_raw, direct_exact_raw)
    proxy_suffix, proxy_exact = prune_domains(
        exc_suffix - direct_suffix_raw,
        exc_exact - direct_exact_raw,
    )

    # Also remove directly matching entries from the legacy block-only output.
    # This keeps filter.list backwards compatible, while the two routed allow
    # sets handle exceptions that remain underneath a wider blocked parent.
    suffix -= exc_suffix
    exact -= exc_exact
    # Drop exact entries that are covered by an exception suffix
    exact = {d for d in exact if not any(d == es or d.endswith("." + es) for es in exc_suffix)}

    # Deduplicate ad rules: drop child rules when their parent rule exists.
    # '.a.b.c' is fully covered by '.b.c'; the exact rule 'x.b.c' as well.
    suffix_before, exact_before = len(suffix), len(exact)
    suffix, exact = prune_domains(suffix, exact)
    print(f"parent-prune: suffix {suffix_before} -> {len(suffix)}, "
          f"exact {exact_before} -> {len(exact)}")

    if len(suffix) < MIN_SUFFIX:
        fail(f"the merged list holds only {len(suffix)} suffix rules, looks incomplete")
    if len(exact) < MIN_EXACT:
        fail(f"the merged list holds only {len(exact)} exact rules, looks incomplete")

    # Surge DOMAIN-SET: a leading '.' means suffix match, no prefix means exact.
    # sing-box domain_suffix uses the dotless form for the same semantics.
    # Note that domain_suffix treats the leading dot the other way round:
    #   domain_suffix: 'd'  matches d itself and all of its subdomains
    #                       (equivalent to Surge's '.d')
    #   domain_suffix: '.d' matches only subdomains, not d itself
    # So the dotless form is written here to match filter.list's '.d'.
    # (sing-box matches on label boundaries, 'oo.com' does not hit 'notoo.com'.)
    count = write_domain_rulesets(suffix, exact, args.list_out, args.json_out)

    direct_count = write_domain_rulesets(
        direct_suffix, direct_exact, args.allow_direct_list_out, args.allow_direct_json_out)
    proxy_count = write_domain_rulesets(
        proxy_suffix, proxy_exact, args.allow_proxy_list_out, args.allow_proxy_json_out)
    print(f"{args.allow_direct_list_out}: {direct_count} rules "
          f"(suffix {len(direct_suffix)} / exact {len(direct_exact)})")
    print(f"{args.allow_proxy_list_out}: {proxy_count} rules "
          f"(suffix {len(proxy_suffix)} / exact {len(proxy_exact)})")

    print(f"{args.list_out}: {count} rules (suffix {len(suffix)} / exact {len(exact)})")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Merge the upstream DNS blocklists")
    sub = ap.add_subparsers(dest="command", required=True)

    build_cmd = sub.add_parser("build", help="merge the sources into filter.list and its JSON")
    build_cmd.add_argument("--adblock", action="append", default=[], required=True,
                           help="Adblock style source, may be repeated")
    build_cmd.add_argument("--domain-list", action="append", default=[],
                           help="plain domain list merged as suffix rules, may be repeated")
    build_cmd.add_argument("--list-out", required=True, help="path of the Surge style .list to write")
    build_cmd.add_argument("--json-out", required=True, help="path of the rule set JSON to write")
    build_cmd.add_argument("--brands", required=True, help="brand tokens used to select direct exceptions")
    build_cmd.add_argument("--allow-direct-list-out", required=True)
    build_cmd.add_argument("--allow-direct-json-out", required=True)
    build_cmd.add_argument("--allow-proxy-list-out", required=True)
    build_cmd.add_argument("--allow-proxy-json-out", required=True)

    args = ap.parse_args()
    if args.command == "build":
        return build(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
