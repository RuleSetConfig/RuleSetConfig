#!/usr/bin/env python3
"""Build the filter block set and its routed upstream exceptions.

Usage:
  merge-filter.py build \
    --adblock /tmp/adguard_dns.txt --adblock /tmp/awavenue.txt \
    --domain-list /tmp/antiad_anv.txt \
    --brands source/china-brands.txt \
    --output-dir /tmp/filter-build

The Adblock style files are merged as domain rules plus the small number of
hosts style entries they carry, and the plain domain lists are merged as suffix
rules. Every 'what to keep' exception (@@) is removed from the block set and
published in exactly one companion set. Domestic exceptions route directly;
all remaining exceptions route through the proxy. Consumers must evaluate the
two allow sets before the block set. Child rules are dropped when covered by a
parent in the same set.
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


def remove_exception_matches(suffix, exact, exc_suffix, exc_exact):
    """Remove direct exception matches while retaining wider blocked parents.

    A wider parent remains useful because consumers evaluate the routed allow
    sets first. That preserves both the upstream exception and the rest of the
    parent's blocking coverage.
    """
    suffix = suffix - exc_suffix
    exact = exact - exc_exact
    exact = {
        domain for domain in exact
        if not any(domain == allowed or domain.endswith("." + allowed)
                   for allowed in exc_suffix)
    }
    return suffix, exact


def split_exceptions(exc_suffix, exc_exact, brands):
    """Partition exceptions into disjoint domestic and non-domestic sets."""
    direct_suffix_raw = {domain for domain in exc_suffix if is_domestic(domain, brands)}
    direct_exact_raw = {domain for domain in exc_exact if is_domestic(domain, brands)}
    proxy_suffix_raw = exc_suffix - direct_suffix_raw
    proxy_exact_raw = exc_exact - direct_exact_raw

    direct = prune_domains(direct_suffix_raw, direct_exact_raw)
    proxy = prune_domains(proxy_suffix_raw, proxy_exact_raw)
    return direct, proxy


def route_overlap(left_suffix, left_exact, right_suffix, right_exact):
    """Return domains whose matching scope overlaps the opposite route."""
    overlaps = (left_suffix | left_exact) & (right_suffix | right_exact)
    for domain in left_suffix | left_exact:
        if parent_of(domain, right_suffix):
            overlaps.add(domain)
    for domain in right_suffix | right_exact:
        if parent_of(domain, left_suffix):
            overlaps.add(domain)
    return overlaps


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

    brands = load_brands(args.brands)
    if not brands:
        fail(f"{args.brands} holds no brand tokens")

    direct, proxy = split_exceptions(exc_suffix, exc_exact, brands)
    direct_suffix, direct_exact = direct
    proxy_suffix, proxy_exact = proxy
    overlaps = route_overlap(direct_suffix, direct_exact, proxy_suffix, proxy_exact)
    if overlaps:
        sample = ", ".join(sorted(overlaps)[:5])
        fail(f"direct/proxy exception routes overlap: {sample}")
    if not direct_suffix and not direct_exact:
        fail("the direct exception set is empty")
    if not proxy_suffix and not proxy_exact:
        fail("the proxy exception set is empty")

    # A wider blocked parent stays in the block set. Matching an allow set first
    # makes its exception effective without weakening the remaining parent tree.
    suffix, exact = remove_exception_matches(
        suffix, exact, exc_suffix, exc_exact)

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
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = (
        ("filter", suffix, exact),
        ("filter-allow-direct", direct_suffix, direct_exact),
        ("filter-allow-proxy", proxy_suffix, proxy_exact),
    )
    for name, output_suffix, output_exact in outputs:
        list_path = output_dir / f"{name}.list"
        json_path = output_dir / f"{name}.json"
        count = write_domain_rulesets(
            output_suffix, output_exact, list_path, json_path)
        print(f"{list_path}: {count} rules "
              f"(suffix {len(output_suffix)} / exact {len(output_exact)})")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Merge the upstream DNS blocklists")
    sub = ap.add_subparsers(dest="command", required=True)

    build_cmd = sub.add_parser("build", help="build block and routed exception candidates")
    build_cmd.add_argument("--adblock", action="append", default=[], required=True,
                           help="Adblock style source, may be repeated")
    build_cmd.add_argument("--domain-list", action="append", default=[],
                           help="plain domain list merged as suffix rules, may be repeated")
    build_cmd.add_argument("--brands", required=True, help="domestic brand token file")
    build_cmd.add_argument("--output-dir", required=True,
                           help="directory for three .list and source .json pairs")

    args = ap.parse_args()
    if args.command == "build":
        return build(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
