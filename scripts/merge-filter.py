#!/usr/bin/env python3
"""Build the filter block set.

Usage:
  merge-filter.py build \
    --adblock /tmp/adguard_dns.txt --adblock /tmp/awavenue.txt \
    --domain-list /tmp/antiad_anv.txt \
    --output-dir /tmp/filter-build

The Adblock style files are merged as domain rules plus the small number of
hosts style entries they carry, and the plain domain lists are merged as suffix
rules. Adblock exception rules (``@@``) are counted for audit purposes but do
not remove positive blocking rules and are not published as routing policy.
Child rules are dropped when covered by a parent in the block set.
"""

import argparse
from bisect import bisect_left
from collections import Counter
import ipaddress
import json
from pathlib import Path
import re
import sys

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
    try:
        ipaddress.ip_address(d)
        return False
    except ValueError:
        pass
    return all(lab and len(lab) <= 63 and not lab.startswith("-")
               and not lab.endswith("-") and re.fullmatch(r"[a-z0-9_\-]+", lab)
               for lab in labels)


def parse_domain_suffix_list(path):
    """Plain domain lists (anti-AD anv.txt and friends): the whole line is a
    domain and is treated as a suffix match."""
    out = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for raw in f:
            s = raw.strip()
            if not s or s.startswith("#") or s.startswith("!"):
                continue
            d = s.lower().rstrip(".")
            if valid_domain(d):
                out.add(d)
    minimum = SOURCE_FLOORS.get(Path(path).name, MIN_DOMAIN_LIST)
    if len(out) < minimum:
        fail(f"{path} holds only {len(out)} rules, below its floor of {minimum}")
    return out


def canonical_rule(line):
    """Canonical key for a same-source $badfilter directive."""
    pattern, _, modifiers = line.partition("$")
    options = sorted(m.strip() for m in modifiers.split(",") if m.strip())
    return pattern.lower(), tuple(options)


def domain_rule(line):
    """Project domain-only rules without broadening paths or scoped modifiers.

    The known AdGuard popup rewrite is intentionally converted to a reject
    match. Arbitrary DNS rewrites, client/DNS-type restrictions, URL paths,
    regular expressions and wildcard masks cannot be represented here.
    """
    pattern, _, modifiers = line.partition("$")
    options = {m.strip() for m in modifiers.split(",") if m.strip()}
    if "badfilter" in options:
        return None, "badfilter"
    supported = {"important", "dnsrewrite=ad-block.dns.adguard.com"}
    if options - supported:
        return None, "unsupported-modifier"
    pattern = pattern.strip()
    if pattern.startswith("/"):
        return None, "regex-or-path"
    if "*" in pattern:
        return None, "wildcard"
    hosts = pattern.split("#", 1)[0].split()
    if len(hosts) >= 2:
        if hosts[0] not in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
            return None, "non-blocking-hosts"
        domains = [d.lower().rstrip(".") for d in hosts[1:]]
        if not all(valid_domain(d) for d in domains):
            return None, "invalid-domain"
        return [("domain", d) for d in domains], "accepted"
    suffix = pattern.startswith("||")
    anchored = pattern.startswith("|") and not suffix
    if suffix:
        pattern = pattern[2:]
    elif anchored:
        pattern = pattern[1:]
    if pattern.endswith("^|"):
        pattern = pattern[:-2]
    elif pattern.endswith("^"):
        pattern = pattern[:-1]
    elif pattern.endswith("|"):
        pattern = pattern[:-1]
    elif anchored:
        return None, "partial-anchor"
    domain = pattern.lower().rstrip(".")
    if not valid_domain(domain):
        return None, "invalid-domain"
    return [("domain_suffix" if suffix else "domain", domain)], "accepted"


def scan_adblock(path):
    suffix, exact = set(), set()
    exc_suffix, exc_exact = set(), set()
    lines = Path(path).read_text(encoding="utf-8", errors="strict").splitlines()
    disabled = set()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("!", "#", "[")):
            continue
        pattern, options = canonical_rule(line)
        if "badfilter" in options:
            disabled.add((pattern, tuple(m for m in options if m != "badfilter")))
    counts = Counter()
    exceptions, skipped = [], []
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(("!", "#", "[")):
            continue
        is_exc = line.startswith("@@")
        rules, reason = domain_rule(line[2:] if is_exc else line)
        if canonical_rule(line) in disabled:
            rules, reason = None, "disabled-by-badfilter"
        counts[reason] += 1
        if is_exc:
            counts["exception-lines"] += 1
            exceptions.append({"line": number, "rule": line, "parse": reason,
                               "domains": [{"kind": k, "domain": d} for k, d in rules or []]})
        if rules is None:
            if len(skipped) < 20:
                skipped.append({"line": number, "rule": line, "reason": reason})
            continue
        for kind, domain in rules:
            if is_exc:
                (exc_suffix if kind == "domain_suffix" else exc_exact).add(domain)
            else:
                (suffix if kind == "domain_suffix" else exact).add(domain)
    minimum = SOURCE_FLOORS.get(Path(path).name, MIN_ADBLOCK)
    if len(suffix) + len(exact) < minimum:
        fail(f"{path} holds only {len(suffix) + len(exact)} rules, below its floor of {minimum}")
    return (suffix, exact, exc_suffix, exc_exact), {
        "counts": dict(sorted(counts.items())), "block_suffix": len(suffix),
        "block_exact": len(exact), "exceptions": exceptions,
        "skipped_examples": skipped,
    }


def parse_adblock(path):
    return scan_adblock(path)[0]


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

    sources, block_sources = {}, {}
    for path in args.adblock:
        (s, e, es, ee), audit = scan_adblock(path)
        sources[Path(path).name] = audit
        block_sources[Path(path).name] = (s, e)
        suffix |= s
        exact |= e
        exc_suffix |= es
        exc_exact |= ee

    for path in args.domain_list:
        domains = parse_domain_suffix_list(path)
        suffix |= domains
        sources[Path(path).name] = {"block_suffix": len(domains), "block_exact": 0}
        block_sources[Path(path).name] = (domains, set())

    # @@ is an Adblock allow/exception operator, not a DIRECT/PROXY routing
    # signal. Keep the count visible for upstream audits, but never let those
    # lines weaken positive rules from this or another source.
    print(f"ignored upstream exceptions: suffix {len(exc_suffix)} / "
          f"exact {len(exc_exact)}")

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
    list_path = output_dir / "filter.list"
    json_path = output_dir / "filter.json"
    count = write_domain_rulesets(suffix, exact, list_path, json_path)
    # Keep @@ visible without inserting an allow rule into either client.
    reversed_domains = sorted(d[::-1] for d in suffix | exact)
    reversed_sources = {name: sorted(d[::-1] for d in s | e)
                        for name, (s, e) in block_sources.items()}
    conflicts = 0
    for source in sources.values():
        for exception in source.get("exceptions", []):
            for item in exception["domains"]:
                domain = item["domain"]
                covering = domain if domain in suffix else parent_of(domain, suffix)
                same_exact = domain in exact
                prefix = domain[::-1] + "."
                start = bisect_left(reversed_domains, prefix)
                child = (item["kind"] == "domain_suffix"
                         and start < len(reversed_domains)
                         and reversed_domains[start].startswith(prefix))
                item["covering_suffix"] = covering
                item["exact_block"] = same_exact
                item["blocked_descendant"] = bool(child)
                item["overlaps_block"] = bool(covering or same_exact or child)
                origins = []
                for name, (src_suffix, src_exact) in block_sources.items():
                    descendants = reversed_sources[name]
                    index = bisect_left(descendants, prefix)
                    if (domain in src_suffix or domain in src_exact
                            or parent_of(domain, src_suffix)
                            or (item["kind"] == "domain_suffix"
                                and index < len(descendants)
                                and descendants[index].startswith(prefix))):
                        origins.append(name)
                item["blocking_sources"] = sorted(origins)
                conflicts += item["overlaps_block"]
    report = {
        "schema": 1, "exception_policy": "audit-only-block-wins",
        "sources": sources,
        "result": {"suffix": len(suffix), "exact": len(exact), "total": count,
                   "overlapping_exception_domains": conflicts},
    }
    (output_dir / "filter-audit.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"exception audit: {conflicts} domains overlap the final block set; "
          "positive block rules retained")
    print(f"{list_path}: {count} rules "
          f"(suffix {len(suffix)} / exact {len(exact)})")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Merge the upstream DNS blocklists")
    sub = ap.add_subparsers(dest="command", required=True)

    build_cmd = sub.add_parser("build", help="build the block candidate")
    build_cmd.add_argument("--adblock", action="append", default=[], required=True,
                           help="Adblock style source, may be repeated")
    build_cmd.add_argument("--domain-list", action="append", default=[],
                           help="plain domain list merged as suffix rules, may be repeated")
    build_cmd.add_argument("--output-dir", required=True,
                           help="directory for the .list and source .json pair")

    args = ap.parse_args()
    if args.command == "build":
        return build(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
