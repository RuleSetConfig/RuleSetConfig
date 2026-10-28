#!/usr/bin/env python3
"""Build three disjoint Surge / sing-box filter partitions.

Usage:
  merge-filter.py build \
    --adblock /tmp/filter_1.txt --domain-only-adblock /tmp/filter_2.txt \
    --output-dir /tmp/filter-build

The Adblock style files are merged as domain rules plus the small number of
hosts style entries they carry. Adblock exception rules (``@@``) are counted for
audit purposes but do not remove positive blocking rules and are not published
as routing policy.
Child domains are pruned under a parent suffix. Wildcards and supported regexes
are preserved through the common Surge glob / sing-box RE2 representation.
"""

import argparse
from rule_sorting import cidr_sort_key, domain_sort_key, sort_list_text
from filter_ips import collapse_ip_rules, ip_source_audit, read_ip_rules
from filter_domains import read_domain_rules
from filter_exclusions import (DEFAULT_DOMAIN_EXCLUSIONS, read_domain_exclusions,
                               remove_domain_exclusions)
from bisect import bisect_left
from filter_patterns import (split_options, mask_rules, regex_globs, wildcard_regex,
                             ipv4_regex_networks, covering_suffix, wildcard_covering_suffix,
                             read_pattern_rules, pattern_line, SURGE_ONLY_KINDS)
from collections import Counter
import ipaddress
import json
from pathlib import Path
import re
import sys
from ruleset_format import RULE_SET_VERSION
from filter_optimizer import optimize_filter

# Refuse to publish a list that shrank past these floors: an upstream that
# changes format, serves an error page or returns a truncated file would
# otherwise be committed silently.
#
# MIN_SUFFIX guards the three domain sources selected in build-filter.yml. The floor
# sits below the current merged domain count with roughly 20% of
# headroom while still catching the order-of-magnitude drop that a broken
# upstream produces. MIN_ADBLOCK guards each individual
# source, so a single upstream going empty is caught before the merge.
MIN_ADBLOCK = 500
MIN_SUFFIX = 150000
MIN_EXACT = 20

# Floors for the named inputs used by build-filter.yml. The generic floor above
# still apply to ad-hoc inputs. These tighter limits stop one large healthy list
# from hiding a badly truncated peer.
SOURCE_FLOORS = {
    "filter_1.txt": 150000,
    "filter_2.txt": 5000,
    "filter_59.txt": 700,
}

PARTITIONS = ("REJECT-DOMAIN-SET", "REJECT-IP-SET", "REJECT-RULE-SET")


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


def canonical_rule(line):
    """Canonical key for a same-source $badfilter directive."""
    prefix = "@@" if line.startswith("@@") else ""
    pattern, modifiers = split_options(line[len(prefix):])
    pattern = prefix + pattern
    options = sorted(m.strip() for m in modifiers.split(",") if m.strip())
    return pattern.lower(), tuple(options)


def domain_rule(line):
    """Project supported DNS hostname matches without broadening their scope."""
    pattern, modifiers = split_options(line)
    options = {m.strip() for m in modifiers.split(",") if m.strip()}
    if "badfilter" in options:
        return None, "badfilter"
    if options - {"important", "dnsrewrite=ad-block.dns.adguard.com"}:
        return None, "unsupported-modifier"
    if pattern.startswith("/") and pattern.endswith("/"):
        expression = pattern[1:-1]
        if ":" in expression or "/" in expression:
            return None, "non-host-regex"
        # Unknown regex constructs intentionally fail the build for review.
        masks = regex_globs(expression)
        rules = [("domain_wildcard", m) for m in masks]
        rules.extend(("ip_cidr", n) for n in ipv4_regex_networks(expression, masks))
        return rules, "accepted"
    hosts = pattern.split("#", 1)[0].split()
    if len(hosts) >= 2:
        if hosts[0] not in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
            return None, "non-blocking-hosts"
        domains = [d.lower().rstrip(".") for d in hosts[1:]]
        if not all(valid_domain(d) for d in domains):
            return None, "invalid-domain"
        return [("domain", d) for d in domains], "accepted"
    # AdGuard Home also checks IP strings in A/AAAA/HTTPS responses.
    if re.fullmatch(r"(?:(?:\|\||\|)[0-9a-fA-F:.]+(?:\^\|?|\|)|[0-9a-fA-F:.]+)", pattern):
        raw_ip = pattern.lstrip("|").rstrip("^|")
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError:
            pass
        else:
            return [("ip_cidr", f"{address}/{address.max_prefixlen}")], "accepted"
    rules, reason = mask_rules(pattern)
    if rules and any(k in {"domain", "domain_suffix"} and not valid_domain(v) for k, v in rules):
        return None, "invalid-or-ip-literal-domain"
    return rules, reason


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
    patterns = set()
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(("!", "#", "[")):
            continue
        is_exc = line.startswith("@@")
        if canonical_rule(line) in disabled:
            rules, reason = None, "disabled-by-badfilter"
        else:
            rules, reason = domain_rule(line[2:] if is_exc else line)
        counts[reason] += 1
        if is_exc:
            counts["exception-lines"] += 1
            exceptions.append({"line": number, "rule": line, "parse": reason,
                               "domains": [{"kind": k, "domain": d} for k, d in rules or []]})
        if rules is None:
            skipped.append({"line": number, "rule": line, "reason": reason})
            continue
        for kind, domain in rules:
            if kind not in {"domain", "domain_suffix"}:
                if not is_exc:
                    patterns.add((kind, domain))
                continue
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
        "skipped": skipped,
        "patterns": [list(r) for r in sorted(patterns)],
        "block_patterns": len(patterns),
    }


def parse_adblock(path):
    return scan_adblock(path)[0]


def parent_of(d, pool):
    """Return the parent suffix rule covering d, or None."""
    return covering_suffix(d, pool, include_self=False)


def prune_domains(suffix, exact):
    """Remove suffix children and exact domains already covered by a suffix."""
    suffix = {d for d in suffix if parent_of(d, suffix) is None}
    exact = {d for d in exact if d not in suffix and parent_of(d, suffix) is None}
    return suffix, exact


def prune_patterns(suffix, patterns):
    """Drop only wildcard rules fully covered by a retained domain suffix."""
    return {(kind, value) for kind, value in patterns
            if kind != "domain_wildcard" or not wildcard_covering_suffix(value, suffix)}


def write_domain_rulesets(suffix, exact, list_path, json_path, patterns=()):
    """Write portable scopes plus audited Surge-only STUN and User-Agent rules."""
    entries = {("domain_suffix", d) for d in suffix} | {("domain", d) for d in exact} | set(patterns)
    lines = [pattern_line(kind, value) for kind, value in sorted(entries)]
    text = "# Surge RULE-SET; use RULE-SET,URL,REJECT (not DOMAIN-SET).\n"
    if any(kind in SURGE_ONLY_KINDS for kind, _ in entries):
        text += "# Surge-only STUN/User-Agent entries are omitted from SRS; see README.\n"
    text += "\n".join(lines) + "\n"
    Path(list_path).write_text(sort_list_text(text), encoding="utf-8")
    fields, logical = {}, []
    for kind, value in sorted(entries):
        if kind in SURGE_ONLY_KINDS:
            continue  # Unsupported headless fields are recorded in the conversion audit.
        if kind == "logical_and":
            logical.append({"type": "logical", "mode": "and",
                            "rules": [{"domain_keyword": [key]} for key in value]})
            continue
        if kind == "domain_wildcard":
            kind, value = "domain_regex", wildcard_regex(value)
        fields.setdefault(kind, set()).add(value)
    rules = logical + [{kind: sorted(values, key=cidr_sort_key) if kind == "ip_cidr" else sorted(values)}
                       for kind, values in sorted(fields.items())]
    Path(json_path).write_text(json.dumps({"version": RULE_SET_VERSION, "rules": rules},
                                         ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    return len(lines)


def write_filter_partitions(suffix, exact, patterns, output_dir):
    """Partition the already deduplicated match language without widening it.

    Surge's IP-only partition is a RULE-SET of IP-CIDR/IP-CIDR6 declarations;
    IP-SET is the artifact name, not a Surge rule type. Empty partitions have
    zero JSON rules, never an empty default rule (which would match everything).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    domain_name, ip_name, rule_name = PARTITIONS
    lines = sorted({"." + d for d in suffix} | set(exact), key=domain_sort_key)
    (output_dir / f"{domain_name}.list").write_text(
        "# Surge DOMAIN-SET; bare domain = exact, leading dot = suffix.\n" +
        "".join(line + "\n" for line in lines), encoding="utf-8")
    rules = [{kind: sorted(values)} for kind, values in
             (("domain", exact), ("domain_suffix", suffix)) if values]
    (output_dir / f"{domain_name}.json").write_text(
        json.dumps({"version": RULE_SET_VERSION, "rules": rules}, ensure_ascii=False,
                   separators=(",", ":")) + "\n", encoding="utf-8")
    patterns = set(patterns)
    if any(k not in {"domain_keyword", "domain_wildcard", "ip_cidr", "logical_and"} | SURGE_ONLY_KINDS for k, _ in patterns):
        raise ValueError("unexpected rule type in filter patterns")
    ip_rules = {(k, v) for k, v in patterns if k == "ip_cidr"}
    other_rules = patterns - ip_rules
    return {
        domain_name: len(lines),
        ip_name: write_domain_rulesets(set(), set(), output_dir / f"{ip_name}.list",
                                      output_dir / f"{ip_name}.json", ip_rules),
        rule_name: write_domain_rulesets(set(), set(), output_dir / f"{rule_name}.list",
                                        output_dir / f"{rule_name}.json", other_rules),
    }


def build(args):
    suffix, exact = set(), set()
    exc_suffix, exc_exact = set(), set()

    sources, block_sources = {}, {}
    patterns = set()
    inputs = [(path, False) for path in args.adblock]
    inputs += [(path, True) for path in getattr(args, "domain_only_adblock", [])]
    for path, domain_only in inputs:
        name = Path(path).name
        if name in sources:
            fail(f"duplicate upstream source identity: {name}")
        (s, e, es, ee), audit = scan_adblock(path)
        selected = {(kind, value) for kind, value in audit["patterns"]
                    if not domain_only or kind != "ip_cidr"}
        audit["role"] = "domains-patterns-only" if domain_only else "domains-patterns-and-ips"
        audit["included"] = {"suffix": len(s), "exact": len(e),
                             "patterns": len(selected),
                             "ip_rules": sum(kind == "ip_cidr" for kind, _ in selected)}
        sources[name] = audit
        patterns.update(selected)
        block_sources[name] = (s, e)
        suffix |= s
        exact |= e
        exc_suffix |= es
        exc_exact |= ee

    for path in getattr(args, "domain_rules", []):
        try:
            s, e = read_domain_rules(path)
        except ValueError as error:
            fail(str(error))
        sources[Path(path).name] = {
            "block_suffix": len(s), "block_exact": len(e),
            "counts": {"domain_suffix": len(s), "domain": len(e)},
        }
        block_sources[Path(path).name] = (s, e)
        suffix |= s
        exact |= e

    # @@ is an Adblock allow/exception operator, not a DIRECT/PROXY routing
    # signal. Keep the count visible for upstream audits, but never let those
    # lines weaken positive rules from this or another source.
    print(f"ignored upstream exceptions: suffix {len(exc_suffix)} / "
          f"exact {len(exc_exact)}")

    for path in getattr(args, "pattern_rules", []):
        try:
            supplemental = read_pattern_rules(path)
        except ValueError as error:
            fail(str(error))
        sources[Path(path).name] = {
            "block_suffix": 0, "block_exact": 0,
            "counts": dict(sorted(Counter(kind for kind, _ in supplemental).items())),
            "patterns": [list(rule) for rule in sorted(supplemental)],
            "block_patterns": len(supplemental),
        }
        patterns.update(supplemental)

    for path in getattr(args, "ip_rules", []):
        supplemental = read_ip_rules(path)
        sources[Path(path).name] = ip_source_audit(supplemental)
        patterns.update(supplemental)
    patterns = collapse_ip_rules(patterns)

    # Deduplicate ad rules: drop child rules when their parent rule exists.
    # '.a.b.c' is fully covered by '.b.c'; the exact rule 'x.b.c' as well.
    suffix_before, exact_before = len(suffix), len(exact)
    exclusion_path = Path(getattr(args, "domain_exclusions", DEFAULT_DOMAIN_EXCLUSIONS))
    try:
        exclusions = read_domain_exclusions(exclusion_path)
        suffix, exact, exclusion_audit = remove_domain_exclusions(suffix, exact, exclusions, patterns)
    except ValueError as error:
        fail(str(error))
    sources[exclusion_path.name] = {"block_suffix": 0, "block_exact": 0,
                                  "counts": {"manual-domain-exclusions": len(exclusions)}}
    # Exclude a reviewed parent before pruning, so explicit child blocks survive.
    suffix, exact = prune_domains(suffix, exact)
    print(f"manual domain exclusions: {len(exclusion_audit['removed_suffix'])} suffix / "
          f"{len(exclusion_audit['removed_exact'])} exact removed")
    print(f"parent-prune: suffix {suffix_before} -> {len(suffix)}, "
          f"exact {exact_before} -> {len(exact)}")

    if len(suffix) < MIN_SUFFIX:
        fail(f"the merged list holds only {len(suffix)} suffix rules, looks incomplete")
    if len(exact) < MIN_EXACT:
        fail(f"the merged list holds only {len(exact)} exact rules, looks incomplete")

    patterns_before = len(patterns)
    patterns = prune_patterns(suffix, patterns)
    parent_pruned_patterns = patterns_before - len(patterns)
    print(f"parent-prune: patterns {patterns_before} -> {len(patterns)}")

    # Audit exceptions against the pre-optimization domain projection. Later
    # equivalent pruning preserves that union even when a pattern covers it.
    output_dir = Path(args.output_dir)
    # Keep @@ visible without inserting an allow rule into either client.
    reversed_domains = sorted(d[::-1] for d in suffix | exact)
    reversed_sources = {name: sorted(d[::-1] for d in s | e)
                        for name, (s, e) in block_sources.items()}
    conflicts = 0
    for source in sources.values():
        for exception in source.get("exceptions", []):
            for item in exception["domains"]:
                if item["kind"] not in {"domain", "domain_suffix"}:
                    item["overlap_analysis"] = "pattern-not-evaluated"
                    continue
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
    suffix, exact, patterns, optimization = optimize_filter(suffix, exact, patterns)
    partitions = write_filter_partitions(suffix, exact, patterns, output_dir)
    count = sum(partitions.values())
    print("equivalent cross-set optimization: "
          f"{optimization['summary']['domain_records_removed']} domain records / "
          f"{optimization['summary']['wildcard_rules_net_removed']} net wildcard rules removed")
    report = {
        "schema": 1, "exception_policy": "audit-only-block-wins",
        "optimization": optimization,
        "sources": sources,
        "result": {"suffix": len(suffix), "exact": len(exact), "patterns": len(patterns), "total": count,
                   "partitions": partitions,
                   "parent_pruned_patterns": parent_pruned_patterns,
                   "equivalent_optimization": optimization["summary"],
                   "domain_exclusions": exclusion_audit,
                   "pattern_types": dict(sorted(Counter(k for k, _ in patterns).items())),
                   "surge_only": sorted(pattern_line(k, v) for k, v in patterns if k in SURGE_ONLY_KINDS),
                   "source_roles": {name: source["role"] for name, source in sorted(sources.items())
                                    if "role" in source},
                   "overlapping_exception_domains": conflicts},
    }
    (output_dir / "filter-audit.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"exception audit: {conflicts} domains overlap the final block set; "
          "positive block rules retained")
    for name, size in partitions.items():
        print(f"{output_dir / (name + '.list')}: {size} rules")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Merge the upstream DNS blocklists")
    sub = ap.add_subparsers(dest="command", required=True)

    build_cmd = sub.add_parser("build", help="build the block candidate")
    build_cmd.add_argument("--adblock", action="append", default=[], required=True,
                           help="Adblock source for hostnames, domain patterns and destination IPs; may be repeated")
    build_cmd.add_argument("--domain-only-adblock", action="append", default=[],
                           help="Adblock source for hostnames/domain patterns only; never import its destination IPs")
    build_cmd.add_argument("--ip-rules", action="append", default=[],
                           help="supplementary IP-only Surge RULE-SET source, may be repeated")
    build_cmd.add_argument("--domain-rules", action="append", default=[],
                           help="supplementary Surge DOMAIN-SET source, may be repeated")
    build_cmd.add_argument("--pattern-rules", action="append", default=[],
                           help="supplementary patterns and reviewed Surge-only STUN/User-Agent source; may be repeated")
    build_cmd.add_argument("--domain-exclusions", default=str(DEFAULT_DOMAIN_EXCLUSIONS),
                           help="reviewed hostname exclusions; defaults to repository source")
    build_cmd.add_argument("--output-dir", required=True,
                           help="directory for the three .list and source .json pairs")

    args = ap.parse_args()
    if args.command == "build":
        return build(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
