#!/usr/bin/env python3
"""Build three disjoint Surge / sing-box filter partitions.

Usage:
  merge-filter.py build \
    --adblock /tmp/adguard_dns.txt --adblock /tmp/awavenue.txt \
    --output-dir /tmp/filter-build

The Adblock style files are merged as domain rules plus the small number of
hosts style entries they carry, and the plain domain lists are merged as suffix
rules. Adblock exception rules (``@@``) are counted for audit purposes but do
not remove positive blocking rules and are not published as routing policy.
Child domains are pruned under a parent suffix. Wildcards and supported regexes
are preserved through the common Surge glob / sing-box RE2 representation.
"""

import argparse
from bisect import bisect_left
from filter_patterns import KINDS, split_options, mask_rules, regex_globs, wildcard_regex, ipv4_regex_networks
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
# MIN_SUFFIX is tied to the five sources listed in build-filter.yml. The floor
# sits below the current merged domain count with roughly 20% of
# headroom while still catching the order-of-magnitude drop that a broken
# upstream produces. MIN_ADBLOCK and MIN_DOMAIN_LIST guard each individual
# source, so a single upstream going empty is caught before the merge.
MIN_ADBLOCK = 500
MIN_DOMAIN_LIST = 10
MIN_SUFFIX = 150000
MIN_EXACT = 20

# Floors for the named inputs used by build-filter.yml. The generic floors above
# still apply to ad-hoc inputs. These tighter limits stop one large healthy list
# from hiding a badly truncated peer.
SOURCE_FLOORS = {
    "filter_1.txt": 150000,
    "filter_2.txt": 5000,
    "filter_5.txt": 40000,
    "filter_53.txt": 700,
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


def write_domain_rulesets(suffix, exact, list_path, json_path, patterns=()):
    """Write Surge RULE-SET and semantically equivalent sing-box JSON."""
    entries = {("domain_suffix", d) for d in suffix} | {("domain", d) for d in exact} | set(patterns)
    lines = [("IP-CIDR6" if k == "ip_cidr" and ":" in v else KINDS[k]) + "," + v
             for k, v in sorted(entries)]
    Path(list_path).write_text("# Surge RULE-SET; use RULE-SET,URL,REJECT (not DOMAIN-SET).\n" +
                               "\n".join(lines) + "\n", encoding="utf-8")
    fields = {}
    for kind, value in sorted(entries):
        if kind == "domain_wildcard":
            kind, value = "domain_regex", wildcard_regex(value)
        fields.setdefault(kind, set()).add(value)
    rules = [{kind: sorted(values)} for kind, values in sorted(fields.items())]
    Path(json_path).write_text(json.dumps({"version": 2, "rules": rules},
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
    lines = sorted({"." + d for d in suffix} | set(exact))
    (output_dir / f"{domain_name}.list").write_text(
        "# Surge DOMAIN-SET; bare domain = exact, leading dot = suffix.\n" +
        "".join(line + "\n" for line in lines), encoding="utf-8")
    rules = [{kind: sorted(values)} for kind, values in
             (("domain", exact), ("domain_suffix", suffix)) if values]
    (output_dir / f"{domain_name}.json").write_text(
        json.dumps({"version": 2, "rules": rules}, ensure_ascii=False,
                   separators=(",", ":")) + "\n", encoding="utf-8")
    patterns = set(patterns)
    if any(k not in {"domain_keyword", "domain_wildcard", "ip_cidr"} for k, _ in patterns):
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
    for path in args.adblock:
        (s, e, es, ee), audit = scan_adblock(path)
        sources[Path(path).name] = audit
        patterns.update(tuple(r) for r in audit["patterns"])
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

    networks = [ipaddress.ip_network(v) for k, v in patterns if k == "ip_cidr"]
    patterns = {(k, v) for k, v in patterns if k != "ip_cidr"}
    for version in (4, 6):
        patterns.update(("ip_cidr", str(n)) for n in ipaddress.collapse_addresses(
            n for n in networks if n.version == version))

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

    # The union of the three partitions is exactly the merged match language.
    output_dir = Path(args.output_dir)
    partitions = write_filter_partitions(suffix, exact, patterns, output_dir)
    count = sum(partitions.values())
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
    report = {
        "schema": 1, "exception_policy": "audit-only-block-wins",
        "sources": sources,
        "result": {"suffix": len(suffix), "exact": len(exact), "patterns": len(patterns), "total": count,
                   "partitions": partitions,
                   "pattern_types": dict(sorted(Counter(k for k, _ in patterns).items())),
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
                           help="Adblock style source, may be repeated")
    build_cmd.add_argument("--domain-list", action="append", default=[],
                           help="plain domain list merged as suffix rules, may be repeated")
    build_cmd.add_argument("--output-dir", required=True,
                           help="directory for the three .list and source .json pairs")

    args = ap.parse_args()
    if args.command == "build":
        return build(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
