#!/usr/bin/env python3
"""Merge the upstream DNS blocklists into filter.list and its sing-box source.

Usage:
  merge-filter.py build \
    --adblock /tmp/adguard_dns.txt --adblock /tmp/oisd_big.txt \
    --domain-list /tmp/antiad_anv.txt \
    --list-out filter.list --json-out /tmp/filter.json

The Adblock style files are merged as domain rules plus the small number of
hosts style entries they carry, the plain domain lists are merged as suffix
rules, and every 'what to keep' exception (@@) is applied afterwards. Child
rules are dropped when a parent rule already covers them.
"""

import argparse
import json
import re
import sys

# Refuse to publish a list that shrank past these floors: an upstream that
# changes format, serves an error page or returns a truncated file would
# otherwise be committed silently.
MIN_ADBLOCK = 500
MIN_SUFFIX = 250000
MIN_EXACT = 20


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
    if len(suffix) + len(exact) < MIN_ADBLOCK:
        fail(f"{path} holds only {len(suffix) + len(exact)} rules, looks incomplete")
    return suffix, exact, exc_suffix, exc_exact


def parent_of(d, pool):
    """Return the parent suffix rule covering d, or None."""
    labels = d.split(".")
    for i in range(1, len(labels)):
        p = ".".join(labels[i:])
        if p in pool:
            return p
    return None


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

    # Apply the whitelist exceptions
    suffix -= exc_suffix
    exact -= exc_exact
    # Drop exact entries that are covered by an exception suffix
    exact = {d for d in exact if not any(d == es or d.endswith("." + es) for es in exc_suffix)}

    # Deduplicate ad rules: drop child rules when their parent rule exists.
    # '.a.b.c' is fully covered by '.b.c'; the exact rule 'x.b.c' as well.
    suffix_before, exact_before = len(suffix), len(exact)
    suffix = {d for d in suffix if parent_of(d, suffix) is None}
    exact = {d for d in exact if d not in suffix and parent_of(d, suffix) is None}
    print(f"parent-prune: suffix {suffix_before} -> {len(suffix)}, "
          f"exact {exact_before} -> {len(exact)}")

    if len(suffix) < MIN_SUFFIX:
        fail(f"the merged list holds only {len(suffix)} suffix rules, looks incomplete")
    if len(exact) < MIN_EXACT:
        fail(f"the merged list holds only {len(exact)} exact rules, looks incomplete")

    # Surge DOMAIN-SET: a leading '.' means suffix match, no prefix means exact
    lines = ["." + d for d in sorted(suffix)] + [d for d in sorted(exact)]
    with open(args.list_out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    # sing-box rule-set source (JSON), compiled into .srs afterwards.
    # Note that domain_suffix treats the leading dot the other way round:
    #   domain_suffix: 'd'  matches d itself and all of its subdomains
    #                       (equivalent to Surge's '.d')
    #   domain_suffix: '.d' matches only subdomains, not d itself
    # So the dotless form is written here to match filter.list's '.d'.
    # (sing-box matches on label boundaries, 'oo.com' does not hit 'notoo.com'.)
    rules = []
    if exact:
        rules.append({"domain": sorted(exact)})
    if suffix:
        rules.append({"domain_suffix": sorted(suffix)})
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump({"version": 2, "rules": rules}, f, ensure_ascii=False, separators=(",", ":"))

    print(f"{args.list_out}: {len(lines)} rules (suffix {len(suffix)} / exact {len(exact)})")
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

    args = ap.parse_args()
    if args.command == "build":
        return build(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
