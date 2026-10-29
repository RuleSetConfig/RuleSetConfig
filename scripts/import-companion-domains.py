#!/usr/bin/env python3
"""Select reproducible companion suffixes from pinned community domain sources."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import tarfile
import urllib.request

from domain_keywords import KEYWORD_SOURCE, IMPORT_SOURCE, covering_keyword
from filter_domains import read_domain_rules
from filter_patterns import read_pattern_rules


def ancestors(host, include_self=True):
    labels = host.split(".")
    return (".".join(labels[i:]) for i in range(0 if include_self else 1, len(labels)))


def covered(host, suffixes, include_self=True):
    return next((parent for parent in ancestors(host, include_self) if parent in suffixes), None)


def valid_suffix(host):
    return (len(host) <= 253 and "." in host and not re.fullmatch(r"[0-9.]+", host)
            and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in host.split(".")))


def read_group(data, name, policy, audit, active=()):
    if name in active or not re.fullmatch(r"[a-z0-9_!.-]+", name):
        raise ValueError(f"invalid or circular community include: {name}")
    result = set()
    for raw in data[name].splitlines():
        tokens = raw.split("#", 1)[0].split()
        if not tokens:
            continue
        entry, tags = tokens[0], set(tokens[1:])
        if entry.startswith("include:"):
            if tags:
                audit["attribute_filtered_includes_omitted"] += 1
                continue
            result |= read_group(data, entry[8:], policy, audit, active + (name,))
        elif entry.startswith(("full:", "regexp:", "keyword:")):
            audit["non_suffix_records_omitted"] += 1
        elif tags & {"@ads", "@telemetry"} or ("@cn" if policy == "proxy" else "@!cn") in tags:
            audit["tagged_records_omitted"] += 1
        else:
            host = entry.removeprefix("domain:").lower()
            if "." not in host:
                audit["single_label_suffixes_omitted"] += 1
                continue
            if not valid_suffix(host):
                raise ValueError(f"unsupported community suffix in {name}: {entry}")
            result.add(host)
    return result


def fetch_sources(plan, directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name, record in plan["sources"].items():
        destination = directory / record["file"]
        if not destination.is_file():
            request = urllib.request.Request(record["url"], headers={"User-Agent": "RuleSetConfig"})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            destination.write_bytes(data)
        data = destination.read_bytes()
        if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError(f"pinned upstream fingerprint differs: {name}")


def select(root, plan, source_dir, document):
    audit = {policy: Counter() for policy in ("proxy", "direct")}
    archive = source_dir / plan["sources"]["community"]["file"]
    with tarfile.open(archive) as tar:
        # Read regular data members only; no extraction or archive paths are trusted.
        records = {}
        for member in tar.getmembers():
            parts = member.name.split("/")
            if member.isfile() and len(parts) == 3 and parts[1] == "data":
                records[parts[2]] = tar.extractfile(member).read().decode("utf-8")
    pools, preferred = {}, {}
    for policy in ("proxy", "direct"):
        path = source_dir / plan["sources"][policy]["file"]
        suffixes, exact = read_domain_rules(path)
        audit[policy]["upstream_suffixes"] = len(suffixes)
        audit[policy]["upstream_exact_hosts_omitted"] = len(exact)
        app_domains = set()
        for group in plan["application_groups"][policy]:
            app_domains |= read_group(records, group, policy, audit[policy])
        vendors = set(plan["vendor_suffixes"][policy])
        preferred[policy] = app_domains | vendors | set(plan["seed_suffixes"][policy])
        pools[policy] = suffixes | preferred[policy]
        audit[policy]["application_and_vendor_suffixes"] = len(preferred[policy])
    tlds = {}
    for policy in ("proxy", "direct"):
        tlds[policy], _ = read_domain_rules(root / (policy.upper() + "-DOMAIN-SET.list"))
    reject_suffixes, _ = read_domain_rules(root / "REJECT-DOMAIN-SET.list")
    reject_keywords = {value for kind, value in read_pattern_rules(root / "REJECT-RULE-SET.list")
                       if kind == "domain_keyword"}
    cleaned = {}
    for policy in ("proxy", "direct"):
        other = "direct" if policy == "proxy" else "proxy"
        keep = set()
        for host in pools[policy]:
            reason = None
            if not valid_suffix(host): reason = "invalid_suffixes_omitted"
            elif covered(host, tlds[policy]): reason = "same_policy_tld_covered"
            elif covered(host, tlds[other]): reason = "opposite_policy_tld_covered"
            elif covering_keyword(host, document[policy]): reason = "same_policy_keyword_covered"
            elif covering_keyword(host, document[other]): reason = "opposite_policy_keyword_covered"
            elif covered(host, reject_suffixes) or covering_keyword(host, reject_keywords):
                reason = "rejection_covered"
            if reason: audit[policy][reason] += 1
            else: keep.add(host)
        cleaned[policy] = {host for host in keep if not covered(host, keep, include_self=False)}
        audit[policy]["parent_covered"] = len(keep) - len(cleaned[policy])
    # Maintained seeds/vendors outrank application families, which outrank the
    # general upstream pools. Equal-priority ambiguous scopes are omitted.
    def priority(policy, host):
        for score, entries in ((3, set(plan["seed_suffixes"][policy]) | set(plan["vendor_suffixes"][policy])),
                               (2, preferred[policy])):
            if covered(host, entries) or any(covered(item, {host}) for item in entries):
                return score
        return 1

    conflicts = {policy: set() for policy in cleaned}
    for policy in cleaned:
        other = "direct" if policy == "proxy" else "proxy"
        for host in cleaned[policy]:
            parent = covered(host, cleaned[other])
            if parent:
                own_priority, other_priority = priority(policy, host), priority(other, parent)
                if own_priority <= other_priority:
                    conflicts[policy].add(host)
                if other_priority <= own_priority:
                    conflicts[other].add(parent)
    selected = {}
    for policy in cleaned:
        candidates = cleaned[policy] - conflicts[policy]
        audit[policy]["cross_policy_conflicts_omitted"] = len(conflicts[policy])
        # Give an app's retained ancestor its priority too, after parent pruning.
        important = {parent for host in preferred[policy]
                     if (parent := covered(host, candidates)) is not None}
        seeds = set(plan["seed_suffixes"][policy])
        if not seeds <= candidates:
            raise ValueError(f"maintained seed suffix lost from {policy}: {seeds - candidates}")
        limit = plan["rule_counts"][policy] - len(document[policy])
        if len(important) > limit or len(candidates) < limit:
            raise ValueError(f"insufficient non-redundant {policy} suffixes for target {limit}")
        rank = lambda host: (host not in important, hashlib.sha256(host.encode("ascii")).hexdigest(), host)
        selected[policy] = sorted(sorted(candidates, key=rank)[:limit])
        audit[policy]["eligible_suffixes"] = len(candidates)
        audit[policy]["preferred_suffixes_selected"] = len(important)
        audit[policy]["selected_suffixes"] = len(selected[policy])
        audit[policy]["retained_keywords"] = len(document[policy])
        audit[policy]["total_rules"] = limit + len(document[policy])
    return selected, audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--audit", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    plan = json.loads((root / IMPORT_SOURCE).read_text())
    document = json.loads((root / KEYWORD_SOURCE).read_text())
    if args.fetch:
        fetch_sources(plan, args.source_dir)
    else:
        # The same hash checks apply to offline cached inputs.
        for record in plan["sources"].values():
            data = (args.source_dir / record["file"]).read_bytes()
            if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError("cached upstream fingerprint differs")
    selected, audit = select(root, plan, args.source_dir, document)
    for policy, values in selected.items():
        if args.check and document[policy + "_domain_suffixes"] != values:
            raise ValueError(f"{policy}: committed suffix selection differs from pinned inputs")
        document[policy + "_domain_suffixes"] = values
    if args.check and document["rule_counts"] != plan["rule_counts"]:
        raise ValueError("committed rule targets differ from import policy")
    document["rule_counts"] = plan["rule_counts"]
    if not args.check:
        (root / KEYWORD_SOURCE).write_text(json.dumps(document, indent=2) + "\n")
    if args.audit:
        args.audit.parent.mkdir(parents=True, exist_ok=True)
        args.audit.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
    print(json.dumps(audit, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
