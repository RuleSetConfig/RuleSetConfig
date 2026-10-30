#!/usr/bin/env python3
"""Select reproducible companion suffixes from pinned community domain sources."""

import argparse
import csv
import shutil
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import tarfile
import urllib.request

from domain_keywords import KEYWORD_SOURCE, IMPORT_SOURCE, covering_keyword
from filter_domains import read_domain_rules
from filter_optimizer import read_optional_patterns, PatternCoverage


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


def fetch_sources(plan, directory, root=None):
    directory.mkdir(parents=True, exist_ok=True)
    for name, record in plan["sources"].items():
        destination = directory / record["file"]
        if not destination.is_file() and record["url"].startswith("repository:"):
            source = (Path(root or ".") / record["url"][11:]).resolve()
            if not source.is_relative_to(Path(root or ".").resolve()):
                raise ValueError("ranking source escapes repository")
            shutil.copyfile(source, destination)
        if not destination.is_file():
            request = urllib.request.Request(record["url"], headers={"User-Agent": "RuleSetConfig"})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            destination.write_bytes(data)
        data = destination.read_bytes()
        if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError(f"pinned upstream fingerprint differs: {name}")


def select(root, plan, source_dir, document):
    audit = {p: Counter() for p in ("proxy", "direct")}
    with tarfile.open(source_dir / plan["sources"]["community"]["file"]) as tar:
        records = {m.name.split("/")[2]: tar.extractfile(m).read().decode("utf-8")
                   for m in tar.getmembers() if m.isfile() and len(m.name.split("/")) == 3
                   and m.name.split("/")[1] == "data"}
    pools, preferred, raw_exact = {}, {}, {}
    for policy in ("proxy", "direct"):
        suffixes, exact = read_domain_rules(source_dir / plan["sources"][policy]["file"])
        raw_exact[policy] = exact
        audit[policy]["upstream_suffixes"] = len(suffixes)
        audit[policy]["upstream_exact_hosts"] = len(exact)
        app = set()
        for group in plan["application_groups"][policy]:
            app |= read_group(records, group, policy, audit[policy])
        preferred[policy] = app | set(plan["vendor_suffixes"][policy]) | set(plan["seed_suffixes"][policy])
        pools[policy] = suffixes | preferred[policy]
        audit[policy]["application_and_vendor_suffixes"] = len(preferred[policy])
    domain_sets = {p: read_domain_rules(root / (p.upper() + "-DOMAIN-SET.list")) for p in pools}
    reject_suffixes, reject_exact = read_domain_rules(root / "REJECT-DOMAIN-SET.list")
    for raw in (root / "REJECT-RULE-SET.list").read_text().splitlines():
        parts = raw.split("#", 1)[0].strip().split(",")
        if len(parts) == 2 and parts[0] in ("DOMAIN", "DOMAIN-SUFFIX"):
            (reject_suffixes if parts[0] == "DOMAIN-SUFFIX" else reject_exact).add(parts[1])
    patterns = read_optional_patterns(root / "REJECT-RULE-SET.list")
    reject_words = {v for k, v in patterns if k == "domain_keyword"}
    reject_coverage = PatternCoverage(patterns)

    def rejected(host, suffix):
        if covered(host, reject_suffixes) or covering_keyword(host, reject_words):
            return True
        if not suffix and host in reject_exact:
            return True
        # Check masks and logical conjunctions with their full matching scope.
        return bool(reject_coverage.domain_proof(("." if suffix else "") + host))

    cleaned = {}
    for policy in pools:
        other = "direct" if policy == "proxy" else "proxy"
        keep = set()
        for host in pools[policy]:
            reason = None
            if not valid_suffix(host): reason = "invalid_suffixes_omitted"
            elif covered(host, domain_sets[policy][0]): reason = "same_policy_domain_set_covered"
            elif covered(host, domain_sets[other][0]): reason = "opposite_policy_domain_set_covered"
            elif covering_keyword(host, document[policy]): reason = "same_policy_keyword_covered"
            elif covering_keyword(host, document[other]): reason = "opposite_policy_keyword_covered"
            elif rejected(host, True): reason = "rejection_covered"
            if reason: audit[policy][reason] += 1
            else: keep.add(host)
        cleaned[policy] = {h for h in keep if not covered(h, keep, False)}
        audit[policy]["parent_covered"] = len(keep) - len(cleaned[policy])

    def priority(policy, host):
        for score, entries in ((3, set(plan["seed_suffixes"][policy]) | set(plan["vendor_suffixes"][policy])),
                               (2, preferred[policy])):
            if covered(host, entries) or any(covered(item, {host}) for item in entries):
                return score
        return 1

    conflicts = {p: set() for p in cleaned}
    for policy in cleaned:
        other = "direct" if policy == "proxy" else "proxy"
        for host in cleaned[policy]:
            parent = covered(host, cleaned[other])
            if parent:
                own, opposite = priority(policy, host), priority(other, parent)
                if own <= opposite: conflicts[policy].add(host)
                if opposite <= own: conflicts[other].add(parent)
    candidates = {p: cleaned[p] - conflicts[p] for p in cleaned}
    ranked_hosts = []
    if "ranking" in plan["sources"]:
        path = source_dir / plan["sources"]["ranking"]["file"]
        seen = set(); last = 0
        with path.open(newline="") as stream:
            for row in csv.DictReader(stream):
                rank, host = int(row["rank"]), row["domain"]
                if rank <= last: raise ValueError("ranking rows must have increasing ranks")
                last = rank
                if valid_suffix(host) and host not in seen:
                    ranked_hosts.append((rank, host)); seen.add(host)
    best_rank = {p: {} for p in candidates}
    for rank, host in ranked_hosts:
        for policy in candidates:
            parent = covered(host, candidates[policy])
            if parent: best_rank[policy].setdefault(parent, rank)
    selected = {}
    for policy in candidates:
        important = {parent for host in preferred[policy]
                     if (parent := covered(host, candidates[policy])) is not None}
        seeds = set(plan["seed_suffixes"][policy])
        if not seeds <= candidates[policy]:
            raise ValueError(f"maintained seed suffix lost from {policy}: {seeds - candidates[policy]}")
        limit = plan["rule_counts"][policy] - len(document[policy])
        if len(important) > limit: raise ValueError("preferred suffixes exceed target")
        def order(host):
            return (host not in important, best_rank[policy].get(host, 10**12),
                    hashlib.sha256(host.encode()).hexdigest(), host)
        suffixes = sorted(sorted(candidates[policy], key=order)[:limit])
        selected[policy] = {"suffixes": suffixes, "domains": []}
        audit[policy]["cross_policy_conflicts_omitted"] = len(conflicts[policy])
        audit[policy]["eligible_suffixes"] = len(candidates[policy])
        audit[policy]["preferred_suffixes_selected"] = len(important)
        missing = limit - len(suffixes)
        if missing and policy == "proxy":
            # Preserve exact hostname scope. All known direct scopes are excluded,
            # including direct candidates outside the selected direct budget.
            other = "direct"; exact_pool = []
            retained_suffixes = set(suffixes)
            for rank, host in [(0, h) for h in sorted(raw_exact[policy])] + ranked_hosts:
                if (not valid_suffix(host) or covered(host, retained_suffixes)
                        or covered(host, domain_sets[policy][0]) or host in domain_sets[policy][1]
                        or covered(host, domain_sets[other][0]) or host in domain_sets[other][1]
                        or covering_keyword(host, document[policy]) or covering_keyword(host, document[other])
                        or covered(host, candidates[other]) or host in raw_exact[other]
                        or rejected(host, False)):
                    continue
                exact_pool.append((rank, host))
            unique = {}
            for rank, host in exact_pool:
                unique.setdefault(host, rank)
            domains = [h for h, r in sorted(unique.items(), key=lambda x:(x[1],x[0]))[:missing]]
            selected[policy]["domains"] = sorted(domains)
            audit[policy]["eligible_exact_hosts"] = len(unique)
            missing -= len(domains)
        if missing:
            raise ValueError(f"insufficient non-redundant {policy} domains: short by {missing}")
        audit[policy]["selected_suffixes"] = len(suffixes)
        audit[policy]["selected_exact_hosts"] = len(selected[policy]["domains"])
        audit[policy]["retained_keywords"] = len(document[policy])
        audit[policy]["total_rules"] = plan["rule_counts"][policy]
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
        fetch_sources(plan, args.source_dir, root)
    else:
        # The same hash checks apply to offline cached inputs.
        for record in plan["sources"].values():
            data = (args.source_dir / record["file"]).read_bytes()
            if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError("cached upstream fingerprint differs")
    selected, audit = select(root, plan, args.source_dir, document)
    for policy, values in selected.items():
        for key, field in (("suffixes", "_domain_suffixes"), ("domains", "_domains")):
            if args.check and document.get(policy + field, []) != values[key]:
                raise ValueError(f"{policy}: committed selection differs from pinned inputs")
            document[policy + field] = values[key]
    document["schema"] = 3
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
