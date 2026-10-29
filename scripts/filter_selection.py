"""Bounded, source-supported hostname additions for the reject rule companion.

Keep the application-selected domain partition intact. New rules retain their
upstream exact/suffix scopes, need agreement, and cannot override an exception,
cover an existing rule, or repeat coverage already supplied by either companion.
Source agreement is a selection heuristic, never a measured usage/blocking rate.
"""
from bisect import bisect_left
from collections import Counter
import hashlib
import json
import re
from pathlib import Path

from filter_patterns import covering_suffix, wildcard_covering_suffix, pattern_line
from filter_optimizer import PatternCoverage


def selection_digest(rules):
    text = "".join(line + "\n" for line in sorted(pattern_line(k, v) for k, v in rules))
    return hashlib.sha256(text.encode()).hexdigest()


def has_descendant(host, reversed_hosts):
    prefix = host[::-1] + "."
    index = bisect_left(reversed_hosts, prefix)
    return index < len(reversed_hosts) and reversed_hosts[index].startswith(prefix)


class RuleSelection:
    def __init__(self, path):
        raw = Path(path).read_bytes()
        data = json.loads(raw)
        if (not isinstance(data, dict) or data.get("schema") != 1
                or data.get("respect_upstream_exceptions") is not True):
            raise ValueError("rule selection requires schema 1 and upstream exceptions")
        self.target = data.get("target_rules")
        self.minimum = data.get("minimum_support")
        self.sources = data.get("source_preference")
        self.categories = data.get("category_preference")
        if type(self.target) is not int or not 1 <= self.target <= 100000:
            raise ValueError("invalid rule-set target")
        if (not isinstance(self.sources, list) or not self.sources
                or any(not isinstance(x, str) or not x for x in self.sources)
                or len(set(self.sources)) != len(self.sources)
                or type(self.minimum) is not int
                or not 2 <= self.minimum <= len(self.sources)):
            raise ValueError("rule selection needs distinct sources and at least two supporters")
        if (not isinstance(self.categories, list) or not self.categories
                or any(not isinstance(x, str) or not x for x in self.categories)
                or len(set(self.categories)) != len(self.categories)):
            raise ValueError("invalid category preference")
        self.sha256 = hashlib.sha256(raw).hexdigest()

    def identity(self):
        return {"schema": 1, "policy_sha256": self.sha256,
                "target_rules": self.target, "minimum_support": self.minimum,
                "source_preference": self.sources, "category_preference": self.categories,
                "frequency_evidence": "not-measured", "blocking_rate_evidence": "not-measured",
                "agreement_evidence": "list-membership-not-independent"}

    def select(self, sources, base_suffix, base_exact, patterns, exclusions=(), scope=None):
        if set(sources) != set(self.sources):
            raise ValueError("rule selection source inventory differs from policy")
        base_count = sum(kind != "ip_cidr" for kind, _ in patterns)
        required = self.target - base_count
        if required < 0:
            raise ValueError("preserved patterns exceed the rule-set target")
        # Every candidate originates in a positive upstream rule; an exact rule
        # cannot be promoted to suffix just because another source lists children.
        suffix_pool = set().union(*(s[0] for s in sources.values()))
        exact_pool = set().union(*(s[1] for s in sources.values()))
        exc_suffix = set(exclusions).union(*(s[2] for s in sources.values()))
        exc_exact = set(exclusions).union(*(s[3] for s in sources.values()))
        exception_hosts = exc_suffix | exc_exact
        reversed_exceptions = sorted(h[::-1] for h in exception_hosts)
        existing = base_suffix | base_exact
        reversed_existing = sorted(h[::-1] for h in existing)
        coverage = PatternCoverage(patterns)
        pattern_ancestors = set()
        for kind, mask in patterns:
            if kind != "domain_wildcard":
                continue
            # Precompute all whole-label ancestors that would subsume a glob.
            # Validate once instead of recompiling every mask for every host.
            wildcard_covering_suffix(mask, set())
            literal = re.split(r"[*?\]]", mask)[-1]
            labels = literal.split(".")
            start = 1 if any(char in mask for char in "*?[") else 0
            pattern_ancestors.update(".".join(labels[i:]) for i in range(start, len(labels)))
        rejected = Counter()
        candidates = []
        category_order = {name: i for i, name in enumerate(self.categories)}
        for kind, pool in (("domain_suffix", suffix_pool), ("domain", exact_pool)):
            for host in sorted(pool):
                is_suffix = kind == "domain_suffix"
                if (covering_suffix(host, base_suffix) or host in base_exact
                        or (is_suffix and has_descendant(host, reversed_existing))):
                    rejected["existing-domain-coverage-or-overlap"] += 1
                    continue
                if (covering_suffix(host, exc_suffix) or host in exc_exact
                        or (is_suffix and has_descendant(host, reversed_exceptions))):
                    rejected["upstream-exception-or-reviewed-exclusion"] += 1
                    continue
                if coverage.domain_proof(("." if is_suffix else "") + host):
                    rejected["existing-pattern-coverage"] += 1
                    continue
                if is_suffix and host in pattern_ancestors:
                    rejected["would-cover-preserved-pattern"] += 1
                    continue
                # A suffix supporter must cover all descendants too. A hosts
                # entry can support an exact candidate, never an entire suffix.
                support = tuple(name for name in self.sources
                                if covering_suffix(host, sources[name][0])
                                or (not is_suffix and host in sources[name][1]))
                if len(support) < self.minimum:
                    rejected["insufficient-scope-support"] += 1
                    continue
                family = scope.family(host) if scope else None
                category = scope.categories.get(family) if family else None
                key = (category_order.get(category, len(category_order)), -len(support),
                       tuple(0 if name in support else 1 for name in self.sources),
                       host, 0 if is_suffix else 1)
                candidates.append((key, kind, host, support, family))
        # Canonicalise the eligible pool before applying the budget. No parent
        # and child pair can consume two slots merely to reach a round number.
        eligible_suffix = {host for _, kind, host, _, _ in candidates if kind == "domain_suffix"}
        ranked = []
        for candidate in candidates:
            _, kind, host, _, _ = candidate
            parent = covering_suffix(host, eligible_suffix, include_self=kind != "domain_suffix")
            if parent:
                rejected["covered-by-eligible-suffix"] += 1
            else:
                ranked.append(candidate)
        ranked.sort()
        if len(ranked) < required:
            raise ValueError(f"only {len(ranked)} eligible additions for {required} slots; refusing padding")
        chosen = ranked[:required]
        rules = {(kind, host) for _, kind, host, _, _ in chosen}
        audit = {
            **self.identity(), "preserved_rules": base_count,
            "eligible_rules": len(ranked), "selected_rules": len(rules),
            "selection_sha256": selection_digest(rules),
            "selected_types": dict(sorted(Counter(k for k, _ in rules).items())),
            "support_histogram": dict(sorted(Counter(str(len(x[3])) for x in chosen).items())),
            "source_support": dict(sorted(Counter(n for x in chosen for n in x[3]).items())),
            "families": dict(sorted(Counter(x[4] or "shared-web" for x in chosen).items())),
            "rejected": dict(sorted(rejected.items())),
        }
        records = [{"rule": pattern_line(kind, host), "support": list(support),
                    "family": family} for _, kind, host, support, family in chosen]
        return rules, audit, records
