"""Equivalent cross-set pruning for companion REJECT domain and pattern sets.

The sets must remain loaded together at the same policy, priority and stage.
Every transformation has a certificate; unknown syntax fails rather than being
projected to a wider match. Native tests complement the symbolic scope proof.
"""
from collections import Counter
import re

from filter_patterns import (pattern_line, wildcard_regex, wildcard_covering_suffix,
                             SURGE_ONLY_KINDS)
from glob_optimizer import Inclusion, optimize_masks


def minimal_keywords(keywords):
    retained, removed = [], []
    for keyword in sorted(set(keywords), key=lambda word: (len(word), word)):
        parent = next((word for word in retained if word in keyword), None)
        if parent is None:
            retained.append(keyword)
        else:
            removed.append({"keyword": keyword, "covered_by": parent})
    return retained, removed


def guaranteed_keyword(mask, keywords):
    """Return a keyword in a mandatory literal fragment of a supported glob."""
    fragments, fragment, in_class = [], "", False
    for character in mask:
        if character == "[":
            in_class = True
        if character in "*?[" or in_class:
            if fragment:
                fragments.append(fragment)
                fragment = ""
        else:
            fragment += character
        if character == "]":
            in_class = False
    if fragment:
        fragments.append(fragment)
    return next((word for word in keywords
                 if any(word in literal for literal in fragments)), None)


class PatternCoverage:
    """Prove exact-host or entire-suffix coverage by a retained pattern union."""

    def __init__(self, patterns):
        self.patterns = set(patterns)
        self.keywords = sorted(value for kind, value in self.patterns if kind == "domain_keyword")
        self.conjunctions = sorted(value for kind, value in self.patterns if kind == "logical_and")
        self.masks = sorted((value for kind, value in self.patterns if kind == "domain_wildcard"),
                            key=lambda mask: (len(mask), mask))
        self.inclusion = Inclusion()
        self.trie = {}
        for mask in self.masks:
            last = max(mask.rfind(character) for character in "*?[]")
            node = self.trie
            for character in reversed(mask[last + 1:]):
                node = node.setdefault(character, {})
            node.setdefault(None, []).append((mask, re.compile(wildcard_regex(mask))))

    def glob_matches(self, domain):
        node = self.trie
        candidates = list(node.get(None, []))
        for character in reversed(domain):
            node = node.get(character)
            if node is None:
                break
            candidates.extend(node.get(None, []))
        return [mask for mask, expression in candidates if expression.fullmatch(domain)]

    def domain_proof(self, entry):
        suffix = entry.startswith(".")
        domain = entry.lstrip(".")
        keyword = next((word for word in self.keywords if word in domain), None)
        if keyword is not None:
            return {"kind": "keyword", "covered_by": ["DOMAIN-KEYWORD," + keyword]}
        conjunction = next((terms for terms in self.conjunctions
                            if all(word in domain for word in terms)), None)
        if conjunction is not None:
            return {"kind": "logical-and", "covered_by": [pattern_line("logical_and", conjunction)]}
        apex = self.glob_matches(domain)
        if not suffix and apex:
            return {"kind": "glob-exact", "covered_by": ["DOMAIN-WILDCARD," + apex[0]]}
        if suffix:
            prefix_closed = next((mask for mask in apex if mask.startswith("*")), None)
            if prefix_closed is not None:
                return {"kind": "glob-prefix-closed", "covered_by": ["DOMAIN-WILDCARD," + prefix_closed]}
            if apex:
                child = next((mask for mask in self.glob_matches("." + domain)
                              if mask.startswith("*")), None)
                if child is not None:
                    return {"kind": "glob-apex-plus-children-union", "covered_by": [
                        "DOMAIN-WILDCARD," + apex[0], "DOMAIN-WILDCARD," + child]}
        return None

    def covers_pattern(self, kind, value, suffixes=()):
        if (kind, value) in self.patterns:
            return True
        if kind == "domain_keyword":
            return any(word in value for word in self.keywords)
        if kind != "domain_wildcard":
            return False
        return (guaranteed_keyword(value, self.keywords) is not None
                or wildcard_covering_suffix(value, suffixes) is not None
                or any(self.inclusion.prove(value, mask) is not None for mask in self.masks))


def read_optional_patterns(path):
    from filter_patterns import read_pattern_rules
    if not path.is_file():
        return set()
    if not any(line.strip() and not line.lstrip().startswith(("#", "//"))
               for line in path.read_text(encoding="utf-8").splitlines()):
        return set()
    return read_pattern_rules(path, skip_domains=True)


def optimize_filter(suffixes, exact, patterns):
    """Return smaller partitions with exactly the same combined match scope."""
    patterns = set(patterns)
    keywords, keyword_deletions = minimal_keywords(
        value for kind, value in patterns if kind == "domain_keyword")
    masks, keyword_masks = set(), []
    for kind, value in sorted(patterns):
        if kind != "domain_wildcard":
            continue
        keyword = guaranteed_keyword(value, keywords)
        if keyword is not None:
            keyword_masks.append({"mask": value, "keyword": keyword})
        else:
            masks.add(value)
    optimized_masks, proof = optimize_masks(masks)
    retained_patterns = {(kind, value) for kind, value in patterns
                         if kind not in {"domain_keyword", "domain_wildcard"}}
    retained_patterns.update(("domain_keyword", word) for word in keywords)
    retained_patterns.update(("domain_wildcard", mask) for mask in optimized_masks)
    coverage = PatternCoverage(retained_patterns)
    retained_suffixes, retained_exact, removed = set(), set(), []
    for is_suffix, domains, retained in ((True, suffixes, retained_suffixes), (False, exact, retained_exact)):
        for domain in sorted(domains):
            entry = ("." if is_suffix else "") + domain
            reason = coverage.domain_proof(entry)
            if reason is None:
                retained.add(domain)
            else:
                removed.append({"entry": entry, **reason})
    protected = {rule for rule in patterns if rule[0] in {"ip_cidr", "logical_and"} | SURGE_ONLY_KINDS}
    if not protected <= retained_patterns:
        raise ValueError("IP, explicit AND or reviewed Surge-only scope changed")
    summary = {
        "domain_records_removed": len(removed),
        "domain_deletion_reasons": dict(sorted(Counter(item["kind"] for item in removed).items())),
        "keyword_rules_removed": len(keyword_deletions),
        "wildcard_rules_net_removed": sum(kind == "domain_wildcard" for kind, _ in patterns) - len(optimized_masks),
        "requires_companion_sets_same_policy_and_stage": True,
        "input_pattern_types": dict(sorted(Counter(kind for kind, _ in patterns).items())),
        "output_pattern_types": dict(sorted(Counter(kind for kind, _ in retained_patterns).items())),
        "coverage_removed_by_missing_logs": 0,
        "ip_and_protocol_and_explicit_and_preserved": True,
        "surge_only_rules_preserved": True,
    }
    audit = {"schema": 1, "summary": summary, "domain_deletions": removed,
             "keyword_deletions": keyword_deletions, "wildcards_covered_by_keywords": keyword_masks,
             "pattern_proofs": proof}
    return retained_suffixes, retained_exact, retained_patterns, audit
