"""Enforce reviewed routing brands and the explicitly maintained rejection rules."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

SOURCE = "source/brand-scope.json"
CODE = "scripts/brand_scope.py"
ALLOWED = {"DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "AND"}


class BrandScope:
    def __init__(self, root):
        self.root = Path(root)
        raw = (self.root / SOURCE).read_bytes()
        data = json.loads(raw)
        if data.get("schema") != 1 or data.get("allowed_types") != sorted(ALLOWED):
            raise ValueError("invalid reviewed brand policy")
        self.families = data["families"]
        self.keywords = data["routing_keywords"]
        self.applications = data["applications"]
        if (len(self.families) != 73 or len(self.applications) != 35
                or len({a["bundle_identifier"] for a in self.applications}) != 35):
            raise ValueError("reviewed inventory must contain 73 groups and 35 apps")
        words = self.keywords["proxy"] + self.keywords["direct"]
        if (not self.keywords["proxy"] or len(self.keywords["direct"]) != 14
                or len(set(words)) != len(words)
                or any(not re.fullmatch(r"[a-z0-9.-]+", w)
                       or len(re.findall("[a-z]", w)) < 5 for w in words)):
            raise ValueError("reviewed inventory requires distinct routing keywords with at least five letters")
        review = data.get("proxy_keyword_review")
        if (not isinstance(review, dict) or review.get("schema") != 1
                or review.get("minimum_ascii_letters") != 5
                or {row["keyword"] for row in review.get("records", [])} != set(self.keywords["proxy"])
                or any(not row.get("evidence") for row in review["records"])):
            raise ValueError("proxy keywords require their maintained source review")
        self.words = tuple(sorted(words, key=lambda w: (-len(w), w)))
        self.roots, self.exact = {}, {}
        for name, family in sorted(self.families.items()):
            for field, index in (("suffix_roots", self.roots), ("exact_hosts", self.exact)):
                for host in family[field]:
                    if not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+", host):
                        raise ValueError("invalid reviewed namespace")
                    index.setdefault(host, name)
        self.pattern_membership = data["reviewed_pattern_keywords"]
        if any(owner not in self.families for owner in self.pattern_membership.values()):
            raise ValueError("pattern keyword owner is outside reviewed groups")
        self.and_rules = {tuple(words) for words in data["preserved_and_keywords"]}
        if self.and_rules != {("ads", "zijieapi.com"), ("fqnovel", "misc")}:
            raise ValueError("both original AND conditions must remain intact")
        self.sha256 = hashlib.sha256(raw).hexdigest()

    def family(self, host, *, suffix=False):
        host = host.lower()
        if not suffix and host in self.exact:
            return self.exact[host]
        parts = host.split(".")
        for i in range(len(parts) - 1):
            if (name := self.roots.get(".".join(parts[i:]))) is not None:
                return name
        # An exact shared-service record never authorises its descendants or a suffix,
        # even when a broad, separately reviewed routing keyword appears in the name.
        if any(".".join(parts[i:]) in self.exact for i in range(len(parts) - 1)):
            return None
        return next(("keyword:" + w for w in self.words if w in host), None)

    def allows(self, kind, value):
        if kind == "logical_and":
            return tuple(value) in self.and_rules
        if kind == "domain_keyword":
            return (len(re.findall("[a-z]", value)) >= 5
                    and bool(value in self.words or value in self.pattern_membership
                             or self.family(value, suffix=True)))
        if kind == "domain_suffix":
            return bool(self.family(value, suffix=True))
        if kind in {"domain", "domain_wildcard"}:
            return bool(self.family(value))
        return False

    def filter(self, rules):
        return {(k, v) for k, v in rules if self.allows(k, v)}

    def identity(self):
        return {"policy_sha256": self.sha256, "reviewed_groups": 73,
                "installed_applications": 35, "routing_keywords": len(self.words),
                "allowed_types": sorted(ALLOWED), "exact_hosts": "literal DOMAIN-WILDCARD",
                "preserved_and_conditions": 2}

    def verify_lists(self, root):
        """Check published syntax and membership, not merely the source document."""
        from filter_optimizer import read_optional_patterns
        from scope_compaction import expand_text, records
        counts = {}
        for policy in ("DIRECT", "PROXY", "REJECT"):
            path = Path(root) / (policy + "-RULE-SET.list")
            if not path.exists():
                continue
            raw = path.read_text()
            for line in records(raw):
                if line.split(",", 1)[0] not in ALLOWED:
                    raise ValueError("unapproved published type: " + line)
            rows = records(expand_text(raw))
            maintained = Path(root) / "source/reject-rule-set.list"
            if policy == "REJECT" and maintained.is_file():
                from filter_patterns import pattern_source_lines
                expected = pattern_source_lines(maintained)
                if set(rows) != expected or len(rows) != len(expected):
                    raise ValueError("rejection rules differ from their maintained source")
                counts[policy] = dict(sorted(Counter(l.split(",", 1)[0] for l in records(raw)).items()))
                continue
            for line in rows:
                kind, value = line.split(",", 1)
                if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
                    field = "domain" if kind == "DOMAIN" else "domain_suffix"
                    if not self.allows(field, value):
                        raise ValueError("out-of-scope hostname: " + line)
            patterns = read_optional_patterns(path)
            if any(not self.allows(k, v) for k, v in patterns):
                raise ValueError("out-of-scope pattern in " + path.name)
            if policy != "REJECT":
                actual = sorted(v for k, v in patterns if k == "domain_keyword")
                if actual != sorted(self.keywords[policy.lower()]):
                    raise ValueError("the original routing keywords changed")
            elif {tuple(v) for k, v in patterns if k == "logical_and"} != self.and_rules:
                raise ValueError("original AND condition missing")
            counts[policy] = dict(sorted(Counter(l.split(",", 1)[0] for l in records(raw)).items()))
        return counts


def optional(root):
    return BrandScope(root) if (Path(root) / SOURCE).is_file() else None
