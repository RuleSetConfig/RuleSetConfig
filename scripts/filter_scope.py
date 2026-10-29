"""Select existing upstream ad rules by reviewed application namespaces.

This module never creates a block for a brand root and never changes rule kind.
Manual supplements are merged later and are intentionally outside this selector.
"""
import hashlib
import json
from collections import Counter
from pathlib import Path
import re

ROOT_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")


class AppScope:
    def __init__(self, path):
        raw = Path(path).read_bytes()
        data = json.loads(raw)
        if (not isinstance(data, dict) or data.get("schema") != 1
                or data.get("preserve_manual_supplements") is not True):
            raise ValueError("application scope requires schema 1 and preserved manual supplements")
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.minimum = data.get("min_selected_domains")
        self.maximum = data.get("max_selected_domains")
        if (type(self.minimum) is not int or type(self.maximum) is not int
                or not 0 < self.minimum <= self.maximum):
            raise ValueError("invalid application-scope size limits")
        self.roots = {}
        self.families = set()
        self.categories = {}
        families = data.get("families")
        if not isinstance(families, list) or not families:
            raise ValueError("application scope needs explicit families")
        for family in families:
            if not isinstance(family, dict):
                raise ValueError("invalid application family")
            name = family.get("id")
            if not isinstance(name, str) or not name or name in self.families:
                raise ValueError("duplicate or invalid application family")
            self.families.add(name)
            self.categories[name] = family.get("category", "mainstream")
            if not isinstance(family.get("roots"), list) or not family["roots"]:
                raise ValueError("application family needs explicit namespace roots")
            for root in family["roots"]:
                if (not isinstance(root, str) or not ROOT_PATTERN.fullmatch(root)
                        or "." not in root or ".." in root
                        or any(not label or label.startswith("-") or label.endswith("-")
                               for label in root.split("."))):
                    raise ValueError("invalid application namespace root")
                if root in self.roots:
                    raise ValueError("duplicate application namespace root: " + root)
                self.roots[root] = name
        self.explicit = set()
        explicit = data.get("explicit_patterns", [])
        if not isinstance(explicit, list):
            raise ValueError("explicit application patterns must be a list")
        for item in explicit:
            if (not isinstance(item, list) or len(item) != 2
                    or item[0] not in {"domain_keyword", "domain_wildcard"}
                    or not isinstance(item[1], str) or not item[1]):
                raise ValueError("invalid explicit application pattern")
            self.explicit.add(tuple(item))

    def family(self, host):
        # Match whole labels only: evilqq.com and qq.com.example cannot qualify.
        parts = host.lower().split(".")
        for i in range(len(parts) - 1):
            name = self.roots.get(".".join(parts[i:]))
            if name:
                return name
        return None

    def select(self, suffix, exact, patterns):
        counts = Counter()
        def keep_host(host):
            family = self.family(host)
            if family:
                counts[family] += 1
            return bool(family)
        kept_suffix = {host for host in suffix if keep_host(host)}
        kept_exact = {host for host in exact if keep_host(host)}
        kept_patterns = set()
        for kind, value in patterns:
            if kind == "ip_cidr":
                kept_patterns.add((kind, value))
                continue
            family = self.family(value) if kind in {"domain_keyword", "domain_wildcard"} else None
            if (kind, value) in self.explicit:
                family = family or "explicit-pattern"
            if family:
                kept_patterns.add((kind, value))
                counts[family] += 1
        before = {"suffix": len(suffix), "exact": len(exact), "patterns": len(patterns)}
        after = {"suffix": len(kept_suffix), "exact": len(kept_exact), "patterns": len(kept_patterns)}
        audit = {"before": before, "selected": after,
                 "removed": {key: before[key] - after[key] for key in before},
                 "families": dict(sorted(counts.items()))}
        return kept_suffix, kept_exact, kept_patterns, audit

    def identity(self):
        return {"schema": 1, "policy_sha256": self.sha256,
                "families": sorted(self.families), "namespace_roots": len(self.roots),
                "manual_supplements": "preserved", "frequency_evidence": "not-measured"}
