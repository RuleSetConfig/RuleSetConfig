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
        self.installed_snapshot = data.get("installed_snapshot")
        if self.installed_snapshot is not None:
            snapshot = self.installed_snapshot
            if (not isinstance(snapshot, dict) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(snapshot.get("date", "")))
                    or not isinstance(snapshot.get("method"), str)):
                raise ValueError("invalid installed application snapshot")
            bundles, installed = set(), 0
            for family in families:
                if family.get("category") != "installed":
                    continue
                installed += 1
                apps = family.get("applications")
                if not isinstance(apps, list) or not apps:
                    raise ValueError("installed family requires observed applications")
                for app in apps:
                    if (not isinstance(app, dict) or not isinstance(app.get("name"), str)
                            or not app["name"] or not re.fullmatch(r"[A-Za-z0-9_.-]+", str(app.get("bundle_identifier", "")))
                            or "." not in app["bundle_identifier"] or app["bundle_identifier"] in bundles):
                        raise ValueError("invalid or duplicate observed application bundle")
                    bundles.add(app["bundle_identifier"])
            if snapshot.get("application_count") != len(bundles) or snapshot.get("family_count") != installed:
                raise ValueError("installed application snapshot count differs")
        self.traffic_families, self.priority_roots, self.priority_exact = set(), {}, {}
        self.functional_exact_hosts, self.traffic_identity = set(), None
        traffic_source = data.get("traffic_priority_source")
        if traffic_source:
            if traffic_source != "source/traffic-brand-priority.json":
                raise ValueError("unsupported traffic priority source")
            traffic_raw = (Path(path).resolve().parents[1] / traffic_source).read_bytes()
            traffic = json.loads(traffic_raw)
            if not isinstance(traffic, dict) or traffic.get("schema") != 1 or not isinstance(traffic.get("families"), list):
                raise ValueError("invalid traffic brand priorities")
            def valid_host(host):
                return (isinstance(host, str) and ROOT_PATTERN.fullmatch(host) and "." in host
                        and all(label and not label.startswith("-") and not label.endswith("-")
                                for label in host.split(".")))
            for item in traffic["families"]:
                name = item.get("id") if isinstance(item, dict) else None
                if not isinstance(name, str) or not name or name in self.traffic_families:
                    raise ValueError("duplicate or invalid traffic brand")
                self.traffic_families.add(name)
                self.categories.setdefault(name, "traffic-observed")
                self.families.add(name)
                for field, target in [("suffix_roots", self.priority_roots), ("exact_hosts", self.priority_exact)]:
                    values = item.get(field)
                    if not isinstance(values, list) or any(not valid_host(h) for h in values):
                        raise ValueError("invalid traffic brand namespace")
                    for host in values:
                        owner = self.roots.get(host) or target.get(host)
                        if owner is not None and owner != name:
                            raise ValueError("conflicting traffic brand namespace")
                        if host in target:
                            raise ValueError("duplicate traffic brand namespace")
                        target[host] = name
                if name not in self.roots.values() and not item["suffix_roots"] and not item["exact_hosts"]:
                    raise ValueError("new traffic brand requires reviewed namespaces")
            functional = traffic.get("functional_exact_hosts", [])
            if not isinstance(functional, list) or any(not valid_host(h) for h in functional):
                raise ValueError("invalid functional service host")
            self.functional_exact_hosts = set(functional)
            self.traffic_identity = {
                "policy_sha256": hashlib.sha256(traffic_raw).hexdigest(),
                "families": sorted(self.traffic_families),
                "suffix_namespaces": len(self.priority_roots), "exact_hosts": len(self.priority_exact),
                "functional_exact_hosts": sorted(self.functional_exact_hosts),
                "raw_records_published": False,
            }
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

    def base_family(self, host):
        # Match whole labels only: evilqq.com and qq.com.example cannot qualify.
        parts = host.lower().split(".")
        for i in range(len(parts) - 1):
            name = self.roots.get(".".join(parts[i:]))
            if name:
                return name
        return None

    def family(self, host):
        host = host.lower()
        if host in self.priority_exact:
            return self.priority_exact[host]
        parts = host.split(".")
        for i in range(len(parts) - 1):
            tail = ".".join(parts[i:])
            family = self.roots.get(tail) or self.priority_roots.get(tail)
            if family:
                return family
        return None

    def category(self, family):
        category = self.categories.get(family)
        if category != "installed" and family in self.traffic_families:
            return "traffic-observed"
        return category

    def select(self, suffix, exact, patterns):
        counts = Counter()
        def keep_host(host):
            family = self.base_family(host)
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
            family = self.base_family(value) if kind in {"domain_keyword", "domain_wildcard"} else None
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
                "manual_supplements": "preserved", "frequency_evidence": "not-measured",
                **({"installed_snapshot": self.installed_snapshot} if self.installed_snapshot else {}),
                **({"traffic_priority": self.traffic_identity} if self.traffic_identity else {})}
