"""Check scope, exclusion, deterministic selection and publication limits."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from filter_selection import RuleSelection, selection_digest
from filter_scope import AppScope
from filter_optimizer import read_optional_patterns
from filter_patterns import read_pattern_rules

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

MERGE = load("selection_merge", "merge-filter.py")
VERIFY = load("selection_verify", "verify-all.py")


class BoundedSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def policy(self, target=1, **changes):
        data = {"schema": 1, "target_rules": target, "minimum_support": 2,
                "source_preference": ["a.txt", "b.txt", "c.txt"],
                "category_preference": ["requested", "installed", "shared-platform", "mainstream"],
                "respect_upstream_exceptions": True}
        data.update(changes)
        path = self.root / "policy.json"
        path.write_text(json.dumps(data))
        return RuleSelection(path)

    def sources(self, suffix=(), exact=(), es=(), ee=()):
        return {name: (set(suffix), set(exact), set(es), set(ee))
                for name in ("a.txt", "b.txt", "c.txt")}

    def select(self, sources, target=1, suffix=(), exact=(), patterns=(), exclusions=(), scope=None):
        return self.policy(target).select(sources, set(suffix), set(exact), set(patterns),
                                          set(exclusions), scope)

    def test_agreement_is_scope_specific_and_never_promotes_hosts(self):
        src = self.sources(exact={"ads.example"})
        src["a.txt"][0].add("ads.example")
        rules, audit, _ = self.select(src)
        self.assertEqual(rules, {("domain", "ads.example")})
        self.assertEqual(audit["support_histogram"], {"3": 1})
        self.assertGreater(audit["rejected"]["insufficient-scope-support"], 0)

    def test_two_exact_sources_cannot_support_an_entire_suffix(self):
        src = self.sources()
        src["a.txt"][0].add("ads.example")
        for name in ("b.txt", "c.txt"):
            src[name][1].add("ads.example")
        rules, _, _ = self.select(src)
        self.assertEqual(rules, {("domain", "ads.example")})

    def test_parent_suffix_support_observes_label_boundaries(self):
        src = self.sources()
        src["a.txt"][0].update({"ads.example", "notads.example"})
        src["b.txt"][0].add("child.ads.example")
        rules, _, _ = self.select(src)
        self.assertEqual(rules, {("domain_suffix", "child.ads.example")})

    def test_exceptions_prevent_same_host_ancestors_and_descendants(self):
        src = self.sources(suffix={"safe.example", "child.safe.example", "parent.example",
                                   "good.example", "x.exact.example"},
                           exact={"exact.example"}, es={"safe.example"},
                           ee={"login.parent.example", "exact.example"})
        rules, audit, _ = self.select(src, target=2)
        self.assertEqual(rules, {("domain_suffix", "good.example"),
                                 ("domain_suffix", "x.exact.example")})
        self.assertGreater(audit["rejected"]["upstream-exception-or-reviewed-exclusion"], 0)

    def test_reviewed_exclusion_cannot_be_overridden_by_an_ancestor(self):
        src = self.sources(suffix={"example", "cdn.qq.com", "beacon.cdn.qq.com", "safe.invalid"})
        rules, _, _ = self.select(src, exclusions={"beacon.cdn.qq.com"})
        self.assertEqual(rules, {("domain_suffix", "example")})

    def test_existing_domains_are_neither_repeated_nor_subsumed(self):
        src = self.sources(suffix={"parent.example", "child.parent.example",
                                   "existing.example", "new.example"},
                           exact={"exact.example", "child.existing.example"})
        rules, _, _ = self.select(src, suffix={"existing.example"},
                                  exact={"exact.example", "child.parent.example"})
        self.assertEqual(rules, {("domain_suffix", "new.example")})

    def test_patterns_are_preserved_and_do_not_consume_duplicate_slots(self):
        src = self.sources(suffix={"applog.example", "ads.example", "new.example"})
        patterns = {("domain_keyword", "applog"), ("domain_wildcard", "*.ads.example")}
        rules, audit, _ = self.select(src, target=3, patterns=patterns)
        self.assertEqual(rules, {("domain_suffix", "new.example")})
        self.assertEqual(audit["preserved_rules"], 2)

    def test_parent_and_child_do_not_pad_the_budget(self):
        src = self.sources(suffix={"ads.example", "child.ads.example"}, exact={"ads.example"})
        rules, _, _ = self.select(src)
        self.assertEqual(rules, {("domain_suffix", "ads.example")})
        with self.assertRaisesRegex(ValueError, "refusing padding"):
            self.select(src, target=2)

    def test_requested_apps_and_source_agreement_precede_alphabetical_ties(self):
        data = {"schema": 1, "preserve_manual_supplements": True,
                "min_selected_domains": 1, "max_selected_domains": 10,
                "families": [{"id": "reading", "category": "requested", "roots": ["fqnovel.com"]}]}
        path = self.root / "scope.json"
        path.write_text(json.dumps(data))
        src = self.sources(suffix={"a.example"})
        for name in ("a.txt", "b.txt"):
            src[name][0].add("mon.fqnovel.com")
        rules, _, _ = self.select(src, scope=AppScope(path))
        self.assertEqual(rules, {("domain_suffix", "mon.fqnovel.com")})

    def test_iteration_order_does_not_change_choices_or_audit(self):
        src = self.sources(suffix={"a.example", "b.example", "c.example"})
        policy = self.policy(2)
        first = policy.select(src, set(), set(), set())
        second = policy.select(dict(reversed(list(src.items()))), set(), set(), set())
        self.assertEqual(first, second)
        self.assertEqual(first[1]["selection_sha256"], selection_digest(first[0]))

    def test_insufficient_candidates_or_preserved_overflow_fail(self):
        src = self.sources(suffix={"a.example"})
        with self.assertRaisesRegex(ValueError, "refusing padding"):
            self.select(src, target=2)
        with self.assertRaisesRegex(ValueError, "exceed"):
            self.select(src, patterns={("domain_keyword", "ads"), ("protocol", "stun")})
        src.pop("c.txt")
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.select(src)

    def test_invalid_or_unsafe_policy_is_rejected(self):
        for changes in ({"target_rules": True}, {"target_rules": 0}, {"minimum_support": 1},
                        {"minimum_support": 4}, {"respect_upstream_exceptions": False},
                        {"source_preference": ["a", "a"]}, {"category_preference": ["a", "a"]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.policy(**changes)

    def test_new_domains_roundtrip_and_pattern_source_stays_strict(self):
        output = self.root / "build"
        additions = {("domain_suffix", "ads.example"), ("domain", "exact.example")}
        counts = MERGE.write_filter_partitions({"base.example"}, set(),
                    {("domain_keyword", "applog"), ("protocol", "stun")}, output, additions)
        self.assertEqual(counts["REJECT-RULE-SET"], 4)
        self.assertEqual(read_optional_patterns(output / "REJECT-RULE-SET.list"),
                         {("domain_keyword", "applog"), ("protocol", "stun")})
        with self.assertRaises(ValueError):
            read_pattern_rules(output / "REJECT-RULE-SET.list")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(VERIFY.verify(output / "REJECT-RULE-SET.list",
                                            output / "REJECT-RULE-SET.json"), 0)
            self.assertEqual(VERIFY.verify_filter_parent_pruning(output), 0)
            self.assertEqual(VERIFY.verify_filter_optimization(output), 0)

    def test_cross_partition_duplicate_and_nested_rule_hosts_are_rejected(self):
        domain = self.root / "REJECT-DOMAIN-SET.list"
        domain.write_text(".keep.example\n")
        rule = self.root / "REJECT-RULE-SET.list"
        for text in ("DOMAIN-SUFFIX,keep.example\n",
                     "DOMAIN-SUFFIX,child.example\nDOMAIN,host.child.example\n",
                     "DOMAIN-SUFFIX,example\nDOMAIN-SUFFIX,child.example\n"):
            rule.write_text(text)
            with self.subTest(text=text), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                VERIFY.verify_filter_parent_pruning(self.root)

    def test_manifest_cannot_hide_extra_duplicate_rows_or_changed_hosts(self):
        policy = self.policy()
        additions, audit, _ = policy.select(self.sources(suffix={"ads.example"}), set(), set(), set())
        source = self.root / "source"
        source.mkdir()
        (self.root / "policy.json").rename(source / "reject-rule-selection.json")
        metadata = self.root / "metadata"
        metadata.mkdir()
        manifest = metadata / "filter.json"
        document = {"schema": 1, "name": "filter", "sources": {}, "outputs": {},
                    "filter": {"surge_only": [], "result": {"surge_only": [],
                                                           "rule_selection": audit}}}
        manifest.write_text(json.dumps(document))
        rules = self.root / "REJECT-RULE-SET.list"
        rules.write_text("DOMAIN-SUFFIX,ads.example\n")
        with redirect_stdout(io.StringIO()):
            VERIFY.verify_manifests(self.root)
        for text in ("DOMAIN-SUFFIX,ads.example\nDOMAIN-SUFFIX,ads.example\n",
                     "DOMAIN-SUFFIX,other.example\n", "# empty\n"):
            rules.write_text(text)
            with self.subTest(text=text), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                VERIFY.verify_manifests(self.root)

    def test_full_builder_keeps_target_and_only_primary_ips(self):
        policy = self.policy(target=3)
        paths = []
        for name in policy.sources:
            path = self.root / name
            path.write_text("||ads.qq.com^\n||a.example^\n||b.example^\n||192.0.2.1^\n")
            paths.append(path)
        scope_path = self.root / "scope.json"
        scope_path.write_text(json.dumps({"schema": 1, "preserve_manual_supplements": True,
                "min_selected_domains": 1, "max_selected_domains": 10,
                "families": [{"id": "tencent", "category": "installed", "roots": ["qq.com"]}]}))
        supplements = self.root / "extra.list"
        supplements.write_text("DOMAIN-KEYWORD,applog\n")
        exclusions = self.root / "exclusions.list"
        exclusions.write_text("# none\n")
        output = self.root / "output"
        import argparse
        args = argparse.Namespace(adblock=paths[:1], domain_only_adblock=paths[1:],
                pattern_rules=[supplements], app_scope=scope_path,
                rule_selection=self.root / "policy.json", domain_exclusions=exclusions,
                output_dir=output)
        with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                patch.object(MERGE, "MIN_EXACT", 0), redirect_stdout(io.StringIO()):
            self.assertEqual(MERGE.build(args), 0)
            result = json.loads((output / "filter-audit.json").read_text())["result"]
            self.assertEqual(result["partitions"]["REJECT-RULE-SET"], 3)
            self.assertEqual(VERIFY.parse_list(output / "REJECT-IP-SET.list")["ip_cidr"],
                             {"192.0.2.1/32"})
            self.assertEqual(VERIFY.verify_filter_optimization(output), 0)


if __name__ == "__main__":
    unittest.main()
