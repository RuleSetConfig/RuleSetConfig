import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from filter_domains import read_domain_rules


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MERGE = load("supplemental_domain_merge", "merge-filter.py")
VERIFY = load("supplemental_domain_verify", "verify-all.py")


class SupplementalDomainTests(unittest.TestCase):
    def test_source_preserves_exact_suffix_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "domains.list"
            path.write_text("# reviewed\n// comment\nExact.Example # host\nexact.example\n.ads.example\n")
            self.assertEqual(read_domain_rules(path), ({"ads.example"}, {"exact.example"}))

    def test_source_rejects_other_languages_and_invalid_hosts(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "domains.list"
            for entry in ("DOMAIN,example.com", "||example.com^", "*.example.com",
                          "https://example.com", ".192.0.2.1", "192.0.2.1",
                          "..example.com", "example.com.", "-bad.example", "localhost"):
                path.write_text(entry + "\n")
                with self.subTest(entry=entry), self.assertRaises(ValueError):
                    read_domain_rules(path)

    def test_build_retains_custom_hosts_and_prunes_covered_children(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            upstream = root / "upstream.txt"
            upstream.write_text("||ads.example^\n" +
                                "\n".join(f"||ad{i}.invalid^" for i in range(600)))
            supplement = root / "custom.list"
            supplement.write_text("exact.example\n.ads.example\nchild.ads.example\n")
            exclusions = root / "exclusions.list"
            exclusions.write_text("# empty fixture\n")
            output = root / "output"
            with patch.object(MERGE, "MIN_SUFFIX", 1), patch.object(MERGE, "MIN_EXACT", 0):
                MERGE.build(argparse.Namespace(adblock=[upstream], domain_rules=[supplement],
                                               domain_exclusions=exclusions, output_dir=output))
            parsed = VERIFY.parse_list(output / "REJECT-DOMAIN-SET.list")
            self.assertEqual(parsed["domain"], {"exact.example"})
            self.assertIn("ads.example", parsed["domain_suffix"])
            audit = json.loads((output / "filter-audit.json").read_text())
            self.assertEqual(audit["sources"]["custom.list"]["counts"],
                             {"domain": 2, "domain_suffix": 1})

    def test_source_only_policy_omits_base_hosts_without_migration_or_stale_pruning(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source").mkdir()
            maintained = root / "source/reject-domain-set.list"
            maintained.write_text(".data\n")
            upstream = []
            for name in ("a", "b"):
                path = root / name
                path.write_text("||ads.vendor.example^\n||a*.ads.vendor.example^\n")
                upstream.append(path)
            scope = root / "scope.json"
            scope.write_text(json.dumps({"schema": 1, "preserve_manual_supplements": True,
                "min_selected_domains": 1, "max_selected_domains": 10,
                "families": [{"id": "vendor", "category": "installed",
                              "roots": ["vendor.example"]}]}))
            selection = root / "selection.json"
            selection.write_text(json.dumps({"schema": 1, "target_rules": None,
                "minimum_support": 2, "source_preference": ["a", "b"],
                "category_preference": ["installed"], "selection_scope": "reviewed-brands",
                "respect_upstream_exceptions": True}))
            exclusions = root / "exclusions.list"
            exclusions.write_text("# none\n")
            output = root / "output"
            args = argparse.Namespace(adblock=upstream[:1], domain_only_adblock=upstream[1:],
                app_scope=scope, rule_selection=selection, domain_set_source=maintained,
                domain_exclusions=exclusions, output_dir=output)
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                    patch.object(MERGE, "MIN_EXACT", 0):
                self.assertEqual(MERGE.build(args), 0)
            self.assertEqual((output / "REJECT-DOMAIN-SET.list").read_text(), ".data\n")
            rules = (output / "REJECT-RULE-SET.list").read_text()
            self.assertNotIn("DOMAIN-SUFFIX,ads.vendor.example", rules)
            self.assertIn("DOMAIN-WILDCARD,a*.ads.vendor.example", rules)
            audit = json.loads((output / "filter-audit.json").read_text())["result"]
            self.assertEqual((audit["suffix"], audit["exact"]), (1, 0))
            self.assertEqual(audit["rule_selection"]["selected_rules"], 0)
            self.assertEqual(audit["domain_set_policy"]["omitted_base_suffix"], 1)
            self.assertEqual(VERIFY.verify(output / "REJECT-DOMAIN-SET.list",
                                           output / "REJECT-DOMAIN-SET.json"), 0)
            self.assertEqual(VERIFY.verify_filter_optimization(output), 0)

    def test_maintained_rule_source_replaces_all_upstream_patterns_and_additions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            upstream = root / "upstream.txt"
            upstream.write_text("||ads.vendor.example^\n||legacy*.vendor.example^\n")
            legacy = root / "legacy.list"
            legacy.write_text("DOMAIN-KEYWORD,removed-keyword\n")
            domains = root / "domains.list"
            domains.write_text(".data\n")
            requested = ROOT / "source/reject-rule-set.list"
            exclusions = root / "exclusions.list"
            exclusions.write_text("# none\n")
            output = root / "output"
            args = argparse.Namespace(adblock=[upstream], pattern_rules=[legacy],
                domain_set_source=domains, rule_set_source=requested,
                rule_selection=root / "unused-selection.json",
                domain_exclusions=exclusions, output_dir=output)
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                    patch.object(MERGE, "MIN_EXACT", 0):
                self.assertEqual(MERGE.build(args), 0)
            from filter_patterns import read_pattern_rules
            self.assertEqual(read_pattern_rules(output / "REJECT-RULE-SET.list"),
                             read_pattern_rules(requested))
            self.assertEqual((output / "REJECT-DOMAIN-SET.list").read_text(), ".data\n")
            self.assertEqual([line for line in (output / "REJECT-RULE-SET.list").read_text().splitlines()
                              if line.startswith("AND,")],
                             [line for line in requested.read_text().splitlines() if line.startswith("AND,")])
            result = json.loads((output / "filter-audit.json").read_text())["result"]
            self.assertIsNone(result["rule_selection"])
            self.assertEqual(result["partitions"]["REJECT-RULE-SET"],
                             len(read_pattern_rules(requested)))
            self.assertEqual(result["rule_set_policy"]["upstream_rule_imports"], "disabled")

    def test_source_only_verifier_rejects_added_or_changed_hostname_scopes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source").mkdir()
            (root / "source/reject-domain-set.list").write_text(".data\n")
            output = root / "REJECT-DOMAIN-SET.list"
            output.write_text(".data\n")
            self.assertEqual(VERIFY.verify_supplemental_domains(root), 0)
            for content in (".data\n.ads.example\n", ".other\n", "data\n", "# empty\n"):
                output.write_text(content)
                with self.subTest(content=content), self.assertRaises(SystemExit):
                    VERIFY.verify_supplemental_domains(root)

    def test_verifier_detects_lost_coverage_and_respects_labels_and_scopes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source").mkdir()
            source = root / "source/reject-domain-extra.list"
            output = root / "REJECT-DOMAIN-SET.list"
            source.write_text("host.example\n.ads.example\n")
            for content in ("host.example\nads.example\n",
                            ".nothost.example\n.ads.example\n",
                            "child.host.example\n.ads.example\n",
                            "host.example\n.child.ads.example\n"):
                output.write_text(content)
                with self.subTest(content=content), self.assertRaises(SystemExit):
                    VERIFY.verify_supplemental_domains(root)
            for content in ("host.example\n.ads.example\n", ".example\n"):
                output.write_text(content)
                self.assertEqual(VERIFY.verify_supplemental_domains(root), 0)
