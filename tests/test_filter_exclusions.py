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
from filter_exclusions import read_domain_exclusions, remove_domain_exclusions


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MERGE = load("exclusion_merge", "merge-filter.py")
VERIFY = load("exclusion_verify", "verify-all.py")
SDK = "beacon.cdn.qq.com"


class FilterExclusionTests(unittest.TestCase):
    def test_exclusion_source_accepts_only_bare_hostnames(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "exclusions.list"
            path.write_text("# reviewed\nBEACON.CDN.QQ.COM # SDK\n")
            self.assertEqual(read_domain_exclusions(path), {SDK})
            for value in ("@@||beacon.cdn.qq.com^", ".beacon.cdn.qq.com", "*.qq.com", "https://qq.com", "0.0.0.0"):
                path.write_text(value + "\n")
                with self.subTest(value=value), self.assertRaises(ValueError):
                    read_domain_exclusions(path)

    def test_removal_preserves_other_telemetry_and_label_boundaries(self):
        suffix, exact, audit = remove_domain_exclusions(
            {SDK, "otheve.beacon.qq.com", "child." + SDK, SDK + ".evil.net"},
            {SDK, "not" + SDK}, {SDK})
        self.assertEqual(suffix, {"otheve.beacon.qq.com", "child." + SDK, SDK + ".evil.net"})
        self.assertEqual(exact, {"not" + SDK})
        self.assertEqual(audit["removed_suffix"], [SDK])
        self.assertEqual(audit["removed_exact"], [SDK])

    def test_broader_parent_or_pattern_cannot_silently_reblock_exclusion(self):
        cases = [({"cdn.qq.com"}, set()),
                 (set(), {("domain_keyword", "beacon")}),
                 (set(), {("domain_wildcard", "*.cdn.qq.com")})]
        for suffix, patterns in cases:
            with self.subTest(suffix=suffix, patterns=patterns), self.assertRaises(ValueError):
                remove_domain_exclusions(suffix, set(), {SDK}, patterns)

    def test_build_uses_reviewed_exclusion_without_applying_upstream_exceptions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "upstream.txt"
            source.write_text("||beacon.cdn.qq.com^\n0.0.0.0 beacon.cdn.qq.com\n"
                              "||otheve.beacon.qq.com^\n@@||otheve.beacon.qq.com^\n" +
                              "\n".join(f"||ad{i}.invalid^" for i in range(600)))
            exclusions = root / "exclusions.list"
            exclusions.write_text(SDK + "\n")
            output = root / "output"
            with patch.object(MERGE, "MIN_SUFFIX", 1), patch.object(MERGE, "MIN_EXACT", 0):
                MERGE.build(argparse.Namespace(adblock=[source], domain_exclusions=exclusions,
                                               output_dir=output))
            lines = (output / "REJECT-DOMAIN-SET.list").read_text().splitlines()
            self.assertNotIn("." + SDK, lines)
            self.assertNotIn(SDK, lines)
            self.assertIn(".otheve.beacon.qq.com", lines)
            audit = json.loads((output / "filter-audit.json").read_text())
            self.assertEqual(audit["exception_policy"], "audit-only-block-wins")
            self.assertEqual(audit["result"]["domain_exclusions"]["removed_suffix"], [SDK])
            self.assertEqual(VERIFY.verify_filter_parent_pruning(output), 0)

    def test_verifier_detects_reintroduced_domain_and_pattern_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source").mkdir()
            (root / "source/reject-domain-exclusions.list").write_text(SDK + "\n")
            domain = root / "REJECT-DOMAIN-SET.list"
            patterns = root / "REJECT-RULE-SET.list"
            for entry in (SDK, "." + SDK, ".cdn.qq.com"):
                domain.write_text(entry + "\n")
                patterns.write_text("# empty\n")
                with self.subTest(entry=entry), self.assertRaises(SystemExit):
                    VERIFY.verify_filter_parent_pruning(root)
            domain.write_text(".otheve.beacon.qq.com\n")
            for entry in ("DOMAIN-KEYWORD,beacon", "DOMAIN-WILDCARD,*.cdn.qq.com"):
                patterns.write_text(entry + "\n")
                with self.subTest(entry=entry), self.assertRaises(SystemExit):
                    VERIFY.verify_filter_parent_pruning(root)
