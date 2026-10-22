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
from filter_patterns import read_pattern_rules


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MERGE = load("supplemental_pattern_merge", "merge-filter.py")
VERIFY = load("supplemental_pattern_verify", "verify-all.py")


class SupplementalPatternTests(unittest.TestCase):
    def test_reader_preserves_keyword_scope_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "patterns.list"
            path.write_text("# reviewed\n// comment\n"
                            "DOMAIN-KEYWORD,-ad-sign.ByteImg.com\n"
                            "DOMAIN-KEYWORD,-ad-sign.byteimg.com\n"
                            "DOMAIN-WILDCARD,*.ads.example\n")
            self.assertEqual(read_pattern_rules(path), {
                ("domain_keyword", "-ad-sign.byteimg.com"),
                ("domain_wildcard", "*.ads.example")})

    def test_reader_rejects_empty_sources_other_languages_and_options(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "patterns.list"
            for entry in ("# empty", "DOMAIN,ads.example", "||ads.example^",
                          "IP-CIDR,192.0.2.1/32", "DOMAIN-KEYWORD,",
                          "DOMAIN-KEYWORD,ads,REJECT", "DOMAIN-KEYWORD,ads,no-resolve",
                          "DOMAIN-KEYWORD,*ads*", "DOMAIN-KEYWORD,https://ads.example",
                          "DOMAIN-WILDCARD,ads.example/path"):
                path.write_text(entry + "\n")
                with self.subTest(entry=entry), self.assertRaises(ValueError):
                    read_pattern_rules(path)

    def test_builder_retains_supplement_and_leaves_other_partitions_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            upstream = root / "upstream.txt"
            upstream.write_text("||ads.example^\ntracker.example\n||192.0.2.1^\n")
            supplement = root / "custom.list"
            supplement.write_text("DOMAIN-KEYWORD,-ad-sign.byteimg.com\n"
                                  "DOMAIN-WILDCARD,*.ads.example\n")
            old, new = root / "old", root / "new"
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), patch.object(MERGE, "MIN_EXACT", 1):
                MERGE.build(argparse.Namespace(adblock=[upstream], pattern_rules=[], output_dir=old))
                MERGE.build(argparse.Namespace(adblock=[upstream], pattern_rules=[supplement], output_dir=new))
            for name in ("REJECT-DOMAIN-SET", "REJECT-IP-SET"):
                for extension in (".list", ".json"):
                    self.assertEqual((old / (name + extension)).read_bytes(),
                                     (new / (name + extension)).read_bytes())
            output = new / "REJECT-RULE-SET.list"
            self.assertIn("DOMAIN-KEYWORD,-ad-sign.byteimg.com\n", output.read_text())
            self.assertNotIn("DOMAIN-WILDCARD,*.ads.example", output.read_text())
            self.assertEqual(VERIFY.verify(output, new / "REJECT-RULE-SET.json"), 0)
            audit = json.loads((new / "filter-audit.json").read_text())
            self.assertEqual(audit["sources"]["custom.list"]["counts"],
                             {"domain_keyword": 1, "domain_wildcard": 1})

    def test_verifier_detects_missing_patterns_and_accepts_parent_covered_wildcard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source").mkdir()
            source = root / "source/reject-rule-extra.list"
            source.write_text("DOMAIN-KEYWORD,-ad-sign.byteimg.com\n"
                              "DOMAIN-WILDCARD,*.ads.example\n")
            (root / "REJECT-DOMAIN-SET.list").write_text(".ads.example\n")
            output = root / "REJECT-RULE-SET.list"
            output.write_text("DOMAIN-KEYWORD,unrelated\n")
            with self.assertRaises(SystemExit):
                VERIFY.verify_supplemental_patterns(root)
            output.write_text("DOMAIN-KEYWORD,-ad-sign.byteimg.com\n")
            self.assertEqual(VERIFY.verify_supplemental_patterns(root), 0)
            (root / "REJECT-DOMAIN-SET.list").write_text(".child.ads.example\n")
            with self.assertRaises(SystemExit):
                VERIFY.verify_supplemental_patterns(root)
            output.write_text("DOMAIN-KEYWORD,-ad-sign.byteimg.com\n"
                              "DOMAIN-WILDCARD,*.ads.example\n")
            self.assertEqual(VERIFY.verify_supplemental_patterns(root), 0)
