"""Keep maintained rejection suffixes distinct from substring keywords."""

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

SPEC = importlib.util.spec_from_file_location("maintained_suffix_merge", ROOT / "scripts/merge-filter.py")
MERGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE)


class MaintainedSuffixTests(unittest.TestCase):
    def test_invalid_suffixes_and_exact_rules_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "rules.list"
            for row in ("DOMAIN-SUFFIX,qq..com", "DOMAIN-SUFFIX,.qq.com",
                        "DOMAIN-SUFFIX,192.0.2.1", "DOMAIN-SUFFIX,qq.com,REJECT",
                        "DOMAIN-SUFFIX,qq.com/path", "DOMAIN,qq.com"):
                source.write_text(row + "\n")
                with self.subTest(row=row), self.assertRaises(ValueError):
                    read_pattern_rules(source)

    def test_builder_keeps_suffixes_in_rule_companion_and_enforces_exclusions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "upstream.txt"
            upstream.write_text("||ads.example.com^\n")
            domains = root / "domains.list"
            domains.write_text(".data\n")
            source = root / "rules.list"
            source.write_text("DOMAIN-SUFFIX,e.qq.com\nDOMAIN-WILDCARD,host.example.com\n")
            exclusions = root / "exclusions.list"
            exclusions.write_text("beacon.cdn.qq.com\n")
            output = root / "output"
            args = argparse.Namespace(adblock=[upstream], domain_set_source=domains,
                                      rule_set_source=source, domain_exclusions=exclusions,
                                      output_dir=output)
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                    patch.object(MERGE, "MIN_EXACT", 0):
                self.assertEqual(MERGE.build(args), 0)
                self.assertEqual((output / "REJECT-DOMAIN-SET.list").read_text(), ".data\n")
                compiled = json.loads((output / "REJECT-RULE-SET.json").read_text())
                self.assertEqual(compiled["rules"], [{"domain": ["host.example.com"]},
                                                      {"domain_suffix": ["e.qq.com"]}])
                published = (output / "REJECT-RULE-SET.list").read_text()
                self.assertIn("DOMAIN-WILDCARD,host.example.com\n", published)
                self.assertNotIn("\nDOMAIN,", published)
                self.assertEqual(read_pattern_rules(output / "REJECT-RULE-SET.list"),
                                 read_pattern_rules(source))
                for row in ("DOMAIN-SUFFIX,beacon.cdn.qq.com", "DOMAIN-SUFFIX,qq.com",
                            "DOMAIN-KEYWORD,beacon.cdn", "DOMAIN-WILDCARD,beacon.cdn.qq.com"):
                    source.write_text(row + "\n")
                    with self.subTest(row=row), self.assertRaises(SystemExit):
                        MERGE.build(args)


if __name__ == "__main__":
    unittest.main()
