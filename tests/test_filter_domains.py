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
