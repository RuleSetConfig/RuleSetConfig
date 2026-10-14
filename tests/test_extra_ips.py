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
from filter_ips import collapse_ip_rules, parse_ip_rule, read_ip_rules


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MERGE = load("extra_ip_merge", "merge-filter.py")
VERIFY = load("extra_ip_verify", "verify-all.py")


class ExtraIpTests(unittest.TestCase):
    def test_parser_rejects_domains_options_family_mismatch_and_host_bits(self):
        for line in ("DOMAIN,ads.example", "IP-CIDR,192.0.2.0/24,REJECT",
                     "IP-CIDR6,192.0.2.0/24", "IP-CIDR,2001:db8::/32",
                     "IP-CIDR,192.0.2.1/24", "IP-CIDR,192.0.2.1/32,no-resolve"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_ip_rule(line)

    def test_reader_rejects_empty_source_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "extra.list"
            path.write_text("# empty\n")
            with self.assertRaises(ValueError):
                read_ip_rules(path)
            path.write_text("IP-CIDR,192.0.2.1/32\n" * 2)
            self.assertEqual(read_ip_rules(path), {("ip_cidr", "192.0.2.1/32")})

    def test_collapse_deduplicates_ipv4_and_ipv6_without_widening(self):
        rules = {("ip_cidr", "192.0.2.0/31"),
                 ("ip_cidr", "192.0.2.1/32"),
                 ("ip_cidr", "192.0.2.2/32"),
                 ("ip_cidr", "192.0.2.3/32"),
                 ("ip_cidr", "2001:db8::1/128")}
        self.assertEqual(collapse_ip_rules(rules), {
            ("ip_cidr", "192.0.2.0/30"), ("ip_cidr", "2001:db8::1/128")})

    def test_build_keeps_extra_ips_without_changing_domain_or_pattern_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream = root / "ads.txt"
            upstream.write_text("||ads.example^\ntracker.example\n||192.0.2.0^\n")
            extra = root / "extra.list"
            extra.write_text("IP-CIDR,192.0.2.1/32\nIP-CIDR,192.0.2.2/32\n"
                             "IP-CIDR,192.0.2.3/32\nIP-CIDR6,2001:db8::1/128\n")
            old, new = root / "old", root / "new"
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), patch.object(MERGE, "MIN_EXACT", 1):
                MERGE.build(argparse.Namespace(adblock=[str(upstream)], ip_rules=[], output_dir=old))
                MERGE.build(argparse.Namespace(adblock=[str(upstream)], ip_rules=[str(extra)], output_dir=new))
            for name in ("REJECT-DOMAIN-SET", "REJECT-RULE-SET"):
                for suffix in (".list", ".json"):
                    self.assertEqual((old / (name + suffix)).read_bytes(),
                                     (new / (name + suffix)).read_bytes())
            text = (new / "REJECT-IP-SET.list").read_text()
            self.assertIn("IP-CIDR,192.0.2.0/30\n", text)
            self.assertIn("IP-CIDR6,2001:db8::1/128\n", text)
            self.assertNotIn("no-resolve", text)
            self.assertEqual(VERIFY.verify(new / "REJECT-IP-SET.list", new / "REJECT-IP-SET.json"), 0)
            audit = json.loads((new / "filter-audit.json").read_text())
            self.assertEqual(audit["sources"]["extra.list"]["counts"]["ip_cidr"], 4)

    def test_verifier_rejects_lost_coverage_and_accepts_covering_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "source/reject-ip-extra.list").write_text("IP-CIDR,192.0.2.1/32\n")
            output = root / "REJECT-IP-SET.list"
            output.write_text("IP-CIDR,192.0.2.2/32\n")
            with self.assertRaises(SystemExit):
                VERIFY.verify_supplemental_ips(root)
            output.write_text("IP-CIDR,192.0.2.0/31\n")
            self.assertEqual(VERIFY.verify_supplemental_ips(root), 0)


if __name__ == "__main__":
    unittest.main()
