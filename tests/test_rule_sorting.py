import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from rule_sorting import check_ruleset_order, domain_sort_key, split_records, sort_list_text

spec = importlib.util.spec_from_file_location("sorting_merge", ROOT / "scripts/merge-filter.py")
MERGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MERGE)


class RuleSortingTests(unittest.TestCase):
    def test_domain_sort_keeps_tlds_first_and_suffix_exact_membership(self):
        rows = ["z.example.net", ".example.com", ".cn", ".ai", "a.example.net"]
        text = "# source\n" + "\n".join(rows) + "\n"
        actual = sort_list_text(text, domain_set=True)
        ordered = [line for line, _ in split_records(actual)[1]]
        self.assertEqual(ordered, [".ai", ".cn", "a.example.net", ".example.com", "z.example.net"])
        self.assertEqual(Counter(ordered), Counter(rows))
        self.assertEqual(sort_list_text(actual, domain_set=True), actual)

    def test_ip_order_uses_numeric_addresses_and_separates_families(self):
        rows = ["IP-CIDR6,2001:db8::10/128", "IP-CIDR,100.64.0.0/10",
                "IP-CIDR,10.0.0.0/8", "IP-CIDR6,2001:db8::2/128",
                "IP-CIDR,2.0.0.1/32"]
        actual = sort_list_text("# source\n" + "\n".join(rows) + "\n")
        ordered = [line for line, _ in split_records(actual)[1]]
        self.assertEqual(ordered, [rows[4], rows[2], rows[1], rows[3], rows[0]])
        self.assertEqual(Counter(ordered), Counter(rows))
        self.assertEqual(actual.count("# IPv4"), 1)
        self.assertEqual(actual.count("# IPv6"), 1)
        self.assertLess(actual.index("# IPv4"), actual.index("# IPv6"))
        self.assertEqual(sort_list_text(actual), actual)

    def test_generator_orders_ip_json_and_interleaves_exact_domain_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ips = {("ip_cidr", "100.64.0.0/10"), ("ip_cidr", "2.0.0.1/32"),
                   ("ip_cidr", "10.0.0.0/8"), ("ip_cidr", "2001:db8::2/128")}
            counts = MERGE.write_filter_partitions({"a.example", "z.example"}, {"m.example"}, ips, root)
            domains = [line for line, _ in split_records((root / "REJECT-DOMAIN-SET.list").read_text())[1]]
            self.assertEqual(domains, [".a.example", "m.example", ".z.example"])
            cidrs = json.loads((root / "REJECT-IP-SET.json").read_text())["rules"][0]["ip_cidr"]
            self.assertEqual(cidrs, ["2.0.0.1/32", "10.0.0.0/8", "100.64.0.0/10", "2001:db8::2/128"])
            self.assertEqual(counts["REJECT-IP-SET"], 4)
            self.assertEqual(check_ruleset_order(root), 3)

    def test_check_catches_unsorted_sources_and_write_preserves_comments_and_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            path = source / "extra.list"
            path.write_text("# attribution\nIP-CIDR,10.0.0.1/32\n# note for 2\nIP-CIDR,2.0.0.1/32\nIP-CIDR,2.0.0.1/32\n")
            command = [sys.executable, "-B", str(ROOT / "scripts/sort-rulesets.py"), "--root", str(root)]
            before = path.read_text()
            self.assertNotEqual(subprocess.run(command + ["--check"], capture_output=True).returncode, 0)
            self.assertEqual(path.read_text(), before)
            subprocess.run(command + ["--write"], check=True, capture_output=True)
            after = path.read_text()
            self.assertEqual(Counter(line for line, _ in split_records(before)[1]),
                             Counter(line for line, _ in split_records(after)[1]))
            self.assertIn("# attribution", after)
            self.assertIn("# note for 2\nIP-CIDR,2.0.0.1/32", after)
            self.assertEqual(check_ruleset_order(root), 1)


if __name__ == "__main__":
    unittest.main()
