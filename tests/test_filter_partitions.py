import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MERGE = load("partition_merge", "merge-filter.py")
VERIFY = load("partition_verify", "verify-all.py")


class PartitionTests(unittest.TestCase):
    def test_tld_validator_rejects_rule_set_syntax(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "DIRECT_SET.list"
            path.write_text(".cn\n")
            VERIFY.verify_tld_set(path)
            path.write_text("DOMAIN-SUFFIX,cn\n")
            with self.assertRaises(SystemExit):
                VERIFY.verify_tld_set(path)

    def test_tld_validator_rejects_duplicates_and_empty_sets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PROXY_SET.list"
            for content in (".ai\n.ai\n", "# empty\n"):
                path.write_text(content)
                with self.subTest(content=content), self.assertRaises(SystemExit):
                    VERIFY.verify_tld_set(path)

    def test_tld_lists_require_matching_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PROXY_SET.list").write_text(".ai\n.app\n")
            (root / "DIRECT_SET.list").write_text(".cn\n")
            stray = root / "unexpected.list"
            stray.write_text(".com\n")
            with patch.object(sys, "argv", ["verify-all.py", "--root", directory]):
                with self.assertRaises(SystemExit) as caught:
                    VERIFY.main()
                self.assertIn("unexpected", str(caught.exception))
                stray.unlink()
                with self.assertRaises(SystemExit) as caught:
                    VERIFY.main()
                self.assertIn("PROXY_SET", str(caught.exception))
                self.assertIn("DIRECT_SET", str(caught.exception))

    def test_partition_union_preserves_original_language_and_file_types(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suffix = {"ads.example.com"}
            exact = {"telemetry.example.net"}
            patterns = {("domain_keyword", "-track-"),
                        ("domain_wildcard", "api-*.example.org"),
                        ("ip_cidr", "192.0.2.0/24"),
                        ("ip_cidr", "2001:db8::/32")}
            MERGE.write_domain_rulesets(suffix, exact, root / "whole.list", root / "whole.json", patterns)
            counts = MERGE.write_filter_partitions(suffix, exact, patterns, root)
            self.assertEqual(list(counts.values()), [2, 2, 2])
            domain = (root / "REJECT-DOMAIN-SET.list").read_text()
            self.assertIn("\n.ads.example.com\n", domain)
            self.assertIn("\ntelemetry.example.net\n", domain)
            self.assertNotIn(",", "\n".join(line for line in domain.splitlines() if not line.startswith("#")))
            parts = [VERIFY.parse_list(root / f"{name}.list") for name in MERGE.PARTITIONS]
            self.assertEqual(parts[0]["domain_suffix"], suffix)
            self.assertEqual(parts[0]["domain"], exact)
            self.assertEqual(parts[1]["ip_cidr"], {"192.0.2.0/24", "2001:db8::/32"})
            self.assertEqual(parts[2]["domain_keyword"], {"-track-"})
            original = VERIFY.parse_list(root / "whole.list")
            for kind in original:
                if kind == "logical_and":
                    self.assertTrue(all(not part[kind] for part in parts))
                    continue
                combined = set().union(*(part[kind] for part in parts))
                self.assertEqual(combined, original[kind])
                self.assertEqual(sum(len(part[kind]) for part in parts), len(combined))
            for name in MERGE.PARTITIONS:
                self.assertEqual(VERIFY.verify(root / f"{name}.list", root / f"{name}.json"), 0)

    def test_empty_partitions_have_no_match_all_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            counts = MERGE.write_filter_partitions({"ads.example"}, set(), [], root)
            for name in MERGE.PARTITIONS[1:]:
                self.assertEqual(counts[name], 0)
                self.assertEqual(json.loads((root / f"{name}.json").read_text())["rules"], [])

    def test_hosts_sink_addresses_are_not_destination_blocks(self):
        entries, _ = MERGE.domain_rule("127.0.0.1 ads.example")
        self.assertEqual(entries, [("domain", "ads.example")])

    def test_source_floor_catches_truncated_oisd_small(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "filter_5.txt"
            source.write_text("\n".join(f"||ads{i}.example^" for i in range(600)))
            with self.assertRaises(SystemExit):
                MERGE.scan_adblock(source)

    def test_optional_empty_partition_still_guards_a_nonempty_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline, candidate = root / "old.list", root / "new.list"
            candidate.write_text("# empty partition\n")
            command = [sys.executable, str(ROOT / "scripts/guard-ruleset.py"),
                       "--candidate", str(candidate), "--baseline", str(baseline),
                       "--max-rules", "300000", "--allow-empty"]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            baseline.write_text("# empty partition\n")
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            baseline.write_text("IP-CIDR,192.0.2.0/24\n")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run(command + ["--allow-large-change"], capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
