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
            path = Path(directory) / "DIRECT-DOMAIN-SET.list"
            path.write_text(".cn\n.amap.com\n.qq.com\n")
            self.assertEqual(VERIFY.verify_tld_set(path), [".cn", ".amap.com", ".qq.com"])
            path.write_text("DOMAIN-SUFFIX,cn\n")
            with self.assertRaises(SystemExit):
                VERIFY.verify_tld_set(path)

    def test_tld_validator_rejects_duplicates_and_empty_sets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PROXY-DOMAIN-SET.list"
            for content in (".ai\n.ai\n", "use.fortawesome.com\nuse.fortawesome.com\n", "# empty\n"):
                path.write_text(content)
                with self.subTest(content=content), self.assertRaises(SystemExit):
                    VERIFY.verify_tld_set(path)

    def test_domain_set_validator_rejects_invalid_domain_suffixes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "DIRECT-DOMAIN-SET.list"
            for entry in ("localhost", "192.0.2.1", ".192.0.2.1", "2001:db8::1",
                          ".qq..com", ".qq.com.", ".-amap.com", ".amap-.com",
                          "." + "a" * 64 + ".com", "." + ".".join(["a" * 63] * 4)):
                path.write_text(entry + "\n")
                with self.subTest(entry=entry), self.assertRaises(SystemExit):
                    VERIFY.verify_tld_set(path)

    def test_domain_set_validator_keeps_exact_and_suffix_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PROXY-DOMAIN-SET.list"
            entries = [".tv", ".moe", ".example.com", "example.com", "use.fortawesome.com"]
            path.write_text("\n".join(entries) + "\n")
            self.assertEqual(VERIFY.verify_tld_set(path), entries)

    def test_manual_parent_pruning_rejects_redundancy_in_any_order(self):
        cases = [
            [".child.example.com", ".example.com"],
            [".example.com", ".child.example.com"],
            ["child.example.com", ".example.com"],
            ["example.com", ".example.com"],
            [".service.microsoft", ".microsoft"],
            ["child.service.microsoft", ".microsoft"],
        ]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(SystemExit):
                VERIFY.verify_domain_set_parent_pruning(Path("PROXY-DOMAIN-SET.list"), entries)

    def test_manual_parent_pruning_respects_labels_and_exact_scope(self):
        cases = [
            [".example.com", ".notexample.com", ".example.com.invalid", ".child.example.net"],
            ["example.com", ".child.example.com", "other.example.com"],
            [".cuhk.edu.hk", ".other.edu.hk"],
        ]
        for entries in cases:
            with self.subTest(entries=entries):
                self.assertEqual(
                    VERIFY.verify_domain_set_parent_pruning(Path("PROXY-DOMAIN-SET.list"), entries), 0)

    def test_manual_compiler_refuses_covered_domains_before_core_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PROXY-DOMAIN-SET.list").write_text(".child.example.com\n.example.com\n")
            (root / "DIRECT-DOMAIN-SET.list").write_text(".cn\n")
            with patch.object(VERIFY.subprocess, "run") as run:
                with self.assertRaises(SystemExit):
                    VERIFY.compile_tld_sets(root, root / "output", "sing-box")
                run.assert_not_called()
            self.assertFalse((root / "output").exists())

    def test_tld_lists_require_matching_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PROXY-DOMAIN-SET.list").write_text(".ai\n.app\n")
            (root / "DIRECT-DOMAIN-SET.list").write_text(".cn\n")
            stray = root / "unexpected.list"
            stray.write_text(".com\n")
            with patch.object(sys, "argv", ["verify-all.py", "--root", directory]):
                with self.assertRaises(SystemExit) as caught:
                    VERIFY.main()
                self.assertIn("unexpected", str(caught.exception))
                stray.unlink()
                with self.assertRaises(SystemExit) as caught:
                    VERIFY.main()
                self.assertIn("PROXY-DOMAIN-SET", str(caught.exception))
                self.assertIn("DIRECT-DOMAIN-SET", str(caught.exception))

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
