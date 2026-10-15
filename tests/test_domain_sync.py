"""Scope, source-failure and preservation checks for the daily domain sync."""

import importlib.util
import json
from pathlib import Path
import re
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


SYNC = load("tested_domain_sync", "sync-domain-sets.py")
VERIFY = load("tested_domain_manifest", "verify-all.py")
from domain_keywords import KEYWORD_SOURCE, covering_keyword, read_inline_keywords


def sing(*, exact=(), suffix=(), regex=()):
    return {"domain": set(exact), "domain_suffix": set(suffix), "domain_regex": set(regex)}


class DomainSyncTests(unittest.TestCase):
    def test_domain_sources_keep_scope_and_deduplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.txt"
            path.write_text("# comment\n// comment\n\n.Example.com\nEXAMPLE.COM\n.example.com\n")
            self.assertEqual(SYNC.read_entries(path), {".example.com", "example.com"})

    def test_invalid_or_empty_domain_inputs_fail(self):
        for value in ("localhost", "192.0.2.1", ".192.0.2.1", "..example.com",
                      "DOMAIN-SUFFIX,example.com", "*.example.com", ".example.com."):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SYNC.validate_entry(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.txt"
            path.write_text("# no rules\n")
            with self.assertRaises(ValueError):
                SYNC.read_entries(path)

    def test_srs_fields_preserve_children_only_and_regex(self):
        result = SYNC.parse_srs({"version": 1, "rules": [
            {"domain": "Exact.Example.com", "domain_suffix": ["example.org", ".example.net"],
             "domain_regex": [r"^cdn[0-9]+\.example.com$"]},
            {"domain": ["another.example.com"]},
        ]})
        self.assertEqual(result["domain"], {"exact.example.com", "another.example.com"})
        self.assertEqual(result["domain_suffix"], {"example.org", ".example.net"})
        self.assertEqual(result["domain_regex"], {r"^cdn[0-9]+\.example.com$"})

    def test_unexpected_srs_logic_or_field_types_fail(self):
        documents = [
            {"version": 1, "rules": []},
            {"version": 1, "rules": [{}]},
            {"version": 1, "rules": [{"type": "logical", "mode": "and", "rules": []}]},
            {"version": 1, "rules": [{"domain": ["example.com"], "invert": True}]},
            {"version": 1, "rules": [{"domain_keyword": ["google"]}]},
            {"version": 1, "rules": [{"domain": [1]}]},
            {"version": 1, "rules": [{"domain": [".example.com"]}]},
            {"version": 1, "rules": [{"domain_suffix": ["..example.com"]}]},
        ]
        for document in documents:
            with self.subTest(document=document), self.assertRaises(ValueError):
                SYNC.parse_srs(document)

    def test_merge_prunes_only_covered_entries_and_retains_custom_scope(self):
        result, audit = SYNC.merge_entries(
            {".custom.example.com", "only.example.net", ".notexample.org"},
            {".example.org", "example.net"},
            sing(exact={"api.example.org"}, suffix={".example.net", "child.example.org"}),
        )
        self.assertEqual(result, {".custom.example.com", ".notexample.org", ".example.org", ".example.net"})
        self.assertTrue(audit["all_domain_inputs_covered_with_inline_keywords"])
        self.assertEqual(audit["children_only_suffixes_covered_without_expansion"], 1)

    def test_exact_parent_keeps_child_scope_and_label_boundaries(self):
        result, _ = SYNC.merge_entries(
            {"example.com", "child.example.com", ".notexample.net"},
            {".example.net"}, sing(),
        )
        self.assertEqual(result, {"example.com", "child.example.com", ".notexample.net", ".example.net"})

    def test_children_only_suffix_cannot_gain_an_apex(self):
        with self.assertRaisesRegex(ValueError, "no input covering its apex"):
            SYNC.merge_entries({".custom.example.com"}, set(), sing(suffix={".example.net"}))
        result, _ = SYNC.merge_entries(
            {".custom.example.com"}, {"example.net"}, sing(suffix={".example.net"}))
        self.assertIn(".example.net", result)

    def test_custom_survives_upstream_withdrawal_without_accumulating_stale_rules(self):
        custom = {".custom.example.com"}
        before, _ = SYNC.merge_entries(custom, {".withdrawn.example.net"}, sing())
        after, _ = SYNC.merge_entries(custom, {".current.example.net"}, sing())
        self.assertIn(".withdrawn.example.net", before)
        self.assertNotIn(".withdrawn.example.net", after)
        self.assertIn(".custom.example.com", after)

    def test_regex_is_audited_without_broadening_to_a_parent(self):
        expression = r"^cdn[0-9]+\.example.net$"
        result, audit = SYNC.merge_entries({".custom.example.com"}, set(), sing(regex={expression}))
        self.assertEqual(result, {".custom.example.com"})
        self.assertEqual(audit["regex_not_imported"], [expression])

    def test_each_upstream_has_an_independent_nonzero_floor(self):
        for name, source in SYNC.SOURCES.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "source floor"):
                    SYNC.check_source_floor(name, source["min_rules"] - 1)
                SYNC.check_source_floor(name, source["min_rules"])

    def fixture(self, root):
        (root / "source").mkdir()
        (root / KEYWORD_SOURCE).write_text(json.dumps({"schema": 1, "proxy": ["google"], "direct": ["baidu"]}))
        for key, relative in SYNC.CUSTOM.items():
            (root / relative).write_text(f".custom-{key}.example.com\n")
        upstream = root / "upstream"
        upstream.mkdir()
        for source in SYNC.SOURCES.values():
            (upstream / source["file"]).write_bytes(b"fixture source\n")
        parsed = {
            "sing-proxy": sing(suffix={"proxy.example.net"}),
            "sing-direct": sing(suffix={"direct.example.net"}),
            "surge-proxy": {".shared.example.net"},
            "surge-direct": {".shared.example.net"},
        }
        floors = {name: {**source, "min_rules": 1} for name, source in SYNC.SOURCES.items()}
        return upstream, parsed, floors

    def test_rebuild_is_deterministic_and_keeps_cross_set_classifications(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream, parsed, floors = self.fixture(root)
            with patch.object(SYNC, "SOURCES", floors):
                first = SYNC.build_lists(root, upstream, root / "first", parsed)
                second = SYNC.build_lists(root, upstream, root / "second", parsed)
            self.assertEqual(first, second)
            for name in ("PROXY_SET.list", "DIRECT_SET.list"):
                self.assertEqual((root / "first" / name).read_bytes(), (root / "second" / name).read_bytes())
                self.assertIn(".shared.example.net\n", (root / "first" / name).read_text())

    def test_bad_second_source_cannot_write_either_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream, parsed, floors = self.fixture(root)
            parsed["sing-direct"] = sing()
            output = root / "candidate"
            with patch.object(SYNC, "SOURCES", floors), self.assertRaises(ValueError):
                SYNC.build_lists(root, upstream, output, parsed)
            self.assertFalse(output.exists())

    def test_source_hash_change_blocks_publication_of_stale_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "metadata").mkdir()
            source = root / "source/custom.list"
            source.write_text(".example.com\n")
            manifest = {"schema": 1, "sources": {
                "custom": {"url": "repository:source/custom.list", **SYNC.digest(source)},
            }, "outputs": {}}
            (root / "metadata/tld.json").write_text(json.dumps(manifest))
            VERIFY.verify_manifests(root)
            source.write_text(".example.com\n.new.example.net\n")
            with self.assertRaisesRegex(SystemExit, "repository source does not match"):
                VERIFY.verify_manifests(root)

    def test_inline_keyword_filter_keeps_only_same_policy_coverage(self):
        result, audit = SYNC.merge_entries(
            {".google.example.org", ".baidu.example.net", "exact.safe.example.net"},
            {"prefix-google-cdn.example.net", ".keep.example.org"},
            sing(exact={"api.github.example.net"}), ("github", "google"),
        )
        self.assertEqual(result, {".baidu.example.net", "exact.safe.example.net", ".keep.example.org"})
        self.assertEqual(audit["keyword_covered_entries_removed"], 3)
        self.assertEqual({item["entry"] for item in audit["keyword_covered_entries"]},
                         {".google.example.org", "prefix-google-cdn.example.net", "api.github.example.net"})
        self.assertTrue(audit["all_domain_inputs_covered_with_inline_keywords"])

    def test_keyword_substring_matching_is_case_insensitive_without_label_boundaries(self):
        self.assertEqual(covering_keyword(".prefix-Google-cdn.example.com", ("google",)), "google")
        self.assertIsNone(covering_keyword(".goog.example.com", ("google",)))

    def test_keyword_pruning_verifier_rejects_reintroduced_domains(self):
        with self.assertRaises(SystemExit):
            VERIFY.verify_domain_set_keyword_pruning(Path("PROXY_SET.list"), [".google.example.org"], ("google",))
        self.assertEqual(VERIFY.verify_domain_set_keyword_pruning(
            Path("DIRECT_SET.list"), [".google.example.org"], ("baidu",)), 0)

    def test_parent_pruning_and_keyword_pruning_have_separate_audit_counts(self):
        result, audit = SYNC.merge_entries(
            {".google.example.org", ".child.google.example.org", ".keep.example.org"}, set(), sing(), ("google",))
        self.assertEqual(result, {".keep.example.org"})
        self.assertEqual(audit["parent_covered_entries_pruned"], 1)
        self.assertEqual(audit["keyword_covered_entries_removed"], 1)

    def test_keyword_source_rejects_empty_duplicate_or_uppercase_words(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            for words in ([""], ["google", "google"], ["GOOGLE"]):
                (root / KEYWORD_SOURCE).write_text(json.dumps({"schema": 1, "proxy": words, "direct": []}))
                with self.subTest(words=words), self.assertRaises(ValueError):
                    read_inline_keywords(root)

    def test_readme_client_keywords_match_the_checked_policy_source(self):
        policy = read_inline_keywords(ROOT)
        readme = (ROOT / "README.md").read_text()
        surge = {key: [] for key in policy}
        for word, target in re.findall(r"^DOMAIN-KEYWORD,([^,\n]+),(PROXY|DIRECT)$", readme, re.MULTILINE):
            surge[target.lower()].append(word)
        self.assertEqual({key: tuple(words) for key, words in surge.items()}, policy)
        sing_box = {}
        for block in re.findall(r"```json\n(.*?)\n```", readme, re.DOTALL):
            for rule in json.loads(block).get("route", {}).get("rules", []):
                if "domain_keyword" in rule:
                    sing_box[rule["outbound"]] = tuple(rule["domain_keyword"])
        self.assertEqual(sing_box, policy)


if __name__ == "__main__":
    unittest.main()
