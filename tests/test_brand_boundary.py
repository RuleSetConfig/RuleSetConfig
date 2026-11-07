"""Regression tests for the requested boundary and exact wildcard representation."""
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from brand_scope import BrandScope
from filter_scope import AppScope
from scope_compaction import compact_text, expand_text
from filter_patterns import wildcard_regex


class BrandBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.scope = BrandScope(ROOT)

    def test_inventory_matches_the_reviewed_inputs(self):
        app = json.loads((ROOT / "source/reject-app-scope.json").read_text())
        traffic = json.loads((ROOT / "source/traffic-brand-priority.json").read_text())
        plan = json.loads((ROOT / "source/companion-import.json").read_text())
        expected = {x["id"] for x in app["families"]} | {x["id"] for x in traffic["families"]}
        expected.update(x for names in plan["application_groups"].values() for x in names)
        self.assertEqual(set(self.scope.families), expected)
        apps = [a for f in app["families"] if f.get("category") == "installed" for a in f["applications"]]
        self.assertEqual(self.scope.applications, apps)
        doc = json.loads((ROOT / "source/domain-keywords.json").read_text())
        self.assertEqual(self.scope.keywords, {p: doc[p] for p in ["proxy", "direct"]})

    def test_unrelated_names_and_generic_blocking_are_excluded(self):
        for kind, value in [("domain_suffix", "unrelated-example.net"), ("domain_suffix", "com"),
                            ("domain_suffix", "evilqq.com"), ("domain_suffix", "qq.com.invalid"),
                            ("domain_keyword", "httpdns"), ("domain_keyword", "applog"),
                            ("domain_wildcard", "*"), ("protocol", "stun"),
                            ("process_name", "trustd"), ("user_agent", "ttplayer*")]:
            with self.subTest(kind=kind, value=value):
                self.assertFalse(self.scope.allows(kind, value))

    def test_all_reviewed_namespaces_and_keywords_remain_eligible(self):
        for kind, value in [("domain_suffix", "qq.com"), ("domain_suffix", "beisen.com"),
                            ("domain_suffix", "unionpay.com"), ("domain_suffix", "claude.ai"),
                            ("domain_wildcard", "track?.qq.com"), ("domain_keyword", "umeng")]:
            with self.subTest(kind=kind, value=value):
                self.assertTrue(self.scope.allows(kind, value))
        for words in self.scope.keywords.values():
            for word in words:
                self.assertTrue(self.scope.allows("domain_keyword", word))

    def test_shared_exact_hosts_cannot_turn_into_parent_suffixes(self):
        for host in ["pages.dev", "ctfassets.net", "fastly-edge.com", "cloudflare.com",
                     "us-west-2.amazonaws.com"]:
            with self.subTest(host=host):
                self.assertTrue(self.scope.allows("domain", host))
                self.assertTrue(self.scope.allows("domain_wildcard", host))
                self.assertFalse(self.scope.allows("domain_suffix", host))
                self.assertFalse(self.scope.allows("domain_wildcard", "*." + host))

    def test_and_conditions_keep_their_original_conjunction(self):
        self.assertTrue(self.scope.allows("logical_and", ("ads", "zijieapi.com")))
        self.assertTrue(self.scope.allows("logical_and", ("fqnovel", "misc")))
        self.assertFalse(self.scope.allows("logical_and", ("ads",)))
        self.assertFalse(self.scope.allows("domain_keyword", "ads"))

    def test_literal_wildcards_preserve_exact_scope_and_inverse_inventory(self):
        text, audit = compact_text("DOMAIN,exact.qq.com\nDOMAIN-SUFFIX,suffix.qq.com\n", no_domain=True)
        self.assertNotIn("\nDOMAIN,", "\n" + text)
        self.assertIn("DOMAIN-WILDCARD,exact.qq.com", text)
        self.assertIn("DOMAIN,exact.qq.com", expand_text(text))
        regex = re.compile(wildcard_regex("exact.qq.com"))
        self.assertTrue(regex.search("exact.qq.com"))
        self.assertFalse(regex.search("sub.exact.qq.com"))
        self.assertFalse(regex.search("exact.qq.com.invalid"))
        self.assertEqual(audit["new_matching_scope"], 0)

    def test_app_selector_uses_the_same_boundary(self):
        app = AppScope(ROOT / "source/reject-app-scope.json")
        self.assertEqual(app.families, set(self.scope.families))
        self.assertIsNone(app.family("unrelated-example.net"))
        self.assertIsNotNone(app.family("unionpay.com"))


if __name__ == "__main__":
    unittest.main()
