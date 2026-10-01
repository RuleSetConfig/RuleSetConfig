import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("merge_filter", ROOT / "scripts" / "merge-filter.py")
MERGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE)

CHINA_SPEC = importlib.util.spec_from_file_location("filter_china", ROOT / "scripts" / "filter-china.py")
CHINA = importlib.util.module_from_spec(CHINA_SPEC)
CHINA_SPEC.loader.exec_module(CHINA)
VERIFY_SPEC = importlib.util.spec_from_file_location("verify_all", ROOT / "scripts" / "verify-all.py")
VERIFY = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY)


class FilterPipelineTests(unittest.TestCase):
    def test_domestic_classifier_retains_brand_boundaries(self):
        brands = {"163", "toutiao"}
        self.assertTrue(CHINA.is_domestic("ad.example.com.cn", brands))
        self.assertTrue(CHINA.is_domestic("ads.pangolin-sdk-toutiao1.com", brands))
        self.assertTrue(CHINA.is_domestic("ads.163.com", brands))
        self.assertFalse(CHINA.is_domestic("163.staticip.rima-tde.net", brands))
        self.assertFalse(CHINA.is_domestic("notoutiao.example", brands))

    def test_unified_verifier_accepts_equal_ip_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            rules = Path(temp) / "candidate.list"
            compiled = Path(temp) / "candidate.json"
            rules.write_text(".example.com\nexact.example\nIP-CIDR,192.0.2.0/24\n", encoding="utf-8")
            compiled.write_text(json.dumps({"version": 2, "rules": [
                {"domain_suffix": ["example.com"]}, {"domain": ["exact.example"]},
                {"ip_cidr": ["192.0.2.0/25", "192.0.2.128/25"]}]}), encoding="utf-8")
            self.assertEqual(VERIFY.verify(rules, compiled), 0)

    def test_unified_verifier_detects_exact_suffix_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            rules = Path(temp) / "candidate.list"
            compiled = Path(temp) / "candidate.json"
            rules.write_text(".example.com\n", encoding="utf-8")
            compiled.write_text(json.dumps({"rules": [{"domain": ["example.com"]}]}), encoding="utf-8")
            self.assertEqual(VERIFY.verify(rules, compiled), 1)

    def test_scoped_rules_and_paths_are_not_broadened(self):
        for rule in ("||example.com/ads.js", "||example.com^$client=alice",
                     "||example.com^$dnstype=A", "||example.com^$denyallow=safe.example.com",
                     "||example.com^$third-party", "@@||example.com^$document",
                     "||example.com^$dnsrewrite=1.2.3.4", "/ads[0-9]+/", "||ads*.example.com^"):
            with self.subTest(rule=rule):
                parsed, _ = MERGE.domain_rule(rule.removeprefix("@@"))
                self.assertIsNone(parsed)

    def test_supported_domain_anchors(self):
        for rule, expected in (
            ("||example.com^", ("domain_suffix", "example.com")),
            ("||example.com^|", ("domain_suffix", "example.com")),
            ("||example.com|", ("domain_suffix", "example.com")),
            ("|example.com^|", ("domain", "example.com")),
            ("example.com", ("domain", "example.com")),
            ("||example.com^$important", ("domain_suffix", "example.com")),
            ("||example.com^$dnsrewrite=ad-block.dns.adguard.com", ("domain_suffix", "example.com")),
        ):
            with self.subTest(rule=rule):
                self.assertEqual(MERGE.domain_rule(rule)[0], [expected])

    def test_hosts_only_accepts_block_addresses_and_all_hosts(self):
        self.assertEqual(MERGE.domain_rule("0.0.0.0 a.example b.example # ads")[0],
                         [("domain", "a.example"), ("domain", "b.example")])
        self.assertIsNone(MERGE.domain_rule("8.8.8.8 safe.example")[0])
        self.assertIsNone(MERGE.domain_rule("||1.2.3.4^")[0])
        self.assertIsNone(MERGE.domain_rule("||-invalid.example^")[0])

    def test_badfilter_disables_same_source_rule_only(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.txt"
            source.write_text("||disabled.example^$important\n"
                              "||disabled.example^$badfilter,important\n"
                              "||directive.example^$badfilter\n" +
                              "\n".join(f"||ad{i}.invalid^" for i in range(600)), encoding="utf-8")
            (suffix, _, _, _), audit = MERGE.scan_adblock(source)
            self.assertNotIn("disabled.example", suffix)
            self.assertNotIn("directive.example", suffix)
            self.assertEqual(audit["counts"]["disabled-by-badfilter"], 1)
            peer = Path(temp) / "peer.txt"
            peer.write_text("||disabled.example^\n" +
                            "\n".join(f"||ad{i}.invalid^" for i in range(600)), encoding="utf-8")
            self.assertIn("disabled.example", MERGE.parse_adblock(peer)[0])

    def test_parent_lookup_uses_label_boundaries(self):
        self.assertEqual(MERGE.parent_of("safe.ads.example.com", {"example.com"}), "example.com")
        self.assertIsNone(MERGE.parent_of("notexample.com", {"example.com"}))

    def test_exceptions_are_parsed_separately_from_block_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.txt"
            source.write_text(
                "||example.com^\n@@||safe.example.com^\n" +
                "\n".join(f"||ad{i}.invalid^" for i in range(600)) + "\n",
                encoding="utf-8",
            )
            suffix, exact, allow_suffix, allow_exact = MERGE.parse_adblock(source)
            self.assertIn("example.com", suffix)
            self.assertIn("safe.example.com", allow_suffix)
            self.assertNotIn("safe.example.com", exact)
            self.assertFalse(allow_exact)

    def test_prune_domains_removes_children_and_covered_exact_rules(self):
        suffix, exact = MERGE.prune_domains(
            {"example.com", "child.example.com"},
            {"host.example.com", "standalone.example"},
        )
        self.assertEqual(suffix, {"example.com"})
        self.assertEqual(exact, {"standalone.example"})

    def test_build_ignores_exception_without_cancelling_positive_rule(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.txt"
            source.write_text(
                "||ads.example.com^\n@@||ads.example.com^\n"
                "@@|login.ads.example.com^|\n@@||unblocked.example^\n"
                "@@||invalid*.example^\n@@||example.com^\n" +
                "\n".join(f"||ad{i}.invalid^" for i in range(600)) + "\n",
                encoding="utf-8",
            )
            output = Path(temp) / "output"
            args = type("Args", (), {
                "adblock": [source],
                "domain_list": [],
                "output_dir": output,
            })()
            original_suffix, original_exact = MERGE.MIN_SUFFIX, MERGE.MIN_EXACT
            try:
                MERGE.MIN_SUFFIX = 1
                MERGE.MIN_EXACT = 0
                self.assertEqual(MERGE.build(args), 0)
            finally:
                MERGE.MIN_SUFFIX, MERGE.MIN_EXACT = original_suffix, original_exact
            rules = (output / "filter.list").read_text(encoding="utf-8").splitlines()
            self.assertIn(".ads.example.com", rules)
            report = json.loads((output / "filter-audit.json").read_text())
            exceptions = report["sources"]["source.txt"]["exceptions"]
            self.assertEqual(report["exception_policy"], "audit-only-block-wins")
            self.assertEqual(exceptions[0]["domains"][0]["covering_suffix"], "ads.example.com")
            self.assertEqual(exceptions[0]["domains"][0]["blocking_sources"], ["source.txt"])
            self.assertEqual(exceptions[1]["domains"][0]["covering_suffix"], "ads.example.com")
            self.assertFalse(exceptions[2]["domains"][0]["overlaps_block"])
            self.assertEqual(exceptions[3]["parse"], "wildcard")
            self.assertTrue(exceptions[4]["domains"][0]["blocked_descendant"])
            self.assertFalse((output / "filter-allow-direct.list").exists())
            self.assertFalse((output / "filter-allow-proxy.list").exists())


if __name__ == "__main__":
    unittest.main()
