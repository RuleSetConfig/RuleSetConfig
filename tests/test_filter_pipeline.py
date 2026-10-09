import importlib.util
import json
import re
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("merge_filter", ROOT / "scripts" / "merge-filter.py")
MERGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE)

VERIFY_SPEC = importlib.util.spec_from_file_location("verify_all", ROOT / "scripts" / "verify-all.py")
VERIFY = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY)


class FilterPipelineTests(unittest.TestCase):
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
                     "||example.com^$dnsrewrite=1.2.3.4", "/https:\\/\\/ads/"):
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
        self.assertEqual(MERGE.domain_rule("||1.2.3.4^")[0], [("ip_cidr", "1.2.3.4/32")])
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
                "output_dir": output,
            })()
            original_suffix, original_exact = MERGE.MIN_SUFFIX, MERGE.MIN_EXACT
            try:
                MERGE.MIN_SUFFIX = 1
                MERGE.MIN_EXACT = 0
                self.assertEqual(MERGE.build(args), 0)
            finally:
                MERGE.MIN_SUFFIX, MERGE.MIN_EXACT = original_suffix, original_exact
            rules = (output / "REJECT-DOMAIN-SET.list").read_text(encoding="utf-8").splitlines()
            self.assertIn(".ads.example.com", rules)
            report = json.loads((output / "filter-audit.json").read_text())
            exceptions = report["sources"]["source.txt"]["exceptions"]
            self.assertEqual(report["exception_policy"], "audit-only-block-wins")
            self.assertEqual(exceptions[0]["domains"][0]["covering_suffix"], "ads.example.com")
            self.assertEqual(exceptions[0]["domains"][0]["blocking_sources"], ["source.txt"])
            self.assertEqual(exceptions[1]["domains"][0]["covering_suffix"], "ads.example.com")
            self.assertFalse(exceptions[2]["domains"][0]["overlaps_block"])
            self.assertEqual(exceptions[3]["parse"], "accepted")
            self.assertEqual(exceptions[3]["domains"][0]["overlap_analysis"], "pattern-not-evaluated")
            self.assertTrue(exceptions[4]["domains"][0]["blocked_descendant"])
            self.assertFalse((output / "filter-allow-direct.list").exists())
            self.assertFalse((output / "filter-allow-proxy.list").exists())


class PatternTests(unittest.TestCase):
    @staticmethod
    def matches(rule, hostname):
        from filter_patterns import wildcard_regex
        parsed, reason = MERGE.domain_rule(rule)
        if parsed is None:
            raise AssertionError(reason)
        hostname = hostname.lower()
        return any((kind == "domain" and hostname == value) or
                   (kind == "domain_suffix" and (hostname == value or hostname.endswith("." + value))) or
                   (kind == "domain_keyword" and value in hostname) or
                   (kind == "domain_wildcard" and re.search(wildcard_regex(value), hostname))
                   for kind, value in parsed)

    def test_applog_keeps_literal_hyphen_and_end_anchor(self):
        for host in ("api-applog.fqnovel.com", "api-applog-lf.fqnovel.com",
                     "x.api-applog.a.b.fqnovel.com"):
            self.assertTrue(self.matches("-applog*.fqnovel.com^", host), host)
        for host in ("applog.fqnovel.com", "applog-lf.fqnovel.com", "www.fqnovel.com",
                     "api-applog.fqnovel.com.evil.net"):
            self.assertFalse(self.matches("-applog*.fqnovel.com^", host), host)

    def test_domain_anchor_and_empty_wildcard(self):
        rule = "||ad*.example.com^"
        for host in ("ad.example.com", "ads.example.com", "x.ads.example.com", "ad.a.example.com"):
            self.assertTrue(self.matches(rule, host), host)
        for host in ("bad.example.com", "example.com", "ads.example.com.evil"):
            self.assertFalse(self.matches(rule, host), host)

    def test_missing_right_anchor_is_not_suffix(self):
        self.assertTrue(self.matches("||adserver.", "adserver.example.org"))
        self.assertTrue(self.matches("||adserver.", "x.adserver.example.org"))
        self.assertFalse(self.matches("||adserver.", "notadserver.example.org"))
        self.assertTrue(self.matches("||example.com", "example.com.evil"))
        self.assertFalse(self.matches("||example.com^", "example.com.evil"))
        self.assertTrue(self.matches("|piwik.", "piwik.example.com"))
        self.assertFalse(self.matches("|piwik.", "a.piwik.example.com"))

    def test_unanchored_rule_is_not_exact(self):
        self.assertTrue(self.matches("vkcdnservice.appspot.com^", "xvkcdnservice.appspot.com"))
        self.assertFalse(self.matches("vkcdnservice.appspot.com", "xvkcdnservice.appspot.com"))
        self.assertTrue(self.matches("-ad123-", "x-ad123-y.example"))
        self.assertFalse(self.matches("-ad123-", "ad123.example"))

    def test_regex_end_anchor_is_not_modifier(self):
        rule = "/^(a|c)\\.[0-9a-f]{56}\\.com$/"
        self.assertTrue(self.matches(rule, "a." + "a0" * 28 + ".com"))
        self.assertFalse(self.matches(rule, "a." + "a0" * 27 + ".com"))
        self.assertFalse(self.matches(rule, "b." + "a0" * 28 + ".com"))
        self.assertFalse(self.matches(rule, "a." + "g0" * 28 + ".com"))

    def test_regex_variants_match_independent_original_expression(self):
        rule = r"/^(mon|tue|wed|thu|fri|sat|sun)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com$/"
        expected = re.compile(rule[1:-1], re.ASCII | re.IGNORECASE)
        for day in ("mon", "sun", "MON", "xyz"):
            for count in (0, 1, 2, 3):
                for digits in (0, 1, 6, 7):
                    host = day + "1" * count + ".ab" + "9" * digits + "wxyz.com"
                    self.assertEqual(bool(self.matches(rule, host)), bool(expected.search(host)), host)

    def test_unsupported_regex_fails_closed(self):
        with self.assertRaises(ValueError):
            MERGE.domain_rule(r"/^ads(?=\.)/")
        self.assertIsNone(MERGE.domain_rule(r"/^https:\/\/ads\.example/ ")[0])

    def test_ip_regex_projection_preserves_decimal_prefixes(self):
        import ipaddress
        rules, _ = MERGE.domain_rule(r"/^94\.242\.247\.(2[0-9]|3[0-2])/")
        networks = [ipaddress.ip_network(v) for k, v in rules if k == "ip_cidr"]
        for i in range(256):
            host = f"94.242.247.{i}"
            expected = bool(re.search(r"^94\.242\.247\.(2[0-9]|3[0-2])", host))
            self.assertEqual(any(ipaddress.ip_address(host) in n for n in networks), expected, host)

    def test_unanchored_ip_regex_includes_162_prefix(self):
        import ipaddress
        rules, _ = MERGE.domain_rule(r"/62.76.25.2(7|8)/")
        networks = [ipaddress.ip_network(v) for k, v in rules if k == "ip_cidr"]
        self.assertTrue(any(ipaddress.ip_address("162.76.25.27") in n for n in networks))
        self.assertFalse(any(ipaddress.ip_address("162.76.25.29") in n for n in networks))

    def test_wildcard_roundtrip_and_corruption_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp)/"REJECT-RULE-SET.list", Path(temp)/"REJECT-RULE-SET.json"
            rules = MERGE.domain_rule("-applog*.fqnovel.com^")[0]
            MERGE.write_domain_rulesets(set(), set(), a, b, rules)
            self.assertEqual(VERIFY.verify(a, b), 0)
            data = json.loads(b.read_text())
            data["rules"][0]["domain_regex"][0] = "wrong"
            b.write_text(json.dumps(data))
            self.assertEqual(VERIFY.verify(a, b), 1)


if __name__ == "__main__":
    unittest.main()
