"""Keep reviewed suffix, keyword, AND, protocol and migrated IP scopes precise."""

import argparse
from collections import Counter
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from filter_domains import read_domain_rules
from filter_ips import read_ip_rules
from filter_patterns import parse_keyword_and, pattern_line, read_pattern_rules
from ip_rulesets import read_networks


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MERGE = load("advanced_merge", "merge-filter.py")
VERIFY = load("advanced_verify", "verify-all.py")


class SupplementScopesTests(unittest.TestCase):
    def test_single_label_suffix_is_valid_but_bare_single_label_is_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "domains.list"
            path.write_text(".data\n.ndcpp.com\nmmgame.qpic.cn\n")
            self.assertEqual(read_domain_rules(path), ({"data", "ndcpp.com"}, {"mmgame.qpic.cn"}))
            path.write_text("data\n")
            with self.assertRaises(ValueError):
                read_domain_rules(path)

    def test_and_is_canonical_and_does_not_become_an_or(self):
        first = "AND,((DOMAIN-KEYWORD,fqnovel),(DOMAIN-KEYWORD,misc))"
        second = "AND,((DOMAIN-KEYWORD,misc),(DOMAIN-KEYWORD,fqnovel))"
        self.assertEqual(parse_keyword_and(first), parse_keyword_and(second))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules = {("logical_and", parse_keyword_and(first)), ("protocol", "stun")}
            MERGE.write_filter_partitions(set(), set(), rules, root)
            document = json.loads((root / "REJECT-RULE-SET.json").read_text())
            self.assertEqual(document["rules"], [{"type": "logical", "mode": "and", "rules": [
                {"domain_keyword": ["fqnovel"]}, {"domain_keyword": ["misc"]}]}])
            self.assertIn("PROTOCOL,STUN\n", (root / "REJECT-RULE-SET.list").read_text())
            self.assertEqual(VERIFY.verify(root / "REJECT-RULE-SET.list", root / "REJECT-RULE-SET.json"), 0)
            document["rules"] = [{"domain_keyword": ["fqnovel", "misc"]}]
            (root / "wrong.json").write_text(json.dumps(document))
            self.assertEqual(VERIFY.verify(root / "REJECT-RULE-SET.list", root / "wrong.json"), 1)

    def test_full_builder_audits_and_preserves_advanced_supplements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "upstream.txt"
            upstream.write_text("||ads.example^\ntracker.example\n")
            domains = root / "domains.list"
            domains.write_text(".data\n")
            patterns = root / "patterns.list"
            patterns.write_text("AND,((DOMAIN-KEYWORD,fqnovel),(DOMAIN-KEYWORD,misc))\nPROTOCOL,STUN\n")
            exclusions = root / "exclusions.list"
            exclusions.write_text("# none\n")
            output = root / "output"
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), patch.object(MERGE, "MIN_EXACT", 1):
                MERGE.build(argparse.Namespace(adblock=[upstream], domain_rules=[domains],
                    pattern_rules=[patterns], domain_exclusions=exclusions, output_dir=output))
            audit = json.loads((output / "filter-audit.json").read_text())
            self.assertEqual(audit["result"]["surge_only"], ["PROTOCOL,STUN"])
            self.assertEqual(audit["sources"]["patterns.list"]["counts"], {"logical_and": 1, "protocol": 1})
            self.assertEqual(VERIFY.verify(output / "REJECT-RULE-SET.list", output / "REJECT-RULE-SET.json"), 0)

    def test_manifest_requires_the_actual_surge_only_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "metadata").mkdir()
            (root / "REJECT-RULE-SET.list").write_text("PROTOCOL,STUN\n")
            path = root / "metadata/filter.json"
            document = {"schema": 1, "name": "filter", "sources": {}, "outputs": {}, "filter": {}}
            path.write_text(json.dumps(document))
            with self.assertRaises(SystemExit):
                VERIFY.verify_manifests(root)
            document["filter"] = {"surge_only": ["PROTOCOL,STUN"], "result": {"surge_only": ["PROTOCOL,STUN"]}}
            path.write_text(json.dumps(document))
            VERIFY.verify_manifests(root)

    def test_source_rejects_protocol_options_unknown_protocols_and_malformed_logic(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rules.list"
            for line in ("PROTOCOL,HTTP", "PROTOCOL,STUN,REJECT", "PROTOCOL,STUN,no-resolve",
                         "AND,((DOMAIN-KEYWORD,ads))", "AND,((DOMAIN-KEYWORD,ads),(DOMAIN,example.com))",
                         "AND,((DOMAIN-KEYWORD,ads),(DOMAIN-KEYWORD,ads))",
                         "AND,((DOMAIN-KEYWORD,ads),(DOMAIN-KEYWORD,tracker)),REJECT",
                         "OR,((DOMAIN-KEYWORD,ads),(DOMAIN-KEYWORD,tracker))"):
                path.write_text(line + "\n")
                with self.subTest(line=line), self.assertRaises(ValueError):
                    read_pattern_rules(path)
            path.write_text("PROTOCOL,STUN\nAND,((DOMAIN-KEYWORD,misc),(DOMAIN-KEYWORD,fqnovel))\n")
            self.assertEqual(read_pattern_rules(path), {("protocol", "stun"), ("logical_and", ("fqnovel", "misc"))})

    def test_verifier_rejects_or_terms_and_extra_match_constraints_inside_and(self):
        for child in ({"domain_keyword": ["ads", "tracker"]},
                      {"domain_keyword": ["ads"], "domain": ["example.com"]}):
            with self.subTest(child=child), self.assertRaises(SystemExit):
                VERIFY.walk_decompiled({"rules": [{"type": "logical", "mode": "and", "rules": [child]}]}, {})

    def test_stun_exception_is_limited_to_the_reviewed_reject_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "PROXY-RULE-SET.list"
            path.write_text("PROTOCOL,STUN\n")
            compiled = root / "candidate.json"
            compiled.write_text(json.dumps({"version": 5, "rules": []}))
            self.assertEqual(VERIFY.verify(path, compiled), 1)
            with self.assertRaises(ValueError):
                pattern_line("protocol", "http")

    def test_empty_inline_source_is_optional_but_empty_curated_source_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "empty.list"
            path.write_text("# no client-only exclusions\n")
            self.assertEqual(read_networks(path, allow_empty=True), [])
            with self.assertRaises(ValueError):
                read_ip_rules(path)

    def test_telegram_and_apple_are_now_curated_and_no_longer_excluded(self):
        curated = read_networks(ROOT / "source/proxy-ip-extra.list")
        self.assertEqual(read_networks(ROOT / "source/proxy-ip-inline.list", allow_empty=True), [])
        for cidr in ("17.0.0.0/8", "185.76.151.0/24", "91.108.12.0/22", "149.154.160.0/20",
                     "2001:67c:4e8::/48", "2001:b28:f23d::/48", "2403:300::/32", "2a0a:f280::/32"):
            network = ipaddress.ip_network(cidr)
            with self.subTest(cidr=cidr):
                self.assertTrue(any(network.version == other.version and network.subnet_of(other) for other in curated))

    def test_keyword_verifier_detects_missing_wrong_and_extra_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source").mkdir()
            (root / "source/domain-keywords.json").write_text(json.dumps({"schema": 1, "proxy": ["apple"], "direct": ["baidu"]}))
            with self.assertRaises(SystemExit):
                VERIFY.verify_keyword_sets(root)
            (root / "PROXY-RULE-SET.list").write_text("DOMAIN-KEYWORD,apple\n")
            (root / "DIRECT-RULE-SET.list").write_text("DOMAIN-KEYWORD,baidu\n")
            self.assertEqual(VERIFY.verify_keyword_sets(root), 0)
            for text in ("DOMAIN-KEYWORD,weixin\n", "DOMAIN-KEYWORD,baidu\nDOMAIN-SUFFIX,cn\n"):
                (root / "DIRECT-RULE-SET.list").write_text(text)
                with self.subTest(text=text), self.assertRaises(SystemExit):
                    VERIFY.verify_keyword_sets(root)


if __name__ == "__main__":
    unittest.main()
