"""Lock the requested upstream roles and the reviewed cross-client rule scopes."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from filter_domains import read_domain_rules
from filter_exclusions import read_domain_exclusions
from filter_patterns import read_pattern_rules
from rule_sorting import sort_list_text, split_records

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

MERGE = load("source_policy_merge", "merge-filter.py")
VERIFY = load("source_policy_verify", "verify-all.py")

class SourcePolicyTests(unittest.TestCase):
    def test_domain_only_sources_cannot_contribute_ip_blocks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            primary, second, third = [root / name for name in ("primary.txt", "second.txt", "third.txt")]
            primary.write_text("||primary.example^\nexact.primary.example\n||192.0.2.1^\n")
            second.write_text("||secondary.example^\n||192.0.2.2^\n-secondary-pattern-\n")
            third.write_text("||third.example^\n||192.0.2.3^\n127.0.0.1 hosts.third.example\n")
            exclusions = root / "exclusions.list"
            exclusions.write_text("# none\n")
            output = root / "output"
            args = argparse.Namespace(adblock=[primary], domain_only_adblock=[second, third],
                                      domain_exclusions=exclusions, output_dir=output)
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                    patch.object(MERGE, "MIN_EXACT", 0), redirect_stdout(io.StringIO()):
                self.assertEqual(MERGE.build(args), 0)
            ips = VERIFY.parse_list(output / "REJECT-IP-SET.list")["ip_cidr"]
            self.assertEqual(ips, {"192.0.2.1/32"})
            domains = VERIFY.parse_list(output / "REJECT-DOMAIN-SET.list")
            self.assertTrue({"primary.example", "secondary.example", "third.example"} <= domains["domain_suffix"])
            patterns = VERIFY.parse_list(output / "REJECT-RULE-SET.list")["domain_keyword"]
            self.assertIn("-secondary-pattern-", patterns)
            audit = json.loads((output / "filter-audit.json").read_text())
            self.assertEqual(audit["result"]["source_roles"], {
                "primary.txt": "domains-patterns-and-ips",
                "second.txt": "domains-patterns-only",
                "third.txt": "domains-patterns-only"})
            self.assertEqual(audit["sources"]["second.txt"]["included"]["ip_rules"], 0)

    def test_support_only_source_cannot_expand_base_domains_patterns_or_ips(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            primary, support = root / "primary.txt", root / "support.txt"
            primary.write_text("||primary.example^\n")
            support.write_text("||support.example^\n||192.0.2.7^\n-support-pattern-\n")
            exclusions = root / "exclusions.list"
            exclusions.write_text("# none\n")
            args = argparse.Namespace(adblock=[primary], selection_only_adblock=[support],
                                      domain_exclusions=exclusions, output_dir=root / "output")
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                    patch.object(MERGE, "MIN_EXACT", 0), redirect_stdout(io.StringIO()):
                MERGE.build(args)
            self.assertNotIn("support.example", (root / "output/REJECT-DOMAIN-SET.list").read_text())
            self.assertNotIn("support-pattern", (root / "output/REJECT-RULE-SET.list").read_text())
            self.assertFalse(VERIFY.parse_list(root / "output/REJECT-IP-SET.list")["ip_cidr"])

    def test_duplicate_source_identity_cannot_overwrite_a_role(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "same.txt"
            source.write_text("||example.net^\n")
            args = argparse.Namespace(adblock=[source], domain_only_adblock=[source], output_dir=root / "output")
            with patch.object(MERGE, "MIN_ADBLOCK", 1), redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                MERGE.build(args)
            self.assertFalse((root / "output").exists())

    def test_workflow_selects_only_the_requested_sources(self):
        workflow = (ROOT / ".github/workflows/build-filter.yml").read_text()
        both = set(re.findall(r'--adblock "\$FILTER_BUILD_DIR/upstream/(filter_\d+\.txt)"', workflow))
        domain_only = set(re.findall(r'--domain-only-adblock "\$FILTER_BUILD_DIR/upstream/(filter_\d+\.txt)"', workflow))
        self.assertEqual(both, {"filter_1.txt"})
        self.assertEqual(domain_only, {"filter_2.txt", "filter_5.txt", "filter_53.txt", "filter_59.txt"})
        self.assertEqual(re.findall(r"for id in ([0-9 ]+); do", workflow), ["1 2 5 34 53 59", "1 2 5 34 53 59"])
        self.assertNotIn("surge-module", workflow)
        self.assertNotIn("novel-sources", workflow)

    def test_approved_local_sources_preserve_97_rules_and_domain_decisions(self):
        suffixes, exact = read_domain_rules(ROOT / "source/reject-domain-extra.list")
        patterns = read_pattern_rules(ROOT / "source/reject-rule-extra.list")
        self.assertEqual(len(suffixes) + len(exact) + len(patterns), 97)
        self.assertEqual(len([r for r in patterns if r[0] == "logical_and"]), 2)
        self.assertIn(("domain_keyword", "snssdk.com"), patterns)
        self.assertNotIn("zijieapi.com", suffixes)
        self.assertNotIn("data", suffixes)
        self.assertNotIn("zijieapi.com", read_domain_exclusions(ROOT / "source/reject-domain-exclusions.list"))
        self.assertIn(("domain_keyword", "zijieapi.com"), patterns)
        self.assertIn(("logical_and", ("ads", "zijieapi.com")), patterns)
        self.assertNotIn(("logical_and", ("ads", "zijieapi")), patterns)
        self.assertIn(("protocol", "stun"), patterns)
        self.assertIn(("user_agent", "ttplayer*"), patterns)

    def test_and_priority_and_reviewed_surge_only_roundtrip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patterns = {("logical_and", ("ads", "zijieapi.com")), ("domain_keyword", "snssdk.com"),
                        ("protocol", "stun"), ("user_agent", "ttplayer*")}
            MERGE.write_filter_partitions(set(), set(), patterns, root)
            text = (root / "REJECT-RULE-SET.list").read_text()
            rows = [line for line, _ in split_records(text)[1]]
            self.assertTrue(rows[0].startswith("AND,"))
            self.assertEqual(rows[-2:], ["PROTOCOL,STUN", "USER-AGENT,ttplayer*"])
            compiled = root / "REJECT-RULE-SET.json"
            document = json.loads(compiled.read_text())
            self.assertEqual(document["rules"][0]["type"], "logical")
            self.assertNotIn("protocol", compiled.read_text())
            self.assertNotIn("user_agent", compiled.read_text())
            self.assertNotIn("ttplayer", compiled.read_text())
            with redirect_stdout(io.StringIO()):
                self.assertEqual(VERIFY.verify(root / "REJECT-RULE-SET.list", compiled), 0)
            self.assertEqual(sort_list_text(text), text)

    def test_unreviewed_user_agents_and_user_agent_options_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.list"
            for line in ("USER-AGENT,*", "USER-AGENT,TTPLAYER*", "USER-AGENT,other*",
                         "USER-AGENT,ttplayer*,REJECT", "USER-AGENT,ttplayer*,pre-matching"):
                with self.subTest(line=line):
                    path.write_text(line + "\n")
                    with self.assertRaises(ValueError):
                        read_pattern_rules(path)

    def test_missing_user_agent_cannot_pass_supplement_or_manifest_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source").mkdir()
            (root / "metadata").mkdir()
            (root / "source/reject-rule-extra.list").write_text("USER-AGENT,ttplayer*\n")
            (root / "REJECT-DOMAIN-SET.list").write_text("# none\n")
            rules = root / "REJECT-RULE-SET.list"
            rules.write_text("PROTOCOL,STUN\n")
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                VERIFY.verify_supplemental_patterns(root)
            rules.write_text("PROTOCOL,STUN\nUSER-AGENT,ttplayer*\n")
            document = {"schema": 1, "name": "filter", "sources": {}, "outputs": {},
                        "filter": {"surge_only": ["PROTOCOL,STUN"],
                                   "result": {"surge_only": ["PROTOCOL,STUN"]}}}
            manifest = root / "metadata/filter.json"
            manifest.write_text(json.dumps(document))
            with self.assertRaises(SystemExit):
                VERIFY.verify_manifests(root)
            entries = ["PROTOCOL,STUN", "USER-AGENT,ttplayer*"]
            document["filter"] = {"surge_only": entries, "result": {"surge_only": entries}}
            manifest.write_text(json.dumps(document))
            with redirect_stdout(io.StringIO()):
                VERIFY.verify_manifests(root)

    def test_whole_zijieapi_exclusion_keeps_child_blocks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.txt"
            source.write_text("||zijieapi.com^\n||ad.zijieapi.com^\n||mon.zijieapi.com^\n")
            exclusions = root / "exclusions.list"
            exclusions.write_text("zijieapi.com\n")
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                    patch.object(MERGE, "MIN_EXACT", 0), redirect_stdout(io.StringIO()):
                MERGE.build(argparse.Namespace(adblock=[source], domain_exclusions=exclusions,
                                              output_dir=root / "output"))
            actual = VERIFY.parse_list(root / "output/REJECT-DOMAIN-SET.list")
            self.assertNotIn("zijieapi.com", actual["domain_suffix"])
            self.assertEqual(actual["domain_suffix"], {"ad.zijieapi.com", "mon.zijieapi.com"})

if __name__ == "__main__":
    unittest.main()
