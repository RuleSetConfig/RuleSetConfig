"""Regression tests for selecting rules without widening their match scope."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
import json
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from filter_scope import AppScope

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

MERGE = load("scope_merge", "merge-filter.py")
VERIFY = load("scope_verify", "verify-all.py")


class AppScopeTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        p = Path(temp.name) / "scope.json"
        self.data = {"schema": 1, "preserve_manual_supplements": True,
                     "min_selected_domains": 1, "max_selected_domains": 100,
                     "families": [{"id": "test", "roots": ["qq.com", "qimao.com"]}],
                     "explicit_patterns": [["domain_wildcard", "*.adservice.google.*"]]}
        p.write_text(json.dumps(self.data))
        return p

    def test_whole_label_namespace_boundaries(self):
        scope = AppScope(self.fixture())
        self.assertEqual(scope.family("ads.qq.com"), "test")
        self.assertIsNone(scope.family("evilqq.com"))
        self.assertIsNone(scope.family("qq.com.example"))
        self.assertIsNone(scope.family("qqx.com"))

    def test_only_existing_input_matches_survive_without_root_synthesis(self):
        scope = AppScope(self.fixture())
        suffix, exact, patterns, audit = scope.select(
            {"ads.qq.com", "unrelated.example"}, {"exact.qimao.com", "exact.example"},
            {("domain_wildcard", "*.ads.qq.com"), ("domain_wildcard", "*.unrelated.example"),
             ("domain_keyword", "-qmad.qimao.com"), ("domain_keyword", "-slot-"),
             ("domain_wildcard", "*.adservice.google.*"), ("ip_cidr", "192.0.2.1/32")})
        self.assertEqual(suffix, {"ads.qq.com"})
        self.assertEqual(exact, {"exact.qimao.com"})
        self.assertEqual(patterns, {("domain_wildcard", "*.ads.qq.com"),
                         ("domain_keyword", "-qmad.qimao.com"),
                         ("domain_wildcard", "*.adservice.google.*"),
                         ("ip_cidr", "192.0.2.1/32")})
        self.assertEqual(audit["removed"], {"suffix": 1, "exact": 1, "patterns": 2})

    def test_selection_is_idempotent_and_ips_are_unchanged(self):
        scope = AppScope(self.fixture())
        values = ({"a.qq.com", "other.example"}, {"b.qq.com"},
                  {("ip_cidr", "2001:db8::/32"), ("domain_wildcard", "*.ads.qq.com")})
        selected = scope.select(*values)[:3]
        self.assertEqual(scope.select(*selected)[:3], selected)
        self.assertIn(("ip_cidr", "2001:db8::/32"), selected[2])

    def test_unsafe_or_duplicate_roots_and_unpreserved_manuals_fail(self):
        path = self.fixture()
        for roots in (["com"], ["*.qq.com"], ["qq.com", "qq.com"], ["QQ.com"], ["qq..com"]):
            with self.subTest(roots=roots):
                data = dict(self.data, families=[{"id": "test", "roots": roots}])
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    AppScope(path)
        path.write_text(json.dumps(dict(self.data, preserve_manual_supplements=False)))
        with self.assertRaises(ValueError):
            AppScope(path)

    def test_curated_build_preserves_all_97_supplements_and_only_primary_ips(self):
        policy = self.fixture()
        work = policy.parent
        primary, secondary = work / "primary.txt", work / "secondary.txt"
        primary.write_text("||ads.qq.com^\n||unused.example^\n||192.0.2.1^\n")
        secondary.write_text("||report.qq.com^\n||192.0.2.2^\n")
        out = work / "output"
        args = argparse.Namespace(adblock=[primary], domain_only_adblock=[secondary],
            domain_rules=[ROOT / "source/reject-domain-extra.list"],
            pattern_rules=[ROOT / "source/reject-rule-extra.list"],
            app_scope=policy, domain_exclusions=ROOT / "source/reject-domain-exclusions.list",
            output_dir=out)
        with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                patch.object(MERGE, "MIN_EXACT", 0), redirect_stdout(io.StringIO()):
            self.assertEqual(MERGE.build(args), 0)
        (out / "source").mkdir()
        for name in ("reject-domain-extra.list", "reject-rule-extra.list"):
            shutil.copyfile(ROOT / "source" / name, out / "source" / name)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(VERIFY.verify_supplemental_domains(out), 0)
            self.assertEqual(VERIFY.verify_supplemental_patterns(out), 0)
        domains = VERIFY.parse_list(out / "REJECT-DOMAIN-SET.list")
        self.assertNotIn("unused.example", domains["domain_suffix"])
        self.assertIn("ads.qq.com", domains["domain_suffix"])
        self.assertIn("ndcpp.com", domains["domain_suffix"])
        self.assertNotIn("zijieapi.com", domains["domain_suffix"])
        self.assertEqual(VERIFY.parse_list(out / "REJECT-IP-SET.list")["ip_cidr"], {"192.0.2.1/32"})
        rows = [line for line in (out / "REJECT-RULE-SET.list").read_text().splitlines()
                if line and not line.startswith("#")]
        self.assertTrue(rows[0].startswith("AND,") and rows[1].startswith("AND,"))
        self.assertIn("PROTOCOL,STUN", rows)
        self.assertIn("USER-AGENT,ttplayer*", rows)

    def test_full_source_and_selected_size_floors_are_independent(self):
        policy = self.fixture()
        work = policy.parent
        primary = work / "primary.txt"
        primary.write_text("||ads.qq.com^\n||irrelevant.example^\n")
        exclusions = work / "exclusions.list"
        exclusions.write_text("# none\n")
        args = argparse.Namespace(adblock=[primary], app_scope=policy,
            domain_exclusions=exclusions, output_dir=work / "output")
        with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 3), \
                patch.object(MERGE, "MIN_EXACT", 0), redirect_stdout(io.StringIO()), \
                redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MERGE.build(args)
        self.assertFalse((work / "output").exists())
        data = json.loads(policy.read_text())
        data["min_selected_domains"] = 2
        policy.write_text(json.dumps(data))
        with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                patch.object(MERGE, "MIN_EXACT", 0), redirect_stdout(io.StringIO()), \
                redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MERGE.build(args)
        self.assertFalse((work / "output").exists())

    def test_manifest_scope_summary_must_match_the_actual_policy(self):
        policy = self.fixture()
        root = policy.parent
        source = root / "source"
        source.mkdir()
        shutil.copyfile(policy, source / "reject-app-scope.json")
        metadata = root / "metadata"
        metadata.mkdir()
        document = {"schema": 1, "name": "filter", "sources": {}, "outputs": {},
                    "filter": {"result": {"application_scope": AppScope(policy).identity()}}}
        path = metadata / "filter.json"
        path.write_text(json.dumps(document))
        with redirect_stdout(io.StringIO()):
            VERIFY.verify_manifests(root)
        document["filter"]["result"]["application_scope"]["namespace_roots"] += 1
        path.write_text(json.dumps(document))
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            VERIFY.verify_manifests(root)

    def test_workflow_enforces_scope_and_fingerprints_its_inputs(self):
        workflow = (ROOT / ".github/workflows/build-filter.yml").read_text()
        self.assertIn("--app-scope source/reject-app-scope.json", workflow)
        self.assertIn("reject_app_scope|source/reject-app-scope.json|repository:", workflow)
        self.assertIn("filter_scope|scripts/filter_scope.py|repository:", workflow)
        self.assertIn("write_manifest|scripts/write-manifest.py|repository:", workflow)
        self.assertIn("--min-ratio 0.80 --max-ratio 1.25", workflow)
        self.assertIn("Application scope:", workflow)

    def test_repository_policy_has_expected_requested_families(self):
        scope = AppScope(ROOT / "source/reject-app-scope.json")
        self.assertEqual(scope.family("ad.qznovelvod.com"), "bytedance-reading-drama")
        self.assertEqual(scope.family("ad.wtzw.com"), "qimao")
        self.assertEqual(scope.family("telemetry.microsoft.com"), "microsoft")
        self.assertIsNone(scope.family("random.cloudfront.net"))
        self.assertIsNone(scope.family("long-tail-shop.example"))
        self.assertEqual(scope.identity()["frequency_evidence"], "not-measured")

if __name__ == "__main__":
    unittest.main()
