"""Exercise candidate coverage changes, reproducibility and failed publication."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from domain_keywords import KEYWORD_SOURCE, read_inline_keywords

SPEC = importlib.util.spec_from_file_location("tested_companion_refresh", ROOT / "scripts/refresh-companions.py")
REFRESH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFRESH)


class CompanionRefreshTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "repository"
        upstream, candidate = root.parent / "upstream", root.parent / "candidate"
        (root / "source").mkdir(parents=True)
        (root / "scripts").mkdir()
        upstream.mkdir()
        shutil.copyfile(ROOT / "scripts/import-companion-domains.py", root / "scripts/import-companion-domains.py")
        (root / "PROXY-DOMAIN-SET.list").write_text(".io\n")
        (root / "DIRECT-DOMAIN-SET.list").write_text(".cn\n")
        (root / "REJECT-DOMAIN-SET.list").write_text(".blocked.example\n")
        (root / "REJECT-RULE-SET.list").write_text("DOMAIN-KEYWORD,adservice\n")
        for policy in ("PROXY", "DIRECT"):
            (root / (policy + "-DOMAIN-SET.srs")).write_bytes(b"TLD fixture")
        for policy in ("proxy", "direct"):
            (upstream / (policy + ".txt")).write_text("".join(
                f".{policy}{number}.example\n" for number in range(8)))
        with tarfile.open(upstream / "community.tar.gz", "w:gz") as archive:
            member = tarfile.TarInfo("snapshot/data/app")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"\n"))
        plan = {"sources": {}, "application_groups": {p: ["app"] for p in ("proxy", "direct")},
                "vendor_suffixes": {p: {} for p in ("proxy", "direct")},
                "seed_suffixes": {p: [] for p in ("proxy", "direct")},
                "rule_counts": {p: 5 for p in ("proxy", "direct")}}
        for name, filename in (("proxy", "proxy.txt"), ("direct", "direct.txt"), ("community", "community.tar.gz")):
            plan["sources"][name] = {"file": filename, **REFRESH.BUILDER.digest(upstream / filename)}
        (root / "source/companion-import.json").write_text(json.dumps(plan))
        initial = {"schema": 3, "proxy": ["python"], "direct": ["weixin"],
                   "proxy_domain_suffixes": [], "direct_domain_suffixes": [],
                   "proxy_domains": [], "direct_domains": [], "rule_counts": plan["rule_counts"]}
        (root / KEYWORD_SOURCE).write_text(json.dumps(initial))
        self.run_refresh(root, candidate, upstream, initial=True)
        shutil.copyfile(candidate / KEYWORD_SOURCE, root / KEYWORD_SOURCE)
        shutil.rmtree(candidate)
        self.write_tld_manifest(root, root)
        return root, candidate, upstream

    def write_tld_manifest(self, directory, root):
        outputs = {}
        for policy in ("PROXY", "DIRECT"):
            for extension in (".list", ".srs"):
                name = policy + "-DOMAIN-SET" + extension
                path = directory / name if (directory / name).is_file() else root / name
                outputs[name] = REFRESH.BUILDER.digest(path)
        document = {"outputs": outputs, "sources": {"inline_keywords": {}},
                    "domain_sync": {"inline_keywords": {"proxy": ["python"], "direct": ["weixin"]}}}
        (directory / "metadata").mkdir(exist_ok=True)
        (directory / "metadata/tld.json").write_text(json.dumps(document))

    def fake_build(self, stage, built, sing_box):
        read_inline_keywords(stage)
        (built / "metadata").mkdir(parents=True)
        for name in REFRESH.PAIRS:
            for extension in (".list", ".srs"):
                (built / (name + extension)).write_bytes(b"compiled fixture")
        (built / "metadata/keywords.json").write_text("{}")

    def run_refresh(self, root, candidate, upstream, initial=False):
        if initial:
            self.write_tld_manifest(root, root)
        with patch.object(REFRESH.BUILDER, "build", side_effect=self.fake_build):
            return REFRESH.refresh(root, candidate, upstream)

    def test_new_tld_coverage_replaces_rules_without_changing_the_repository(self):
        root, candidate, upstream = self.fixture()
        before = (root / KEYWORD_SOURCE).read_bytes()
        selected = json.loads(before)["proxy_domain_suffixes"][0]
        candidate.mkdir()
        (candidate / "PROXY-DOMAIN-SET.list").write_text(".io\n." + selected + "\n")
        self.write_tld_manifest(candidate, root)
        (candidate / "domain-sync-audit.json").write_text(json.dumps({"sources": {"inline_keywords": {}}}))
        audit = self.run_refresh(root, candidate, upstream)
        after = json.loads((candidate / KEYWORD_SOURCE).read_text())
        self.assertNotIn(selected, after["proxy_domain_suffixes"])
        self.assertEqual(len(after["proxy_domain_suffixes"]) + len(after["proxy"]), 5)
        self.assertEqual(audit["changes"]["proxy"]["domain_suffixes"]["removed"], [selected])
        self.assertEqual((root / KEYWORD_SOURCE).read_bytes(), before)
        tld = json.loads((candidate / "metadata/tld.json").read_text())
        self.assertEqual(tld["sources"]["inline_keywords"]["sha256"], hashlib.sha256(
            (candidate / KEYWORD_SOURCE).read_bytes()).hexdigest())
        evidence = json.loads((candidate / "domain-sync-audit.json").read_text())
        self.assertEqual(evidence["sources"]["inline_keywords"], tld["sources"]["inline_keywords"])

    def test_reject_changes_refill_both_policies_before_publication(self):
        root, candidate, upstream = self.fixture()
        document = json.loads((root / KEYWORD_SOURCE).read_text())
        blocked = {document[p + "_domain_suffixes"][0] for p in ("proxy", "direct")}
        candidate.mkdir()
        (candidate / "REJECT-RULE-SET.list").write_text("".join(
            "DOMAIN-SUFFIX," + host + "\n" for host in sorted(blocked)))
        audit = self.run_refresh(root, candidate, upstream)
        selected = json.loads((candidate / KEYWORD_SOURCE).read_text())
        for policy in ("proxy", "direct"):
            self.assertFalse(blocked & set(selected[policy + "_domain_suffixes"]))
            self.assertEqual(audit["selection"][policy]["total_rules"], 5)
            self.assertTrue(audit["changes"][policy]["domain_suffixes"]["added"])

    def test_unchanged_inputs_reproduce_the_same_selection_and_outputs(self):
        root, candidate, upstream = self.fixture()
        audit = self.run_refresh(root, candidate, upstream)
        files = [KEYWORD_SOURCE, "metadata/tld.json", "metadata/keywords.json", "companion-sync-audit.json"]
        before = {name: (candidate / name).read_bytes() for name in files}
        self.assertEqual((candidate / KEYWORD_SOURCE).read_bytes(), (root / KEYWORD_SOURCE).read_bytes())
        self.run_refresh(root, candidate, upstream)
        self.assertEqual(before, {name: (candidate / name).read_bytes() for name in files})
        self.assertFalse(audit["changes"]["proxy"]["domain_suffixes"]["added"])

    def test_failed_projection_leaves_existing_candidates_untouched(self):
        root, candidate, upstream = self.fixture()
        candidate.mkdir()
        (candidate / "PROXY-RULE-SET.list").write_text("existing candidate\n")
        before = (root / KEYWORD_SOURCE).read_bytes()
        with patch.object(REFRESH.BUILDER, "build", side_effect=ValueError("projection failed")):
            with self.assertRaisesRegex(ValueError, "projection failed"):
                REFRESH.refresh(root, candidate, upstream)
        self.assertEqual((candidate / "PROXY-RULE-SET.list").read_text(), "existing candidate\n")
        self.assertFalse((candidate / KEYWORD_SOURCE).exists())
        self.assertEqual((root / KEYWORD_SOURCE).read_bytes(), before)

    def test_incomplete_tld_pair_fails_before_reselection(self):
        root, candidate, upstream = self.fixture()
        candidate.mkdir()
        (candidate / "PROXY-DOMAIN-SET.list").write_text(".changed\n")
        with self.assertRaisesRegex(ValueError, "candidate TLD fingerprint differs"):
            REFRESH.refresh(root, candidate, upstream)
        self.assertFalse((candidate / KEYWORD_SOURCE).exists())

    def test_cached_source_corruption_prevents_all_new_outputs(self):
        root, candidate, upstream = self.fixture()
        (upstream / "proxy.txt").write_text("tampered\n")
        import subprocess
        with self.assertRaises(subprocess.CalledProcessError):
            REFRESH.refresh(root, candidate, upstream)
        self.assertFalse(candidate.exists())


if __name__ == "__main__":
    unittest.main()
