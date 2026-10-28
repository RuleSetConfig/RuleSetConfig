"""Reject incomplete public releases before native checks or publication."""
from contextlib import contextmanager, redirect_stderr
import io
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("contract_verify", ROOT / "scripts/verify-all.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class RepositoryContractTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "metadata").mkdir()
        for extension in ("*.list", "*.srs"):
            for source in ROOT.glob(extension):
                (root / source.name).touch()
        for source in (ROOT / "metadata").glob("*.json"):
            shutil.copyfile(source, root / "metadata" / source.name)
        return root

    @contextmanager
    def rejected(self, message):
        with redirect_stderr(io.StringIO()) as diagnostic:
            with self.assertRaises(SystemExit) as caught:
                yield
        self.assertEqual(caught.exception.code, 1)
        self.assertRegex(diagnostic.getvalue(), message)

    def mutate(self, root, name, change):
        path = root / "metadata" / (name + ".json")
        document = json.loads(path.read_text())
        change(document)
        path.write_text(json.dumps(document))

    def test_complete_public_layout_is_accepted(self):
        self.assertEqual(VERIFY.verify_repository_contract(self.fixture()), 0)

    def test_missing_paired_files_cannot_disappear_together(self):
        root = self.fixture()
        for extension in ("list", "srs"):
            (root / ("PROXY-RULE-SET." + extension)).unlink()
        with self.rejected("PROXY-RULE-SET"):
            VERIFY.verify_repository_contract(root)

    def test_extra_pair_is_not_a_public_partition(self):
        root = self.fixture()
        for extension in ("list", "srs"):
            (root / ("legacy-filter." + extension)).touch()
        with self.rejected("legacy-filter"):
            VERIFY.verify_repository_contract(root)

    def test_each_manifest_is_required(self):
        for name in ("filter", "tld", "keywords", "direct-ip", "proxy-ip"):
            with self.subTest(name=name):
                root = self.fixture()
                (root / "metadata" / (name + ".json")).unlink()
                with self.rejected(name):
                    VERIFY.verify_repository_contract(root)

    def test_manifest_cannot_claim_a_different_partition(self):
        root = self.fixture()
        self.mutate(root, "tld", lambda d: d.update(name="keywords"))
        with self.rejected("identity"):
            VERIFY.verify_repository_contract(root)

    def test_every_output_fingerprint_is_required(self):
        root = self.fixture()
        self.mutate(root, "tld", lambda d: d["outputs"].pop("PROXY-DOMAIN-SET.srs"))
        with self.rejected("output contract"):
            VERIFY.verify_repository_contract(root)

    def test_output_cannot_escape_the_release_inventory(self):
        root = self.fixture()
        self.mutate(root, "tld", lambda d: d["outputs"].update({"../other.srs": {}}))
        with self.rejected("output contract"):
            VERIFY.verify_repository_contract(root)

    def test_keyword_source_fingerprint_cannot_be_deleted(self):
        root = self.fixture()
        self.mutate(root, "tld", lambda d: d["sources"].pop("inline_keywords"))
        with self.rejected("source fingerprints"):
            VERIFY.verify_repository_contract(root)

    def test_policy_fingerprint_cannot_be_redirected_to_another_file(self):
        root = self.fixture()
        self.mutate(root, "tld", lambda d: d["sources"]["inline_keywords"].update(
            url="repository:source/proxy-custom.list"))
        with self.rejected("source identity"):
            VERIFY.verify_repository_contract(root)

    def test_external_provenance_and_compiler_are_required(self):
        for change in (lambda d: d["sources"].pop("apnic_md5"),
                       lambda d: d.pop("generator"),
                       lambda d: d["sources"]["apnic"].update(sha256=""),
                       lambda d: d["sources"]["apnic"].update(bytes=-1),
                       lambda d: d["sources"]["apnic"].pop("url")):
            with self.subTest(change=change):
                root = self.fixture()
                self.mutate(root, "direct-ip", change)
                with self.assertRaises(SystemExit):
                    VERIFY.verify_repository_contract(root)

    def test_filter_source_roles_cannot_reintroduce_nonprimary_ips(self):
        root = self.fixture()
        self.mutate(root, "filter", lambda d: d["filter"]["result"]["source_roles"].update(
            {"filter_2.txt": "domains-patterns-and-ips"}))
        with self.rejected("source roles"):
            VERIFY.verify_repository_contract(root)

    def test_application_scope_fingerprint_and_identity_are_required(self):
        for change in (lambda d: d["filter"]["result"].pop("application_scope"),
                       lambda d: d["filter"]["result"]["application_scope"].update(policy_sha256="0" * 64),
                       lambda d: d["filter"]["result"]["application_scope"].update(manual_supplements="filtered")):
            with self.subTest(change=change):
                root = self.fixture()
                self.mutate(root, "filter", change)
                with self.rejected("application scope"):
                    VERIFY.verify_repository_contract(root)

    def test_missing_manifest_stops_full_cli_before_native_execution(self):
        root = self.fixture()
        (root / "metadata/keywords.json").unlink()
        with patch.object(sys, "argv", ["verify-all.py", "--root", str(root)]), \
                patch.object(VERIFY.subprocess, "run") as native:
            with self.rejected("manifest contract"):
                VERIFY.main()
            native.assert_not_called()

    def test_single_candidate_mode_remains_independent_of_full_repository(self):
        root = self.fixture()
        source = root / "candidate.list"
        source.write_text("DOMAIN,exact.example\n")
        decoded = root / "candidate.json"
        decoded.write_text(json.dumps({"version": 5, "rules": [{"domain": ["exact.example"]}]}))
        with patch.object(sys, "argv", ["verify-all.py", "--list", str(source), "--decompiled", str(decoded)]):
            self.assertEqual(VERIFY.main(), 0)


if __name__ == "__main__":
    unittest.main()
