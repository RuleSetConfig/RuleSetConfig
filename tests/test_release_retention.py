"""Verify that historical Releases are removed only after the retained assets pass."""

from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_retention", ROOT / "scripts/prune-releases.py")
RETENTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETENTION)


class ReleaseRetentionTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        for name in RETENTION.ASSETS - {"SHA256SUMS"}:
            (directory / name).write_bytes(("Verified " + name + "\n").encode())
        lines = [hashlib.sha256((directory / name).read_bytes()).hexdigest() + "  " + name
                 for name in sorted(RETENTION.ASSETS - {"SHA256SUMS"})]
        (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        assets = [{"name":name, "state":"uploaded", "size":(directory / name).stat().st_size,
                   "digest":"sha256:" + hashlib.sha256((directory / name).read_bytes()).hexdigest()}
                  for name in sorted(RETENTION.ASSETS)]
        releases = [{"id":i, "tag_name":"rulesets-" + str(i), "draft":False,
                     "published_at":f"2026-10-28T10:0{i}:00Z", "assets":assets if i == 4 else []}
                    for i in range(1, 5)]
        return directory, releases

    def client(self, releases, fail_id=None):
        calls = []
        def api(method, path):
            calls.append((method, path))
            if method == "GET":
                return list(releases)
            release_id = int(path.rsplit("/", 1)[1])
            if release_id == fail_id:
                raise RuntimeError("Removal refused.")
            releases[:] = [release for release in releases if release["id"] != release_id]
        return api, calls

    def test_only_newest_verified_publication_is_retained(self):
        directory, releases = self.fixture()
        api, calls = self.client(releases)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(RETENTION.prune(api, "owner/repository", "rulesets-4", directory), 3)
        self.assertEqual([release["id"] for release in releases], [4])
        self.assertEqual([path.rsplit("/", 1)[1] for method, path in calls if method == "DELETE"], ["1", "2", "3"])

    def test_missing_draft_or_older_retained_release_prevents_removal(self):
        directory, releases = self.fixture()
        for tag in ("missing", "rulesets-1"):
            api, calls = self.client(releases)
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                RETENTION.prune(api, "owner/repository", tag, directory)
            self.assertFalse(any(method == "DELETE" for method, _ in calls))
        releases[-1]["draft"] = True
        with self.assertRaises(ValueError):
            RETENTION.deletion_plan(releases, "rulesets-4")

    def test_unpublished_drafts_are_preserved(self):
        directory, releases = self.fixture()
        releases.append({"id":99,"tag_name":"future-draft","draft":True,"published_at":None})
        api, calls = self.client(releases)
        with redirect_stdout(io.StringIO()):
            RETENTION.prune(api, "owner/repository", "rulesets-4", directory)
        self.assertEqual([release["id"] for release in releases], [4, 99])

    def test_missing_or_corrupt_download_prevents_any_removal(self):
        for damage in ("missing", "corrupt"):
            directory, releases = self.fixture()
            asset = directory / "DIRECT-RULE-SET.srs"
            if damage == "missing":
                asset.unlink()
            else:
                asset.write_bytes(b"corrupt")
            api, calls = self.client(releases)
            with self.subTest(damage=damage), self.assertRaises(ValueError):
                RETENTION.prune(api, "owner/repository", "rulesets-4", directory)
            self.assertFalse(any(method == "DELETE" for method, _ in calls))

    def test_remote_inventory_and_digest_must_match(self):
        for damage in ("digest", "state", "missing"):
            directory, releases = self.fixture()
            assets = releases[-1]["assets"]
            if damage == "missing":
                assets.pop()
            elif damage == "digest":
                assets[0]["digest"] = "sha256:" + "0" * 64
            else:
                assets[0]["state"] = "new"
            api, calls = self.client(releases)
            with self.subTest(damage=damage), self.assertRaises(ValueError):
                RETENTION.prune(api, "owner/repository", "rulesets-4", directory)
            self.assertFalse(any(method == "DELETE" for method, _ in calls))

    def test_api_failure_stops_further_removal(self):
        directory, releases = self.fixture()
        api, calls = self.client(releases, fail_id=2)
        with redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            RETENTION.prune(api, "owner/repository", "rulesets-4", directory)
        self.assertEqual([release["id"] for release in releases], [2, 3, 4])
        self.assertFalse(any(path.endswith("/3") or path.endswith("/4") for method, path in calls if method == "DELETE"))

    def test_pagination_collects_the_complete_inventory(self):
        pages = {1:[{"id":i} for i in range(100)], 2:[{"id":100}]}
        def api(method, path):
            return pages[int(path.rsplit("=", 1)[1])]
        self.assertEqual(len(RETENTION.list_releases(api, "owner/repository")), 101)

    def test_workflow_verifies_uploads_before_retention(self):
        text = (ROOT / ".github/workflows/publish-release.yml").read_text()
        self.assertLess(text.index("- name: Verify uploaded Release assets"),
                        text.index("- name: Retain only the latest verified Release"))
        self.assertIn("cmp -- release-assets/SHA256SUMS", text)
        self.assertIn("sha256sum --check SHA256SUMS", text)
        self.assertIn("--verified-directory", text)


if __name__ == "__main__":
    unittest.main()
