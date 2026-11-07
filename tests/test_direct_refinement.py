"""Exercise direct coalescing, registration boundaries and proxy fallbacks."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from direct_refinement import refine_direct


class DirectRefinementTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "source").mkdir()
        data = b"com\ncn.com\nco.uk\ngithub.io\n*.ck\n!www.ck\n"
        (root / "source/public-suffix-list.dat").write_bytes(data)
        plan = {"direct_refinement": {"public_suffix_list": {
            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}}}
        return root, plan

    def test_second_level_suffixes_cover_children_without_substring_matching(self):
        root, plan = self.fixture()
        result, audit = refine_direct({"cdn.qq.com", "img.qq.com", "qq.com", "notqq.com"},
                                      root, plan)
        self.assertEqual(result, {"qq.com", "notqq.com"})
        self.assertEqual(len(audit["promoted"]), 2)

    def test_public_suffixes_and_wildcards_retain_original_domains(self):
        root, plan = self.fixture()
        originals = {"tenant.cn.com", "service.co.uk", "tenant.github.io", "a.foo.ck"}
        result, audit = refine_direct(originals | {"a.www.ck"}, root, plan)
        self.assertEqual(result, originals | {"www.ck"})
        self.assertEqual({r["reason"] for r in audit["retained_original"]}, {"public-suffix"})

    def test_proxy_descendants_apexes_and_keywords_prevent_promotion(self):
        root, plan = self.fixture()
        originals = {"cdn.shared.example", "cdn.apex.example", "cdn.python-services.example"}
        result, audit = refine_direct(originals | {"cdn.clean.example"}, root, plan,
                                      {"proxy.shared.example"}, {"apex.example"}, ["python"])
        self.assertEqual(result, originals | {"clean.example"})
        self.assertEqual(len(audit["retained_original"]), 3)

    def test_public_suffix_snapshot_must_match_its_recorded_fingerprint(self):
        root, plan = self.fixture()
        (root / "source/public-suffix-list.dat").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            refine_direct({"cdn.qq.com"}, root, plan)


if __name__ == "__main__":
    unittest.main()
