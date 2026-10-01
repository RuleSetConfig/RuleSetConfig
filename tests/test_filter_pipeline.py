import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("merge_filter", ROOT / "scripts" / "merge-filter.py")
MERGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE)


class FilterPipelineTests(unittest.TestCase):
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
                "||ads.example.com^\n@@||ads.example.com^\n" +
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
            self.assertFalse((output / "filter-allow-direct.list").exists())
            self.assertFalse((output / "filter-allow-proxy.list").exists())


if __name__ == "__main__":
    unittest.main()
