import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("merge_filter", ROOT / "scripts" / "merge-filter.py")
MERGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE)


class FilterPipelineTests(unittest.TestCase):
    def test_parent_lookup_uses_label_boundaries(self):
        self.assertEqual(MERGE.parent_of("safe.ads.example.com", {"example.com"}), "example.com")
        self.assertIsNone(MERGE.parent_of("notexample.com", {"example.com"}))

    def test_allow_rules_survive_a_broader_block_rule(self):
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

    def test_exception_removes_every_covering_suffix(self):
        covered = MERGE.exception_covered_suffixes({"safe.ads.example.com"})
        self.assertEqual(
            covered,
            {"safe.ads.example.com", "ads.example.com", "example.com"},
        )

    def test_apply_exceptions_prefers_false_negatives_to_false_positives(self):
        suffix, exact = MERGE.apply_exceptions(
            {"example.com", "unrelated.example"},
            {"safe.example.com", "child.allowed.example", "blocked.example"},
            {"allowed.example"},
            {"safe.example.com"},
        )
        self.assertEqual(suffix, {"unrelated.example"})
        self.assertEqual(exact, {"blocked.example"})


if __name__ == "__main__":
    unittest.main()
