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
from domainclass import is_domestic, load_brands


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

    def test_remove_exception_matches_keeps_wider_block_parent(self):
        suffix, exact = MERGE.remove_exception_matches(
            {"example.com", "safe.example.com"},
            {"safe.example.com", "child.allowed.example", "blocked.example"},
            {"safe.example.com", "allowed.example"},
            {"exact.example"},
        )
        self.assertEqual(suffix, {"example.com"})
        self.assertEqual(exact, {"blocked.example"})

    def test_split_exceptions_is_exhaustive_and_disjoint(self):
        brands = {"bilibili"}
        original_suffix = {"bilibili.com", "example.net", "service.cn"}
        original_exact = {"api.bilibili.com", "host.example.org"}
        direct, proxy = MERGE.split_exceptions(original_suffix, original_exact, brands)
        direct_suffix, direct_exact = direct
        proxy_suffix, proxy_exact = proxy
        for domain in original_suffix | original_exact:
            direct_match = (domain in direct_exact or domain in direct_suffix or
                            MERGE.parent_of(domain, direct_suffix) is not None)
            proxy_match = (domain in proxy_exact or domain in proxy_suffix or
                           MERGE.parent_of(domain, proxy_suffix) is not None)
            self.assertNotEqual(direct_match, proxy_match)
        self.assertFalse(direct_suffix & proxy_suffix)
        self.assertFalse(direct_exact & proxy_exact)
        self.assertFalse(MERGE.route_overlap(*direct, *proxy))

    def test_committed_exception_sets_match_the_route_policy(self):
        brands = load_brands(ROOT / "source" / "china-brands.txt")

        def rules(name):
            suffix, exact = set(), set()
            with open(ROOT / name, encoding="utf-8") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    (suffix if line.startswith(".") else exact).add(line.lstrip("."))
            return suffix, exact

        direct = rules("filter-allow-direct.list")
        proxy = rules("filter-allow-proxy.list")
        direct_domains = direct[0] | direct[1]
        proxy_domains = proxy[0] | proxy[1]
        self.assertTrue(direct_domains)
        self.assertTrue(proxy_domains)
        self.assertFalse(MERGE.route_overlap(*direct, *proxy))
        self.assertTrue(all(is_domestic(domain, brands) for domain in direct_domains))
        self.assertTrue(all(not is_domestic(domain, brands) for domain in proxy_domains))


if __name__ == "__main__":
    unittest.main()
