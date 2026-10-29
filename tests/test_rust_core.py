"""Cross-check Rust projection against independent Python policy validation."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from domain_keywords import read_inline_keywords, read_companion_suffixes, read_companion_domains
from rust_core import binary, generate


class RustProjectionTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "source").mkdir()
        (root / "PROXY-DOMAIN-SET.list").write_text(".io\n")
        (root / "DIRECT-DOMAIN-SET.list").write_text(".cn\n")
        policy = {"schema": 3, "proxy": ["python"], "direct": ["weixin"],
                  "proxy_domain_suffixes": ["7-zip.org"], "direct_domain_suffixes": ["qq.com"],
                  "proxy_domains": ["ranked.scope.example"], "direct_domains": [],
                  "rule_counts": {"proxy": 3, "direct": 2}}
        return root, policy

    def write(self, root, policy):
        (root / "source/domain-keywords.json").write_text(json.dumps(policy))

    def test_exact_and_suffix_fields_agree_with_python_validation(self):
        root, policy = self.fixture()
        self.write(root, policy)
        summary = generate(root, root / "output")
        self.assertEqual(summary["keywords"], {p: list(v) for p, v in read_inline_keywords(root).items()})
        self.assertEqual(summary["domain_suffixes"], {p: list(v) for p, v in read_companion_suffixes(root).items()})
        self.assertEqual(summary["domains"], {p: list(v) for p, v in read_companion_domains(root).items()})
        document = json.loads((root / "output/PROXY-RULE-SET.json").read_text())
        self.assertIn({"domain": ["ranked.scope.example"]}, document["rules"])
        self.assertNotIn({"domain_suffix": ["ranked.scope.example"]}, document["rules"])

    def test_redundancy_conflicts_unknown_fields_and_counts_fail_in_both(self):
        for index, mutation in enumerate((
            lambda d: d["proxy_domains"].append("child.7-zip.org"),
            lambda d: d["direct_domain_suffixes"].append("child.7-zip.org"),
            lambda d: d["proxy_domains"].append("covered.io"),
            lambda d: d.update(unexpected=True),
            lambda d: d["rule_counts"].update(proxy=99),
        )):
            root, policy = self.fixture()
            mutation(policy)
            if index < 3:
                policy["rule_counts"] = {p: len(policy[p]) + len(policy[p + "_domain_suffixes"]) +
                                         len(policy[p + "_domains"]) for p in ("proxy", "direct")}
            self.write(root, policy)
            with self.assertRaises(ValueError):
                read_inline_keywords(root)
            result = subprocess.run([str(binary()), "--root", str(root), "--output-dir", str(root / "output")],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(list((root / "output").glob("*.list")))

    def test_legacy_source_schemas_remain_supported(self):
        for schema in (1, 2):
            root, _ = self.fixture()
            policy = {"schema": schema, "proxy": ["python"], "direct": ["weixin"]}
            if schema == 2:
                policy.update(proxy_domain_suffixes=[], direct_domain_suffixes=[],
                              rule_counts={"proxy": 1, "direct": 1})
            self.write(root, policy)
            summary = generate(root, root / "output")
            self.assertEqual(summary["keywords"]["proxy"], list(read_inline_keywords(root)["proxy"]))

    def test_committed_lists_are_byte_identical_to_rust_projection(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)
        generate(ROOT, output)
        for name in ("PROXY-RULE-SET.list", "DIRECT-RULE-SET.list"):
            self.assertEqual((ROOT / name).read_bytes(), (output / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
