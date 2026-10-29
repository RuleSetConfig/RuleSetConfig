"""Protect imported domain scope, policy separation and fixed selection budgets."""

from collections import Counter
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("companion_import", ROOT / "scripts/import-companion-domains.py")
IMPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORT)


class CompanionImportTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "PROXY-DOMAIN-SET.list").write_text(".io\n")
        (root / "DIRECT-DOMAIN-SET.list").write_text(".cn\n")
        (root / "REJECT-DOMAIN-SET.list").write_text(".blocked.example\n")
        (root / "REJECT-RULE-SET.list").write_text("DOMAIN-KEYWORD,adservice\n")
        for policy in ("proxy", "direct"):
            values = [f".seed{policy}.example", f".preferred{policy}.example"]
            values += [f".{policy}{number}.example" for number in range(8)]
            values += [f".child.{policy}0.example", ".conflict.example", ".blocked.example",
                       ".adservice.example", ".python.example", ".weixin.example",
                       ".already.io", ".already.cn", "exact-only.example",
                       ".preferred" + ("direct" if policy == "proxy" else "proxy") + ".example"]
            if policy == "direct": values += [".child.conflict.example"]
            (root / (policy + ".txt")).write_text("\n".join(values) + "\n")
        with tarfile.open(root / "community.tar.gz", "w:gz") as archive:
            for policy in ("proxy", "direct"):
                data = f"preferred{policy}.example\n".encode()
                member = tarfile.TarInfo("snapshot/data/" + policy)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        plan = {"sources": {"proxy": {"file": "proxy.txt"}, "direct": {"file": "direct.txt"},
                            "community": {"file": "community.tar.gz"}},
                "application_groups": {p: [p] for p in ("proxy", "direct")},
                "vendor_suffixes": {"proxy": {}, "direct": {}},
                "seed_suffixes": {p: [f"seed{p}.example"] for p in ("proxy", "direct")},
                "rule_counts": {"proxy": 5, "direct": 5}}
        document = {"proxy": ["python"], "direct": ["weixin"]}
        return root, plan, document

    def test_exact_regex_keywords_and_tagged_domains_are_never_widened(self):
        data = {"app": "good.example\nfull:exact.example\nregexp:^pattern$\nkeyword:short\n"
                       "ads.example @ads\ntelemetry.example @telemetry\ncn.example @cn\n"
                       "include:child\ninclude:filtered @cn\n",
                "child": "child.example\n"}
        audit = Counter()
        self.assertEqual(IMPORT.read_group(data, "app", "proxy", audit),
                         {"good.example", "child.example"})
        self.assertEqual(audit["non_suffix_records_omitted"], 3)
        self.assertEqual(audit["tagged_records_omitted"], 3)
        self.assertEqual(audit["attribute_filtered_includes_omitted"], 1)
        with self.assertRaisesRegex(ValueError, "circular"):
            IMPORT.read_group({"app": "include:app"}, "app", "proxy", Counter())

    def test_selection_has_bounded_scope_and_keeps_preferred_services(self):
        root, plan, document = self.fixture()
        selected, audit = IMPORT.select(root, plan, root, document)
        for policy, selection in selected.items():
            suffixes = selection["suffixes"]
            self.assertEqual(len(suffixes) + len(document[policy]), 5)
            self.assertIn(f"seed{policy}.example", suffixes)
            self.assertIn(f"preferred{policy}.example", suffixes)
            self.assertFalse({"conflict.example", "child.conflict.example", "blocked.example",
                              "python.example", "weixin.example", "adservice.example",
                              "already.io", "already.cn", "exact-only.example"} & set(suffixes))
            self.assertNotIn(f"child.{policy}0.example", suffixes)
            self.assertGreater(audit[policy]["cross_policy_conflicts_omitted"], 0)
        again, _ = IMPORT.select(root, plan, root, document)
        self.assertEqual(selected, again)

    def test_reject_companion_hostname_rules_keep_their_matching_scope(self):
        root, plan, document = self.fixture()
        (root / "REJECT-RULE-SET.list").write_text(
            "DOMAIN-SUFFIX,proxy0.example\nDOMAIN-SUFFIX,direct0.example\n"
            "DOMAIN,preferreddirect.example\nDOMAIN-KEYWORD,adservice\n")
        selected, audit = IMPORT.select(root, plan, root, document)
        for policy in ("proxy", "direct"):
            self.assertNotIn(policy + "0.example", selected[policy]["suffixes"])
            self.assertNotIn("child." + policy + "0.example", selected[policy]["suffixes"])
            self.assertGreater(audit[policy]["rejection_covered"], 0)
        # An exact reject does not cover every child of a routing suffix.
        self.assertIn("preferreddirect.example", selected["direct"]["suffixes"])

    def test_ranked_hostnames_fill_only_exact_slots_and_keep_rank_order(self):
        root, plan, document = self.fixture()
        (root / "ranking.csv").write_text("rank,domain\n" + "".join(
            f"{i + 1},www{i}.catalogue.example\n" for i in range(30)))
        plan["sources"]["ranking"] = {"file": "ranking.csv"}
        plan["rule_counts"]["proxy"] = 20
        selected, _ = IMPORT.select(root, plan, root, document)
        suffixes = selected["proxy"]["suffixes"]
        exact = selected["proxy"]["domains"]
        self.assertTrue(exact)
        self.assertIn("www0.catalogue.example", exact)
        self.assertNotIn("www0.catalogue.example", suffixes)
        self.assertEqual(len(suffixes) + len(exact) + len(document["proxy"]), 20)
        self.assertFalse(any(host.startswith("child.") for host in exact))

    def test_insufficient_independent_domains_fail_instead_of_padding(self):
        root, plan, document = self.fixture()
        plan["rule_counts"]["direct"] = 10000
        with self.assertRaisesRegex(ValueError, "insufficient non-redundant direct"):
            IMPORT.select(root, plan, root, document)

    def test_pinned_cache_is_checked_before_it_is_used(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "proxy.txt").write_text("tampered\n")
        plan = {"sources": {"proxy": {"file": "proxy.txt", "bytes": 2, "sha256": "0" * 64}}}
        with self.assertRaisesRegex(ValueError, "fingerprint differs"):
            IMPORT.fetch_sources(plan, root)


if __name__ == "__main__":
    unittest.main()
