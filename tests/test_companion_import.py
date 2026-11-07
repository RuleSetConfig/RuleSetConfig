"""Protect imported domain scope, policy separation and fixed selection budgets."""

from collections import Counter
import importlib.util
import io
import json
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

    def test_process_names_reserve_slots_in_the_fixed_budget(self):
        root, plan, document = self.fixture()
        document.update(proxy_process_names=["netbiosd", "trustd"], direct_process_names=[])
        selected, audit = IMPORT.select(root, plan, root, document)
        for policy, selection in selected.items():
            self.assertEqual(len(selection["suffixes"]) + len(selection["domains"])
                             + len(document[policy]) + len(document[policy + "_process_names"]), 5)
        self.assertEqual(audit["proxy"]["retained_process_names"], 2)
        self.assertEqual(document["proxy_process_names"], ["netbiosd", "trustd"])

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

    def test_uncapped_brand_scope_keeps_reviewed_suffixes_and_omits_generic_pool(self):
        root, plan, document = self.fixture()
        self.brand_scope(root, "proxy7.example")
        plan.update(app_scope="source/reject-app-scope.json", selection_scope="reviewed-brands",
                    rule_counts={"proxy": None, "direct": None})
        selected, audit = IMPORT.select(root, plan, root, document)
        self.assertEqual(set(selected["proxy"]["suffixes"]),
                         {"seedproxy.example", "preferredproxy.example", "proxy7.example"})
        self.assertEqual(set(selected["direct"]["suffixes"]),
                         {"seeddirect.example", "preferreddirect.example"})
        self.assertGreater(audit["proxy"]["outside_reviewed_brand_scope"], 0)

    def test_uncapped_brand_scope_retains_related_exact_hosts_without_padding(self):
        root, plan, document = self.fixture()
        self.brand_scope(root, "brand.example")
        plan.update(app_scope="source/reject-app-scope.json", selection_scope="reviewed-brands",
                    rule_counts={"proxy": None, "direct": None})
        (root / "ranking.csv").write_text("rank,domain\n1,generic.example\n2,one.brand.example\n")
        plan["sources"]["ranking"] = {"file": "ranking.csv"}
        selected, _ = IMPORT.select(root, plan, root, document)
        self.assertEqual(selected["proxy"]["domains"], ["one.brand.example"])
        self.assertNotIn("brand.example", selected["proxy"]["suffixes"])

    def test_uncapped_direct_selection_keeps_the_eligible_pool_without_padding(self):
        root, plan, document = self.fixture()
        plan["rule_counts"]["direct"] = None
        selected, audit = IMPORT.select(root, plan, root, document)
        actual = len(selected["direct"]["suffixes"]) + len(document["direct"])
        self.assertGreater(actual, 5)
        self.assertEqual(actual, audit["direct"]["total_rules"])
        self.assertEqual(selected["direct"]["domains"], [])
        self.assertEqual(audit["proxy"]["total_rules"], 5)

    def brand_scope(self, root, namespace):
        (root / "source").mkdir(exist_ok=True)
        (root / "source/reject-app-scope.json").write_text(json.dumps({
            "schema": 1, "preserve_manual_supplements": True,
            "min_selected_domains": 1, "max_selected_domains": 100,
            "families": [{"id": "observed-brand", "category": "installed", "roots": [namespace]}]}))

    def test_installed_brand_suffix_precedes_a_higher_ranked_generic(self):
        root, plan, document = self.fixture()
        self.brand_scope(root, "proxy7.example")
        plan["app_scope"] = "source/reject-app-scope.json"
        plan["rule_counts"]["proxy"] = 4
        (root / "ranking.csv").write_text("rank,domain\n1,proxy0.example\n99,proxy7.example\n")
        plan["sources"]["ranking"] = {"file": "ranking.csv"}
        selected, audit = IMPORT.select(root, plan, root, document)
        self.assertIn("proxy7.example", selected["proxy"]["suffixes"])
        self.assertNotIn("proxy0.example", selected["proxy"]["suffixes"])
        self.assertEqual(audit["proxy"]["brand_priority"]["selected_suffixes"], 1)

    def test_installed_brand_exact_precedes_generic_without_inventing_a_parent(self):
        root, plan, document = self.fixture()
        self.brand_scope(root, "brand.example")
        plan["app_scope"] = "source/reject-app-scope.json"
        plan["rule_counts"]["proxy"] = 20
        (root / "ranking.csv").write_text("rank,domain\n" + "".join(
            f"{i+1},host{i}.generic.example\n" for i in range(30)) + "99,one.brand.example\n")
        plan["sources"]["ranking"] = {"file": "ranking.csv"}
        selected, audit = IMPORT.select(root, plan, root, document)
        self.assertIn("one.brand.example", selected["proxy"]["domains"])
        self.assertNotIn("brand.example", selected["proxy"]["suffixes"])
        self.assertNotIn("one.brand.example", selected["proxy"]["suffixes"])
        self.assertEqual(audit["proxy"]["brand_priority"]["selected_exact_hosts"], 1)

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
