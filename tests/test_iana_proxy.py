"""Keep shared TLDs and changed or retired delegations out of proxy generation."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from iana_proxy import (IANA_PAGE, POLICY_SOURCE, read_policy, read_registry,
                        select_proxy_tlds, verify_proxy_snapshot)


def policy():
    return {"schema": 1, "scope": "conservative-overseas-dedicated-tlds", "entries": [
        {"tld": "gov", "category": "government", "manager": "Government Agency",
         "country_iso": "US", "reason": "Dedicated government namespace."},
        {"tld": "brand", "category": "brand", "manager": "Brand Corporation",
         "country_iso": "US", "reason": "Reviewed brand namespace."},
    ]}


def registry():
    return {entry["tld"]: {"tld": entry["tld"], "status": "active", "type": "generic",
                           "manager": entry["manager"], "country_iso": entry["country_iso"],
                           "nameserver_count": 2} for entry in policy()["entries"]}


class IANAProxyTests(unittest.TestCase):
    def test_foreign_manager_and_google_ownership_do_not_import_open_registration(self):
        records = registry()
        for name in ("com", "net", "org", "edu", "app", "dev", "io", "cn", "hk", "mo", "tw", "unknownbrand"):
            records[name] = {**records["brand"], "tld": name}
        selected, audit = select_proxy_tlds(records, policy())
        self.assertEqual(selected, {".brand", ".gov"})
        self.assertEqual(audit["selected"], [".brand", ".gov"])

    def test_retired_undelegated_and_changed_owners_are_removed(self):
        for change, reason in (({"status": "retired"}, "not_active"),
                               ({"nameserver_count": 0}, "not_delegated"),
                               ({"type": "country-code"}, "not_generic"),
                               ({"manager": "New Owner"}, "manager_changed"),
                               ({"country_iso": "CN"}, "manager_country_changed")):
            with self.subTest(change=change):
                records = registry()
                records["brand"].update(change)
                selected, audit = select_proxy_tlds(records, policy())
                self.assertEqual(selected, {".gov"})
                self.assertEqual(audit["excluded"], [{"tld": "brand", "reason": reason}])

    def test_missing_policy_record_is_a_source_failure(self):
        records = registry()
        records.pop("brand")
        with self.assertRaisesRegex(ValueError, "missing policy TLD"):
            select_proxy_tlds(records, policy())

    def test_policy_rejects_open_country_and_local_namespaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            for changes in ({"tld": "com"}, {"tld": "edu"}, {"tld": "app"}, {"tld": "cn"},
                            {"country_iso": "CN"}, {"country_iso": "HK"}, {"tld": "xn--fiqs8s"},
                            {"tld": "gov", "category": "brand"}):
                document = policy()
                document["entries"][1].update(changes)
                (root / POLICY_SOURCE).write_text(json.dumps(document))
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    read_policy(root)

    def test_official_schema_preserves_delegation_evidence_and_rejects_duplicate_records(self):
        document = {"meta": {"specversion": 1, "source": IANA_PAGE, "generated": "2026-10-28T00:00:00Z"},
                    "domains": [{"name": "brand", "status": "active", "type": "generic",
                                 "manager": {"organization": "Brand Corporation", "address": {"country_iso": "US"}},
                                 "nameservers": [{"name": "ns.example.net"}]}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "iana.json"
            path.write_text(json.dumps(document))
            records, _ = read_registry(path)
            self.assertEqual(records["brand"]["manager"], "Brand Corporation")
            self.assertEqual(records["brand"]["nameserver_count"], 1)
            document["domains"].append(copy.deepcopy(document["domains"][0]))
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                read_registry(path)
            path.write_text("<html>upstream unavailable</html>")
            with self.assertRaises(ValueError):
                read_registry(path)

    def test_committed_snapshot_cannot_reintroduce_legacy_or_shared_rules(self):
        entries = (ROOT / "PROXY-DOMAIN-SET.list").read_text().splitlines()
        self.assertEqual(verify_proxy_snapshot(ROOT, entries), 0)
        for unwanted in (".com", ".cn", ".edu", ".io", ".legacy.example.com"):
            with self.subTest(unwanted=unwanted), self.assertRaises(ValueError):
                verify_proxy_snapshot(ROOT, entries + [unwanted])


if __name__ == "__main__":
    unittest.main()
