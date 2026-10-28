"""Keep direct routing limited to the three delegated mainland ccTLDs."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from iana_direct import DIRECT_TLDS, select_direct_tlds, verify_direct_snapshot


def registry():
    return {name: {"tld": name, "status": "active", "type": "country-code",
                   "manager": "CNNIC", "country_iso": "CN", "nameserver_count": 5}
            for name in DIRECT_TLDS}


class IANADirectTests(unittest.TestCase):
    def test_only_cn_and_its_two_independent_idn_tlds_are_selected(self):
        records = registry()
        for name in ("com", "hk", "tw", "mo", "cn.com", "xin", "xn--55qx5d"):
            records[name] = {**records["cn"], "tld": name}
        selected, audit = select_direct_tlds(records)
        self.assertEqual(selected, {".cn", ".xn--fiqs8s", ".xn--fiqz9s"})
        self.assertEqual({name.encode("idna").decode() for name in ("cn", "\u4e2d\u56fd", "\u4e2d\u570b")}, DIRECT_TLDS)
        self.assertEqual({item["tld"] for item in audit["selection_records"]}, DIRECT_TLDS)
        self.assertTrue(audit["standalone_tld_coverage"])

    def test_missing_required_tld_is_a_source_failure(self):
        for name in DIRECT_TLDS:
            records = registry()
            records.pop(name)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "missing direct TLD"):
                select_direct_tlds(records)

    def test_inactive_undelegated_or_malformed_required_tld_stops_selection(self):
        for change in ({"status": "retired"}, {"type": "generic"}, {"country_iso": "HK"},
                       {"tld": "com"}, {"nameserver_count": 0}, {"nameserver_count": True},
                       {"nameserver_count": "5"}, {"manager": None}):
            records = registry()
            records["cn"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                select_direct_tlds(records)

    def test_committed_snapshot_rejects_legacy_and_other_tld_rules(self):
        entries = (ROOT / "DIRECT-DOMAIN-SET.list").read_text().splitlines()
        self.assertEqual(verify_direct_snapshot(ROOT, entries), 0)
        for unwanted in (".com", ".hk", ".qq.com", ".\u4e2d\u56fd", "example.cn"):
            with self.subTest(unwanted=unwanted), self.assertRaises(ValueError):
                verify_direct_snapshot(ROOT, entries + [unwanted])
        with self.assertRaises(ValueError):
            verify_direct_snapshot(ROOT, entries[:-1])

    def test_snapshot_cannot_hide_missing_duplicate_or_undelegated_evidence(self):
        original = json.loads((ROOT / "metadata/tld.json").read_text())
        mutations = [
            lambda d: d["domain_sync"].pop("iana_direct"),
            lambda d: d["domain_sync"]["iana_direct"]["selection_records"].pop(),
            lambda d: d["domain_sync"]["iana_direct"]["selection_records"].append(
                copy.deepcopy(d["domain_sync"]["iana_direct"]["selection_records"][0])),
            lambda d: d["domain_sync"]["iana_direct"]["selection_records"][0].update(nameserver_count=0),
            lambda d: d["sources"]["iana"].update(url="https://example.com/registry.json"),
            lambda d: d["domain_sync"]["result_entries"].update(direct=4),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "metadata").mkdir()
            for mutate in mutations:
                document = copy.deepcopy(original)
                mutate(document)
                (root / "metadata/tld.json").write_text(json.dumps(document))
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    verify_direct_snapshot(root, {"." + name for name in DIRECT_TLDS})


if __name__ == "__main__":
    unittest.main()
