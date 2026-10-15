"""APNIC country/status selection, exact range conversion and integrity checks."""

from collections import Counter
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


APNIC = load("tested_apnic", "sync-apnic-cn.py")
VERIFY = load("tested_apnic_verify", "verify-all.py")


def document(records):
    counts = Counter(record.split("|")[2] for record in records)
    lines = [f"2|apnic|20261015|{len(records)}|19830613|20261014|+1000"]
    lines.extend(f"apnic|*|{kind}|*|{counts.get(kind, 0)}|summary" for kind in ("asn", "ipv4", "ipv6"))
    return "\n".join([*lines, *records]) + "\n"


def record(kind, start, value, *, country="CN", status="allocated"):
    return f"apnic|{country}|{kind}|{start}|{value}|20200101|{status}"


class ApnicCnTests(unittest.TestCase):
    def test_field_whitespace_is_ignored(self):
        text = document([record("ipv4", "192.0.2.0", "256")]).replace("|", " | ")
        networks, _ = APNIC.parse_delegated(text)
        self.assertEqual([str(network) for network in networks], ["192.0.2.0/24"])

    def test_country_and_allocation_status_selection_excludes_non_cn_and_unallocated(self):
        records = [record("ipv4", "192.0.2.0", "16"),
                   record("ipv4", "192.0.2.16", "16", status="assigned"),
                   record("ipv4", "192.0.2.32", "16", status="available"),
                   record("ipv4", "192.0.2.48", "16", status="reserved"),
                   record("ipv4", "198.51.100.0", "256", country="HK"),
                   record("ipv4", "203.0.113.0", "256", country="TW"),
                   record("ipv6", "2001:db8::", "32"),
                   record("asn", "64496", "1")]
        networks, audit = APNIC.parse_delegated(document(records))
        self.assertEqual([str(network) for network in networks], ["192.0.2.0/27", "2001:db8::/32"])
        self.assertEqual(audit["cn_records"], {"ipv4": 2, "ipv6": 1})
        self.assertEqual(audit["cn_status_counts"]["ipv4"], {"allocated": 1, "assigned": 1})

    def test_ipv4_value_is_an_address_count_not_a_prefix_length(self):
        networks, _ = APNIC.parse_delegated(document([record("ipv4", "192.0.2.0", "24")]))
        self.assertEqual([str(network) for network in networks], ["192.0.2.0/28", "192.0.2.16/29"])
        self.assertEqual(sum(network.num_addresses for network in networks), 24)

    def test_unaligned_ipv4_range_has_exact_coverage(self):
        networks, _ = APNIC.parse_delegated(document([record("ipv4", "192.0.2.1", "3")]))
        self.assertEqual([str(network) for network in networks], ["192.0.2.1/32", "192.0.2.2/31"])
        self.assertFalse(any(ipaddress.ip_address("192.0.2.0") in network for network in networks))
        self.assertFalse(any(ipaddress.ip_address("192.0.2.4") in network for network in networks))

    def test_ipv6_value_is_a_prefix_and_adjacency_is_collapsed(self):
        networks, audit = APNIC.parse_delegated(document([
            record("ipv6", "2001:db8::", "127"), record("ipv6", "2001:db8::2", "127", status="assigned")]))
        self.assertEqual([str(network) for network in networks], ["2001:db8::/126"])
        self.assertEqual(audit["address_counts"]["ipv6"], 4)

    def test_overlap_is_deduplicated_without_expanding_coverage(self):
        networks, _ = APNIC.parse_delegated(document([
            record("ipv4", "192.0.2.0", "256"), record("ipv4", "192.0.2.64", "64", status="assigned")]))
        self.assertEqual([str(network) for network in networks], ["192.0.2.0/24"])

    def test_truncated_or_inconsistent_summaries_fail(self):
        text = document([record("ipv4", "192.0.2.0", "256"), record("ipv6", "2001:db8::", "32")])
        for invalid in ("\n".join(text.splitlines()[:-1]), text.replace("ipv4|*|1|summary", "ipv4|*|2|summary")):
            with self.subTest(text=invalid), self.assertRaisesRegex(ValueError, "totals or type summaries"):
                APNIC.parse_delegated(invalid)

    def test_invalid_header_or_registry_is_rejected(self):
        text = document([record("ipv4", "192.0.2.0", "256")])
        for invalid in ("", text.replace("2|apnic|", "2.3|apnic|", 1),
                        text.replace("apnic|CN|", "arin|CN|", 1)):
            with self.subTest(text=invalid), self.assertRaises(ValueError):
                APNIC.parse_delegated(invalid)

    def test_invalid_ranges_or_unexpected_cn_status_fail(self):
        records = [record("ipv4", "192.0.2.0", "0"), record("ipv4", "255.255.255.255", "2"),
                   record("ipv6", "2001:db8::1", "64"), record("ipv6", "2001:db8::", "129"),
                   record("ipv4", "192.0.2.0", "256", status="unknown")]
        for row in records:
            with self.subTest(record=row), self.assertRaises(ValueError):
                APNIC.parse_delegated(document([row]))

    def test_official_md5_detects_tampering(self):
        data = document([record("ipv4", "192.0.2.0", "256")]).encode()
        checksum = "MD5 (delegated-apnic-latest) = " + hashlib.md5(data).hexdigest()
        APNIC.validate_checksum(data, checksum)
        with self.assertRaises(ValueError):
            APNIC.validate_checksum(data + b"\n", checksum)
        with self.assertRaises(ValueError):
            APNIC.validate_checksum(data, "missing checksum")

    def test_each_family_requires_a_complete_source(self):
        for missing in ("ipv4", "ipv6"):
            audit = {"cn_records": dict(APNIC.MIN_CN_RECORDS), "result_cidrs": {"ipv4": 1, "ipv6": 1}}
            audit["cn_records"][missing] = 0
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "source floor"):
                APNIC.check_source_floors(audit)

    def test_generated_text_json_are_pure_ip_and_deterministic(self):
        networks, _ = APNIC.parse_delegated(document([
            record("ipv6", "2001:db8::", "32"), record("ipv4", "192.0.2.0", "256")]))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            APNIC.write_ip_source(networks, root / "first")
            APNIC.write_ip_source(list(reversed(networks)), root / "second")
            for suffix in (".list", ".json"):
                self.assertEqual((root / "first" / (APNIC.SET_NAME + suffix)).read_bytes(),
                                 (root / "second" / (APNIC.SET_NAME + suffix)).read_bytes())
            text = (root / "first/DIRECT-IP-SET.list").read_text()
            self.assertIn("IP-CIDR,192.0.2.0/24\n", text)
            self.assertIn("IP-CIDR6,2001:db8::/32\n", text)
            self.assertNotIn("no-resolve", text)
            self.assertEqual(VERIFY.verify_direct_ip_set(root / "first"), 0)

    def test_direct_ip_verifier_rejects_domain_rules_redundancy_and_missing_family(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "DIRECT-IP-SET.list"
            for text in ("DOMAIN,example.com\n", "IP-CIDR,192.0.2.0/24\n",
                         "IP-CIDR,192.0.2.0/24\nIP-CIDR,192.0.2.0/24\nIP-CIDR6,2001:db8::/32\n",
                         "IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25\nIP-CIDR6,2001:db8::/32\n"):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(SystemExit):
                    VERIFY.verify_direct_ip_set(root)


if __name__ == "__main__":
    unittest.main()
