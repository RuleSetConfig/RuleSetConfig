"""Service selection, partial-prefix subtraction and existing inline exclusions."""

from copy import deepcopy
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ip_rulesets import collapse, intersection, read_networks, subtract, write_ip_source


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROXY = load("tested_proxy_ips", "sync-proxy-ips.py")
VERIFY = load("tested_proxy_ip_verify", "verify-all.py")


def nets(*values):
    return [ipaddress.ip_network(value) for value in values]


def google(*values):
    return {"syncToken": "1", "creationTime": "2026-10-15T00:00:00Z", "prefixes": [
        {"ipv4Prefix" if ":" not in value else "ipv6Prefix": value} for value in values]}


def microsoft(identifier, category, required, *ips):
    return {"id": identifier, "category": category, "required": required, "ips": list(ips)}


def meta(prefix="157.240.0.0/16", end="2026-10-15T00:00:00"):
    return {"status": "ok", "status_code": 200, "data": {
        "resource": "32934", "query_starttime": "2026-10-01T00:00:00",
        "query_endtime": "2026-10-15T00:00:00", "prefixes": [{"prefix": prefix, "timelines": [
            {"starttime": "2026-10-01T00:00:00", "endtime": end}]}]}}


class IpDifferenceTests(unittest.TestCase):
    def test_customer_subnet_is_removed_without_dropping_the_whole_parent(self):
        result = subtract(nets("8.8.8.0/24"), nets("8.8.8.64/26"))
        self.assertEqual([str(net) for net in result], ["8.8.8.0/26", "8.8.8.128/25"])

    def test_supernet_exclusion_removes_the_whole_input(self):
        self.assertEqual(subtract(nets("8.8.8.0/24"), nets("8.0.0.0/8")), [])

    def test_ipv6_holes_and_host_boundaries_are_exact(self):
        result = subtract(nets("2001:db8::/125"), nets("2001:db8::1/128", "2001:db8::4/126"))
        self.assertEqual([str(net) for net in result], ["2001:db8::/128", "2001:db8::2/127"])

    def test_both_families_and_repeated_overlapping_exclusions(self):
        result = subtract(nets("8.8.8.0/24", "2001:db8::/125"),
                          nets("8.8.8.0/25", "8.8.8.0/26", "2001:db8::/126"))
        self.assertEqual([str(net) for net in result], ["8.8.8.128/25", "2001:db8::4/126"])

    def test_difference_matches_independent_address_enumeration(self):
        base = nets("192.0.2.0/26", "192.0.2.128/26")
        exclusions = nets("192.0.2.16/28", "192.0.2.128/25", "198.51.100.0/24")
        expected = {address for net in base for address in net} - {address for net in exclusions for address in net}
        self.assertEqual({address for net in subtract(base, exclusions) for address in net}, expected)

    def test_intersection_is_independent_of_prefix_representation(self):
        result = intersection(nets("8.8.0.0/16", "2001:db8::/32"),
                              nets("8.8.8.0/24", "2001:db8:1::/48", "9.9.9.0/24"))
        self.assertEqual([str(net) for net in result], ["8.8.8.0/24", "2001:db8:1::/48"])

    def test_existing_apple_and_telegram_inline_coverage_is_cut_out_of_supernets(self):
        inline = read_networks(ROOT / PROXY.INLINE_SOURCE)
        result = subtract(nets("16.0.0.0/7", "91.104.0.0/13", "2001:b28::/32", "2403::/16"), inline)
        self.assertFalse(intersection(result, inline))
        for host in ("17.1.2.3", "91.108.12.1", "2001:b28:f23d::1", "2403:300::1"):
            self.assertFalse(any(ipaddress.ip_address(host) in net for net in result))
        for host in ("16.1.2.3", "91.108.24.1", "2001:b28:f23e::1", "2403:301::1"):
            self.assertTrue(any(ipaddress.ip_address(host) in net for net in result))


class ProxySourcesTests(unittest.TestCase):
    def test_google_official_difference_keeps_service_ranges_only(self):
        base = PROXY.parse_google(google("8.8.8.0/24", "2001:4860::/124"))
        cloud = PROXY.parse_google(google("8.8.8.64/26", "2001:4860::8/125"))
        self.assertEqual([str(net) for net in subtract(base, cloud)],
                         ["8.8.8.0/26", "8.8.8.128/25", "2001:4860::/125"])

    def test_google_rejects_empty_wrong_family_private_and_unaligned_data(self):
        invalid = [{}, google("0.0.0.0/0"), google("10.0.0.0/8"), google("8.8.8.1/24"),
                   {**google("8.8.8.0/24"), "prefixes": [{"ipv6Prefix": "8.8.8.0/24"}]},
                   {**google("8.8.8.0/24"), "prefixes": [{}]}]
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(ValueError):
                PROXY.parse_google(document)

    def test_microsoft_selects_required_optimize_allow_and_ignores_url_only(self):
        rows = [microsoft(1, "Optimize", True, "40.92.0.0/15"),
                microsoft(2, "Allow", True, "2603:1006::/40"),
                microsoft(3, "Default", True, "52.96.0.0/14"),
                microsoft(4, "Allow", False, "104.47.0.0/17"),
                microsoft(5, "Allow", True)]
        networks, ids = PROXY.parse_microsoft365(rows)
        self.assertEqual([str(net) for net in networks], ["40.92.0.0/15", "2603:1006::/40"])
        self.assertEqual(ids, [1, 2])

    def test_microsoft_rejects_duplicate_ids_unknown_categories_and_nonboolean_flags(self):
        row = microsoft(1, "Allow", True, "40.92.0.0/15")
        for rows in ([], [row, row], [{**row, "category": "Unknown"}], [{**row, "required": "true"}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                PROXY.parse_microsoft365(rows)

    def test_meta_uses_current_visibility_and_drops_withdrawn_prefixes(self):
        current, audit = PROXY.parse_meta(meta())
        self.assertEqual(current, nets("157.240.0.0/16"))
        self.assertEqual(audit["active_prefixes"], 1)
        self.assertEqual(PROXY.parse_meta(meta(end="2026-10-14T23:59:59"))[0], [])

    def test_meta_accepts_any_timeline_that_covers_snapshot(self):
        document = meta("2a03:2880::/32")
        document["data"]["prefixes"][0]["timelines"].insert(0, {
            "starttime": "2026-10-01T00:00:00", "endtime": "2026-10-02T00:00:00"})
        self.assertEqual(PROXY.parse_meta(document)[0], nets("2a03:2880::/32"))

    def test_meta_rejects_wrong_asn_errors_and_reversed_visibility(self):
        invalid = [meta(), meta(), meta()]
        invalid[0]["data"]["resource"] = "15169"
        invalid[1]["status"] = "error"
        invalid[2]["data"]["prefixes"][0]["timelines"][0]["starttime"] = "2026-10-16T00:00:00"
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(ValueError):
                PROXY.parse_meta(document)

    def test_missing_family_fails_each_upstream_floor(self):
        sources = {name: [*nets("8.8.8.0/24") * floors["ipv4"],
                          *nets("2001:4860::/32") * floors["ipv6"]]
                   for name, floors in PROXY.MIN_SOURCE_PREFIXES.items()}
        PROXY.check_source_floors(sources)
        for name in sources:
            incomplete = {**sources, name: nets("8.8.8.0/24")}
            with self.subTest(source=name), self.assertRaisesRegex(ValueError, "source floor"):
                PROXY.check_source_floors(incomplete)

    def test_ripe_fingerprint_ignores_query_nonce_but_detects_changed_prefixes(self):
        first = meta()
        second = deepcopy(first)
        second.update(query_id="new-query", server_id="other-server", process_time=0.1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "meta.json"
            path.write_text(json.dumps(first))
            expected = PROXY.source_fingerprint(path, "meta")
            path.write_text(json.dumps(second))
            self.assertEqual(expected, PROXY.source_fingerprint(path, "meta"))
            second["data"]["prefixes"][0]["prefix"] = "157.240.0.0/17"
            path.write_text(json.dumps(second))
            self.assertNotEqual(expected, PROXY.source_fingerprint(path, "meta"))

    def test_output_is_deterministic_pure_ip_and_empty_does_not_match_all(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_ip_source(nets("2001:4860::/32", "8.8.8.0/25", "8.8.8.128/25"), root, "PROXY-IP-SET", [])
            expected = (root / "PROXY-IP-SET.list").read_bytes()
            write_ip_source(nets("8.8.8.0/24", "2001:4860::/32"), root, "PROXY-IP-SET", [])
            self.assertEqual(expected, (root / "PROXY-IP-SET.list").read_bytes())
            write_ip_source([], root, "EMPTY", [])
            self.assertEqual(json.loads((root / "EMPTY.json").read_text())["rules"], [])

    def test_proxy_verifier_rejects_inline_overlap_and_missing_curated_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / PROXY.INLINE_SOURCE).write_text("IP-CIDR,17.0.0.0/8\n")
            (root / PROXY.EXTRA_SOURCE).write_text("IP-CIDR,1.1.1.1/32\nIP-CIDR6,2606:4700:4700::1111/128\n")
            expected = nets("1.1.1.1/32", "2606:4700:4700::1111/128")
            write_ip_source(expected, root, PROXY.SET_NAME, [])
            self.assertEqual(VERIFY.verify_proxy_ip_set(root), 0)
            for invalid in ([*expected, *nets("17.1.0.0/16")], nets("8.8.8.0/24", "2001:4860::/32")):
                write_ip_source(invalid, root, PROXY.SET_NAME, [])
                with self.subTest(networks=invalid), self.assertRaises(SystemExit):
                    VERIFY.verify_proxy_ip_set(root)


if __name__ == "__main__":
    unittest.main()
