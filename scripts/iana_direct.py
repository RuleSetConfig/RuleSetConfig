"""Select only the three mainland country-code TLDs from official IANA data."""

import json
from pathlib import Path

from iana_proxy import IANA_URL

SELECTOR_SOURCE = "scripts/iana_direct.py"
DIRECT_TLDS = frozenset({"cn", "xn--fiqs8s", "xn--fiqz9s"})
SCOPE = "cn-country-code-tlds"
RECORD_FIELDS = {"tld", "status", "type", "manager", "country_iso", "nameserver_count"}


def select_direct_tlds(registry):
    """Fail closed if any required TLD is missing, malformed or undelegated."""
    records = []
    for name in sorted(DIRECT_TLDS):
        if name not in registry:
            raise ValueError(f"IANA registry is missing direct TLD: {name}")
        record = registry[name]
        if (not isinstance(record, dict) or set(record) != RECORD_FIELDS
                or record["tld"] != name or record["status"] != "active"
                or record["type"] != "country-code" or record["country_iso"] != "CN"
                or not isinstance(record["manager"], str) or not record["manager"]
                or type(record["nameserver_count"]) is not int or record["nameserver_count"] <= 0):
            raise ValueError(f"invalid or inactive IANA direct TLD: {name}")
        records.append(record)
    selected = ["." + name for name in sorted(DIRECT_TLDS)]
    return set(selected), {
        "scope": SCOPE, "registry_records": len(registry),
        "selection_records": records, "selected": selected,
        "standalone_tld_coverage": True,
    }


def verify_direct_snapshot(root, entries):
    """Require the exact direct inventory and its committed IANA evidence offline."""
    manifest = json.loads((Path(root) / "metadata/tld.json").read_text(encoding="utf-8"))
    snapshot = manifest.get("domain_sync", {}).get("iana_direct")
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("selection_records"), list):
        raise ValueError("missing IANA direct selection snapshot")
    records = snapshot["selection_records"]
    if any(not isinstance(item, dict) or not isinstance(item.get("tld"), str) for item in records):
        raise ValueError("invalid IANA direct snapshot records")
    registry = {item["tld"]: item for item in records}
    if len(registry) != len(records) or set(registry) != DIRECT_TLDS:
        raise ValueError("IANA direct snapshot does not match the three required TLDs")
    expected, audit = select_direct_tlds(registry)
    if (set(entries) != expected or snapshot.get("selected") != audit["selected"]
            or snapshot.get("scope") != SCOPE
            or snapshot.get("standalone_tld_coverage") is not True
            or manifest.get("sources", {}).get("iana", {}).get("url") != IANA_URL
            or manifest.get("domain_sync", {}).get("result_entries", {}).get("direct") != len(expected)):
        raise ValueError("DIRECT-DOMAIN-SET differs from its IANA TLD selection")
    return 0
