"""Country-code and explicitly reviewed proxy TLDs from IANA's official registry."""

import json
from pathlib import Path
import re

IANA_URL = "https://data.iana.org/TLD/v1/tlds.json"
IANA_PAGE = "https://www.iana.org/domains/root/db"
POLICY_SOURCE = "source/proxy-tld-policy.json"
SELECTOR_SOURCE = "scripts/iana_proxy.py"
# Shared names require an explicit reviewed generic exception, never a brand entry.
# All active country-code TLDs are handled separately, including repurposed ccTLDs.
SHARED_TLDS = frozenset("com net org edu int arpa app dev moe ai io tv cc co me xyz top asia zip mov".split())
REVIEWED_GENERIC_TLDS = frozenset({"app", "dev", "moe"})
# Explicit foreign brand aliases only; open-registration and mainland IDNs remain excluded.
REVIEWED_IDN_BRANDS = frozenset({
    "xn--flw351e", "xn--qcka1pmc", "xn--cg4bki", "xn--cckwcxetd", "xn--jlq480n2rg",
})
MAINLAND_TLDS = frozenset({"cn", "xn--fiqs8s", "xn--fiqz9s"})
EXCLUDED_COUNTRIES = frozenset({"CN", "HK", "MO", "TW"})
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def read_policy(root):
    document = json.loads((Path(root) / POLICY_SOURCE).read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or set(document) != {"schema", "scope", "entries", "country_code"}
            or type(document["schema"]) is not int or document["schema"] != 1
            or document["scope"] != "non-cn-country-and-reviewed-tlds"
            or not isinstance(document["entries"], list) or not document["entries"]):
        raise ValueError("invalid IANA proxy TLD policy")
    country_code = document["country_code"]
    if (not isinstance(country_code, dict) or set(country_code) != {"include_active", "excluded_tlds"}
            or country_code["include_active"] is not True
            or not isinstance(country_code["excluded_tlds"], list)
            or not all(isinstance(name, str) for name in country_code["excluded_tlds"])
            or len(country_code["excluded_tlds"]) != len(MAINLAND_TLDS)
            or set(country_code["excluded_tlds"]) != MAINLAND_TLDS):
        raise ValueError("country-code policy must include all active ccTLDs except the three mainland TLDs")
    seen = set()
    for entry in document["entries"]:
        if (not isinstance(entry, dict)
                or set(entry) != {"tld", "category", "manager", "country_iso", "reason"}
                or not all(isinstance(value, str) and value.strip() == value and value
                           for value in entry.values())):
            raise ValueError("invalid proxy TLD policy entry")
        name = entry["tld"]
        reviewed_generic = entry["category"] == "generic" and name in REVIEWED_GENERIC_TLDS
        if (not LABEL.fullmatch(name) or name in seen
                or (name in SHARED_TLDS and not reviewed_generic)
                or len(name) <= 2
                or (name.startswith("xn--")
                    and (name not in REVIEWED_IDN_BRANDS or entry["category"] != "brand"))
                or not re.fullmatch(r"[A-Z]{2}", entry["country_iso"])
                or entry["country_iso"] in EXCLUDED_COUNTRIES
                or entry["category"] not in {"government", "military", "brand", "generic"}
                or (entry["category"] == "generic" and not reviewed_generic)
                or (entry["category"] == "government" and name != "gov")
                or (entry["category"] == "military" and name != "mil")
                or (name in {"gov", "mil"} and entry["category"] == "brand")):
            raise ValueError(f"out-of-scope or duplicate proxy TLD: {name!r}")
        seen.add(name)
    return document


def read_registry(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or not isinstance(document.get("meta"), dict)
            or type(document["meta"].get("specversion")) is not int
            or document["meta"].get("specversion") != 1
            or document["meta"].get("source") != IANA_PAGE
            or not isinstance(document["meta"].get("generated"), str)
            or not isinstance(document.get("domains"), list)):
        raise ValueError("invalid IANA TLD registry schema or source")
    registry = {}
    for item in document["domains"]:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or not LABEL.fullmatch(item["name"]) or item["name"] in registry
                or not isinstance(item.get("status"), str) or not isinstance(item.get("type"), str)
                or not isinstance(item.get("nameservers"), list)
                or not (item.get("manager") is None or isinstance(item["manager"], dict))):
            raise ValueError("invalid or duplicate IANA TLD record")
        manager = item.get("manager") or {}
        address = manager.get("address") or {}
        if not isinstance(address, dict):
            raise ValueError("invalid IANA manager address")
        registry[item["name"]] = {
            "tld": item["name"], "status": item["status"], "type": item["type"],
            "manager": manager.get("organization"), "country_iso": address.get("country_iso"),
            "nameserver_count": len(item["nameservers"]),
        }
    return registry, document["meta"]


def select_proxy_tlds(registry, policy):
    """Include active non-mainland ccTLDs and explicitly reviewed generic names."""
    selected, excluded, records = [], [], []
    generic_count = 0
    for entry in sorted(policy["entries"], key=lambda item: item["tld"]):
        name = entry["tld"]
        if name not in registry:
            raise ValueError(f"IANA registry is missing policy TLD: {name}")
        record = registry[name]
        if (not isinstance(record, dict)
                or set(record) != {"tld", "status", "type", "manager", "country_iso", "nameserver_count"}
                or record["tld"] != name or type(record["nameserver_count"]) is not int
                or record["nameserver_count"] < 0):
            raise ValueError(f"invalid IANA policy snapshot for {name}")
        records.append(record)
        reason = None
        if record["status"] != "active":
            reason = "not_active"
        elif record["type"] != "generic":
            reason = "not_generic"
        elif not record["nameserver_count"]:
            reason = "not_delegated"
        elif record["manager"] != entry["manager"]:
            reason = "manager_changed"
        elif record["country_iso"] != entry["country_iso"]:
            reason = "manager_country_changed"
        if reason:
            excluded.append({"tld": name, "reason": reason})
        else:
            selected.append("." + name)
            generic_count += entry["category"] == "generic"
    explicit_names = {entry["tld"] for entry in policy["entries"]}
    country_code_selected = []
    for name, record in sorted(registry.items()):
        if record["type"] != "country-code" or name in explicit_names:
            continue
        records.append(record)
        reason = None
        if name in policy["country_code"]["excluded_tlds"]:
            reason = "mainland_tld"
        elif record["status"] != "active":
            reason = "not_active"
        elif not record["nameserver_count"]:
            reason = "not_delegated"
        if reason:
            excluded.append({"tld": name, "reason": reason})
        else:
            country_code_selected.append("." + name)
    dedicated_count = len(selected) - generic_count
    selected = sorted(selected + country_code_selected)
    records.sort(key=lambda item: item["tld"])
    excluded.sort(key=lambda item: item["tld"])
    if not selected:
        raise ValueError("IANA proxy TLD selection is empty")
    return set(selected), {
        "scope": policy["scope"], "registry_records": len(registry),
        "selection_records": records, "selected": selected, "excluded": excluded,
        "selected_counts": {"country_code": len(country_code_selected),
                            "dedicated": dedicated_count, "generic": generic_count},
        "standalone_tld_coverage": True,
    }


def verify_proxy_snapshot(root, entries):
    """Check committed policy evidence without requiring network during verification."""
    root = Path(root)
    manifest = json.loads((root / "metadata/tld.json").read_text(encoding="utf-8"))
    snapshot = manifest.get("domain_sync", {}).get("iana_proxy")
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("selection_records"), list):
        raise ValueError("missing IANA proxy selection snapshot")
    records = snapshot["selection_records"]
    if any(not isinstance(item, dict) or not isinstance(item.get("tld"), str) for item in records):
        raise ValueError("invalid IANA proxy snapshot records")
    registry = {item["tld"]: item for item in records}
    policy = read_policy(root)
    explicit = {entry["tld"] for entry in policy["entries"]}
    if (len(registry) != len(records) or not explicit <= registry.keys()
            or any(record.get("type") != "country-code" and name not in explicit
                   for name, record in registry.items())):
        raise ValueError("IANA proxy snapshot does not match the explicit policy inventory")
    expected, audit = select_proxy_tlds(registry, policy)
    if (set(entries) != expected or snapshot.get("selected") != audit["selected"]
            or snapshot.get("excluded") != audit["excluded"]
            or snapshot.get("selected_counts") != audit["selected_counts"]
            or snapshot.get("scope") != policy["scope"]
            or snapshot.get("standalone_tld_coverage") is not True
            or manifest.get("sources", {}).get("iana", {}).get("url") != IANA_URL):
        raise ValueError("PROXY-DOMAIN-SET differs from its IANA TLD policy")
    return 0
