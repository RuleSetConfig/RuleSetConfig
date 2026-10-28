#!/usr/bin/env python3
"""Build proxy and direct TLD pairs exclusively from the official IANA registry."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
from urllib.request import Request, urlopen

from iana_direct import SELECTOR_SOURCE as DIRECT_SELECTOR_SOURCE, select_direct_tlds
from iana_proxy import (IANA_URL, POLICY_SOURCE, SELECTOR_SOURCE, read_policy,
                        read_registry, select_proxy_tlds)
from filter_patterns import covering_domain_entry, covering_suffix
from rule_sorting import domain_sort_key
from domain_keywords import (KEYWORD_SOURCE, covering_keyword, covering_domain_or_keyword,
                             read_inline_keywords)

SOURCES = {
    "iana": {
        "file": "iana-tlds.json",
        "url": IANA_URL,
        "min_rules": 1000,
    },
}
MAX_SOURCE_BYTES = 32 * 1024 * 1024


def digest(path):
    data = Path(path).read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def validate_entry(entry):
    host = entry[1:] if entry.startswith(".") else entry
    if (not host or len(host) > 253 or (not entry.startswith(".") and "." not in host)
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                       for label in host.split("."))):
        raise ValueError(f"invalid DOMAIN-SET entry: {entry!r}")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return entry
    raise ValueError(f"IP address is not a domain entry: {entry!r}")


def read_entries(path):
    entries = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        entry = line.strip().lower()
        if entry and not entry.startswith(("#", "//")):
            entries.add(validate_entry(entry))
    if not entries:
        raise ValueError(f"empty domain source: {path}")
    return entries


def parse_srs(document):
    if (not isinstance(document, dict) or set(document) != {"version", "rules"}
            or document["version"] not in (1, 2, 3)
            or not isinstance(document["rules"], list) or not document["rules"]):
        raise ValueError("expected a nonempty sing-box rule-set document")
    fields = {"domain": set(), "domain_suffix": set(), "domain_regex": set()}
    for rule in document["rules"]:
        if not isinstance(rule, dict) or not rule or not set(rule) <= fields.keys():
            raise ValueError("upstream contains unsupported or logical rule fields")
        for field, values in rule.items():
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                raise ValueError(f"expected strings in {field}")
            for value in values:
                if field == "domain_regex":
                    fields[field].add(value)
                elif field == "domain":
                    if value.startswith("."):
                        raise ValueError(f"invalid exact hostname: {value!r}")
                    fields[field].add(validate_entry(value.lower()))
                else:
                    # A dotted sing-box suffix means descendants only. Preserve
                    # that distinction until the other inputs cover its apex.
                    validate_entry("." + value.lstrip(".").lower())
                    if value.startswith(".."):
                        raise ValueError(f"invalid sing-box suffix: {value!r}")
                    fields[field].add(value.lower())
    return fields


def check_source_floor(name, count):
    minimum = SOURCES[name]["min_rules"]
    if count < minimum:
        raise ValueError(f"{name}: {count} domain rules, below source floor {minimum}")


def download_sources(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    def fetch(item):
        name, source = item
        for attempt in range(3):
            try:
                request = Request(source["url"], headers={"User-Agent": "RuleSetConfig-domain-sync"})
                with urlopen(request, timeout=60) as response:
                    data = response.read(MAX_SOURCE_BYTES + 1)
                if not data or len(data) > MAX_SOURCE_BYTES:
                    raise ValueError(f"{name}: empty or oversized upstream response")
                (directory / source["file"]).write_bytes(data)
                return name, len(data)
            except (OSError, ValueError):
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)

    with ThreadPoolExecutor(max_workers=len(SOURCES)) as pool:
        for name, size in pool.map(fetch, SOURCES.items()):
            print(f"downloaded {name}: {size} bytes")


def split_entries(entries):
    return ({entry[1:] for entry in entries if entry.startswith(".")},
            {entry for entry in entries if not entry.startswith(".")})


def is_covered(entry, suffixes, exact):
    return covering_domain_entry(entry, suffixes, exact) is not None


def prune_direct_entries(direct, proxy, proxy_keywords=()):
    """Prune whole scopes already won by the earlier proxy companion union."""
    suffixes, exact = split_entries(proxy)
    removed = [
        {"entry": entry, "covered_by": covering}
        for entry in sorted(direct, key=domain_sort_key)
        if (covering := covering_domain_or_keyword(entry, suffixes, exact, proxy_keywords)) is not None
    ]
    retained = set(direct) - {item["entry"] for item in removed}
    return retained, removed


def merge_entries(custom, surge, sing, keywords=()):
    combined = set(custom) | set(surge) | sing["domain"] | {
        "." + value for value in sing["domain_suffix"] if not value.startswith(".")
    }
    suffixes, exact = split_entries(combined)
    dotted = {value for value in sing["domain_suffix"] if value.startswith(".")}
    for entry in sorted(dotted):
        if not is_covered(entry[1:], suffixes, exact):
            raise ValueError(f"children-only suffix {entry} has no input covering its apex")
    combined.update(dotted)
    for entry in combined:
        validate_entry(entry)
    suffixes, _ = split_entries(combined)
    retained = {
        entry for entry in combined
        if not covering_suffix(entry.lstrip("."), suffixes,
                               include_self=not entry.startswith("."))
    }
    parent_pruned = len(combined) - len(retained)
    keyword_covered = [
        {"entry": entry, "keyword": keyword}
        for entry in sorted(retained, key=domain_sort_key)
        if (keyword := covering_keyword(entry, keywords)) is not None
    ]
    retained.difference_update(item["entry"] for item in keyword_covered)
    suffixes, exact = split_entries(retained)
    missing = sorted(entry for entry in combined
                     if not is_covered(entry, suffixes, exact)
                     and not covering_keyword(entry, keywords))
    if missing:
        raise ValueError(f"domain coverage lost during pruning: {missing[:5]}")
    return retained, {
        "custom_entries": len(custom), "union_entries": len(combined),
        "parent_covered_entries_pruned": parent_pruned,
        "keyword_covered_entries_removed": len(keyword_covered),
        "keyword_covered_entries": keyword_covered,
        "inline_keywords": list(keywords),
        "result_entries": len(retained),
        "all_domain_inputs_covered_with_inline_keywords": True,
        "children_only_suffixes_covered_without_expansion": len(dotted),
        "regex_not_imported": sorted(sing["domain_regex"]),
    }


def build_lists(root, upstream, output, parsed):
    candidates, audit, sources = {}, {}, {}
    keywords = read_inline_keywords(root)
    sources["inline_keywords"] = {"url": "repository:" + KEYWORD_SOURCE, **digest(root / KEYWORD_SOURCE)}
    for name, source in SOURCES.items():
        path = upstream / source["file"]
        count = len(parsed[name])
        check_source_floor(name, count)
        sources[name] = {"url": source["url"], **digest(path), "domain_entries": count}
    for name, relative in (("proxy_tld_policy", POLICY_SOURCE), ("iana_selector", SELECTOR_SOURCE),
                           ("iana_direct_selector", DIRECT_SELECTOR_SOURCE)):
        sources[name] = {"url": "repository:" + relative, **digest(root / relative)}
    proxy, selection = select_proxy_tlds(parsed["iana"], read_policy(root))
    candidates["proxy"] = proxy
    # Keep the IANA list independently complete, even where a keyword companion overlaps.
    audit["proxy"] = {
        "inline_keywords": list(keywords["proxy"]), "keyword_covered_entries_removed": 0,
        "keyword_covered_entries": [], "result_entries": len(proxy), "regex_not_imported": [],
        "iana_proxy": selection,
    }
    direct, selection = select_direct_tlds(parsed["iana"])
    candidates["direct"] = direct
    audit["direct"] = {
        "inline_keywords": list(keywords["direct"]), "keyword_covered_entries_removed": 0,
        "keyword_covered_entries": [], "result_entries": len(direct), "regex_not_imported": [],
        "iana_direct": selection,
    }
    for key in candidates:
        other = "direct" if key == "proxy" else "proxy"
        suffixes, exact = split_entries(candidates[other])
        audit[key]["entries_fully_covered_by_other_set"] = sum(
            is_covered(entry, suffixes, exact) for entry in candidates[key])
    # No candidate file is written until both IANA selections succeed.
    output.mkdir(parents=True, exist_ok=True)
    for key, entries in candidates.items():
        (output / (key.upper() + "-DOMAIN-SET.list")).write_text(
            "\n".join(sorted(entries, key=domain_sort_key)) + "\n", encoding="utf-8")
    return sources, audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--fetch", action="store_true", help="download the official IANA registry first")
    args = parser.parse_args()
    root, upstream, output = map(lambda path: Path(path).resolve(),
                                 (args.root, args.source_dir, args.output_dir))
    if output == root or upstream == root or output == upstream:
        parser.error("use separate upstream and candidate directories outside the repository root")
    if args.fetch:
        download_sources(upstream)
    registry, _ = read_registry(upstream / SOURCES["iana"]["file"])
    sources, audit = build_lists(root, upstream, output, {"iana": registry})
    verify_path = Path(__file__).with_name("verify-all.py")
    spec = importlib.util.spec_from_file_location("domain_sync_verify", verify_path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.compile_tld_sets(output, output, args.sing_box)
    version_text = subprocess.run([args.sing_box, "version"], text=True, capture_output=True, check=True).stdout
    version = re.search(r"^sing-box version (\S+)", version_text)
    if not version:
        raise ValueError("could not identify sing-box compiler version")
    manifest = {
        "schema": 1, "name": "tld", "generator": {"sing_box": version.group(1)},
        "sources": dict(sorted(sources.items())),
        "outputs": {name: digest(output / name) for name in
                    ("DIRECT-DOMAIN-SET.list", "DIRECT-DOMAIN-SET.srs", "PROXY-DOMAIN-SET.list", "PROXY-DOMAIN-SET.srs")},
        "domain_sync": {
            "iana_proxy": audit["proxy"]["iana_proxy"],
            "iana_direct": audit["direct"]["iana_direct"],
            "inline_keywords_source": KEYWORD_SOURCE,
            "inline_keywords": {key: result["inline_keywords"] for key, result in audit.items()},
            "keyword_covered_entries_removed": {
                key: result["keyword_covered_entries_removed"] for key, result in audit.items()
            },
            "source_domain_counts": {name: source["domain_entries"] for name, source in sources.items()
                                     if "domain_entries" in source},
            "result_entries": {key: result["result_entries"] for key, result in audit.items()},
            "regex_not_imported": {key: len(result["regex_not_imported"]) for key, result in audit.items()},
            "requires_proxy_companions_before_direct": True,
            "overlap_policy": "keep both IANA TLD selections independently complete; earlier proxy companions retain routing priority",
        },
    }
    (output / "metadata").mkdir(exist_ok=True)
    (output / "metadata/tld.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (output / "domain-sync-audit.json").write_text(json.dumps({
        "schema": 1, "sources": sources, "sets": audit,
    }, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest["domain_sync"], indent=2))


if __name__ == "__main__":
    main()
