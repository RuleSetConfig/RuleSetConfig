#!/usr/bin/env python3
"""Build common service proxy IP sets from upstreams and curated ranges."""

import argparse
from datetime import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
from urllib.request import Request, urlopen

from ip_rulesets import (collapse, compile_pair, family_counts, intersection,
                         read_networks, subtract, write_ip_source)

SET_NAME = "PROXY-IP-SET"
EXTRA_SOURCE = "source/proxy-ip-extra.list"
SOURCES = {
    "google": "https://www.gstatic.com/ipranges/goog.json",
    "google-cloud": "https://www.gstatic.com/ipranges/cloud.json",
    "microsoft365": "https://endpoints.office.com/endpoints/worldwide?clientrequestid=1a018bf0-72b1-4ffd-8ce8-152303bc5927",
    "meta": "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS32934",
}
MIN_SOURCE_PREFIXES = {
    "google": {"ipv4": 50, "ipv6": 5},
    "google-cloud": {"ipv4": 500, "ipv6": 5},
    "microsoft365": {"ipv4": 30, "ipv6": 10},
    "meta": {"ipv4": 100, "ipv6": 100},
}
MAX_SOURCE_BYTES = 16 * 1024 * 1024


def digest(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def public_network(value):
    if not isinstance(value, str) or "/" not in value:
        raise ValueError("source IP must be an explicit CIDR")
    network = ipaddress.ip_network(value, strict=True)
    if not network.is_global or network.prefixlen == 0:
        raise ValueError(f"unexpected non-public source prefix: {value}")
    return network


def parse_google(document):
    if not document.get("syncToken") or not document.get("creationTime") or not document.get("prefixes"):
        raise ValueError("incomplete Google IP range document")
    networks = []
    for row in document["prefixes"]:
        keys = [key for key in ("ipv4Prefix", "ipv6Prefix") if key in row]
        if len(keys) != 1:
            raise ValueError("Google range must contain exactly one address family")
        network = public_network(row[keys[0]])
        if network.version != (4 if keys[0] == "ipv4Prefix" else 6):
            raise ValueError("Google address family does not match prefix key")
        networks.append(network)
    return networks


def parse_microsoft365(document):
    if not isinstance(document, list) or not document:
        raise ValueError("expected a non-empty Microsoft 365 endpoint array")
    networks, selected, identifiers = [], [], set()
    for row in document:
        identifier = row.get("id")
        if (not isinstance(identifier, int) or identifier in identifiers
                or row.get("category") not in {"Optimize", "Allow", "Default"}
                or not isinstance(row.get("required"), bool)):
            raise ValueError("unexpected Microsoft 365 endpoint schema")
        identifiers.add(identifier)
        if not row["required"] or row["category"] not in {"Optimize", "Allow"}:
            continue
        ips = row.get("ips", [])
        if not isinstance(ips, list):
            raise ValueError("Microsoft 365 ips must be an array")
        if ips:
            networks.extend(public_network(value) for value in ips)
            selected.append(identifier)
    return networks, sorted(selected)


def parse_meta(document):
    data = document.get("data", {})
    if (document.get("status") != "ok" or document.get("status_code") != 200
            or str(data.get("resource")) != "32934" or not data.get("prefixes")):
        raise ValueError("expected a successful RIPEstat AS32934 response")
    snapshot = datetime.fromisoformat(data["query_endtime"])
    networks = []
    for row in data["prefixes"]:
        network = public_network(row["prefix"])
        timelines = row.get("timelines")
        if not isinstance(timelines, list) or not timelines:
            raise ValueError("RIPEstat prefix has no visibility timeline")
        active = False
        for period in timelines:
            start, end = (datetime.fromisoformat(period[key]) for key in ("starttime", "endtime"))
            if start > end:
                raise ValueError("invalid RIPEstat visibility timeline")
            active |= start <= snapshot <= end
        if active:
            networks.append(network)
    return networks, {"asn": 32934, "query_endtime": data["query_endtime"],
                                "observed_prefixes": len(data["prefixes"]),
                                "active_prefixes": len(networks)}


def check_source_floors(sources):
    for name, minimums in MIN_SOURCE_PREFIXES.items():
        counts = family_counts(sources[name])
        for family, minimum in minimums.items():
            if counts[family] < minimum:
                raise ValueError(f"{name} {family} source floor {minimum} not met: {counts[family]}")


def source_fingerprint(path, name):
    data = path.read_bytes()
    if name != "meta":
        return digest(data)
    # Query IDs, server names and timings vary even for an identical BGP sample.
    document = json.loads(data)["data"]
    canonical = {key: document[key] for key in ("resource", "query_starttime", "query_endtime")}
    canonical["prefixes"] = sorted(
        ({"prefix": row["prefix"], "timelines": sorted(row["timelines"], key=lambda item: (item["starttime"], item["endtime"]))}
         for row in document["prefixes"]), key=lambda item: item["prefix"])
    encoded = (json.dumps(canonical, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return {**digest(encoded), "representation": "canonical RIPEstat resource, query interval and prefix timelines"}


def download_sources(directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        for attempt in range(3):
            try:
                request = Request(url, headers={"User-Agent": "RuleSetConfig-proxy-IP-sync"})
                with urlopen(request, timeout=90) as response:
                    data = response.read(MAX_SOURCE_BYTES + 1)
                if not data or len(data) > MAX_SOURCE_BYTES:
                    raise ValueError(f"{name}: empty or oversized response")
                json.loads(data)
                (directory / (name + ".json")).write_bytes(data)
                break
            except (OSError, ValueError):
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--direct-list", required=True, help="fresh APNIC candidate for overlap audit")
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    root, upstream, output = (Path(value).resolve() for value in (args.root, args.source_dir, args.output_dir))
    if output in {root, upstream, Path.cwd().resolve()}:
        parser.error("use separate upstream and isolated output directories")
    if args.fetch:
        download_sources(upstream)
    documents = {name: json.loads((upstream / (name + ".json")).read_bytes()) for name in SOURCES}
    sources = {name: parse_google(documents[name]) for name in ("google", "google-cloud")}
    sources["microsoft365"], microsoft_ids = parse_microsoft365(documents["microsoft365"])
    sources["meta"], meta_audit = parse_meta(documents["meta"])
    check_source_floors(sources)
    google_services = subtract(sources["google"], sources["google-cloud"])
    extra = read_networks(root / EXTRA_SOURCE)
    networks = collapse([*google_services, *sources["microsoft365"], *sources["meta"], *extra])
    if not all(family_counts(networks).values()):
        raise ValueError("proxy output must include both IPv4 and IPv6")
    overlaps = intersection(networks, read_networks(args.direct_list))
    write_ip_source(networks, output, SET_NAME, [
        "Common service proxy IPv4 and IPv6 networks; not all non-CN addresses.",
        "Google services (goog.json minus cloud.json), Microsoft 365 required Optimize/Allow,",
        "Meta AS32934 active RIPEstat announcements, curated DNS, Telegram and Apple ranges.",
        "Sources and hashes: metadata/proxy-ip.json",
    ])
    compile_pair(output, SET_NAME, args.sing_box)
    version_text = subprocess.run([args.sing_box, "version"], text=True, capture_output=True, check=True).stdout
    version = re.search(r"^sing-box version (\S+)", version_text)
    if not version:
        raise ValueError("could not identify sing-box compiler version")
    manifest = {
        "schema": 1, "name": "proxy-ip", "generator": {"sing_box": version.group(1)},
        "sources": {name: {"url": url, **source_fingerprint(upstream / (name + ".json"), name)}
                    for name, url in SOURCES.items()},
        "outputs": {name: digest((output / name).read_bytes()) for name in (SET_NAME + ".list", SET_NAME + ".srs")},
        "selection": {
            "source_cidrs": {name: family_counts(values) for name, values in sources.items()},
            "google_services_after_cloud_exclusion": family_counts(google_services),
            "microsoft365_endpoint_ids": microsoft_ids, "meta": meta_audit,
            "curated_cidrs": family_counts(extra),
            "result_cidrs": family_counts(networks),
            "direct_ip_overlap": [str(net) for net in overlaps],
            "routing": "explicit domain policies first, then PROXY-IP-SET before DIRECT-IP-SET",
        },
    }
    manifest["sources"]["curated"] = {"url": "repository:" + EXTRA_SOURCE,
                                       **digest((root / EXTRA_SOURCE).read_bytes())}
    # Rebase verification also prevents publishing against a different CN candidate.
    direct = Path(args.direct_list)
    manifest["sources"]["direct_ip"] = {"url": "repository:DIRECT-IP-SET.list", **digest(direct.read_bytes())}
    (output / "metadata").mkdir(exist_ok=True)
    (output / "metadata/proxy-ip.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest["selection"], indent=2))


if __name__ == "__main__":
    main()
