#!/usr/bin/env python3
"""Build DIRECT-IP-SET from APNIC's CN allocation/assignment statistics."""

import argparse
from collections import Counter
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
from urllib.request import Request, urlopen

from ip_rulesets import write_ip_source as write_source
from ruleset_format import compile_ruleset

SOURCE_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
SOURCE_NAME = "delegated-apnic-latest"
SET_NAME = "DIRECT-IP-SET"
MIN_CN_RECORDS = {"ipv4": 8000, "ipv6": 1500}
MAX_SOURCE_BYTES = 32 * 1024 * 1024


def digest(path):
    data = Path(path).read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def validate_checksum(data, checksum):
    match = re.fullmatch(r"MD5 \(delegated-apnic-latest\) = ([0-9a-fA-F]{32})", checksum.strip())
    if not match or hashlib.md5(data).hexdigest() != match.group(1).lower():
        raise ValueError("APNIC source does not match its official MD5 file")


def download_sources(directory):
    directory.mkdir(parents=True, exist_ok=True)
    for attempt in range(3):
        try:
            downloads = {}
            for suffix in ("", ".md5"):
                request = Request(SOURCE_URL + suffix, headers={"User-Agent": "RuleSetConfig-APNIC-sync"})
                with urlopen(request, timeout=90) as response:
                    data = response.read(MAX_SOURCE_BYTES + 1)
                if not data or len(data) > MAX_SOURCE_BYTES:
                    raise ValueError("APNIC source response is empty or oversized")
                downloads[suffix] = data
            # Retry the pair together if latest changed between the two requests.
            validate_checksum(downloads[""], downloads[".md5"].decode("ascii"))
            for suffix, data in downloads.items():
                (directory / (SOURCE_NAME + suffix)).write_bytes(data)
            return
        except (OSError, ValueError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def parse_delegated(text):
    records = [line.strip() for line in text.splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    if not records:
        raise ValueError("empty APNIC statistics file")
    header = [field.strip() for field in records[0].split("|")]
    if (len(header) != 7 or header[:2] != ["2", "apnic"]
            or not header[2].isdigit() or not header[3].isdigit()
            or not re.fullmatch(r"\d{8}", header[4])
            or not re.fullmatch(r"\d{8}", header[5])
            or not re.fullmatch(r"[+-]\d{4}", header[6])):
        raise ValueError("expected an APNIC format-2 statistics header")
    summaries, actual = {}, Counter()
    status_counts = {"ipv4": Counter(), "ipv6": Counter()}
    networks = {4: [], 6: []}
    for number, line in enumerate(records[1:], 2):
        fields = [field.strip() for field in line.split("|")]
        if len(fields) == 6 and fields[1] == "*" and fields[3] == "*" and fields[5] == "summary":
            if fields[0] != "apnic" or fields[2] not in {"asn", "ipv4", "ipv6"} or fields[2] in summaries:
                raise ValueError(f"invalid or duplicate APNIC summary at record {number}")
            summaries[fields[2]] = int(fields[4])
            continue
        if len(fields) < 7 or fields[0] != "apnic" or fields[2] not in {"asn", "ipv4", "ipv6"}:
            raise ValueError(f"invalid APNIC record {number}")
        registry, country, kind, start, value, date, status = fields[:7]
        actual[kind] += 1
        if country != "CN" or kind not in {"ipv4", "ipv6"}:
            continue
        if status not in {"allocated", "assigned", "available", "reserved"}:
            raise ValueError(f"unexpected CN status: {status}")
        if status not in {"allocated", "assigned"}:
            continue
        status_counts[kind][status] += 1
        if kind == "ipv4":
            first = ipaddress.IPv4Address(start)
            count = int(value)
            if count <= 0:
                raise ValueError("IPv4 allocation count must be positive")
            last = ipaddress.IPv4Address(int(first) + count - 1)
            networks[4].extend(ipaddress.summarize_address_range(first, last))
        else:
            if not value.isdigit() or not 0 <= int(value) <= 128:
                raise ValueError("IPv6 value must be a prefix length")
            networks[6].append(ipaddress.IPv6Network(start + "/" + value, strict=True))
    if (sum(actual.values()) != int(header[3]) or not actual.keys() <= summaries.keys()
            or any(count != actual.get(kind, 0) for kind, count in summaries.items())):
        raise ValueError("APNIC record totals or type summaries do not match the complete file")
    collapsed = {version: list(ipaddress.collapse_addresses(values)) for version, values in networks.items()}
    audit = {
        "country": "CN", "included_statuses": ["allocated", "assigned"],
        "country_semantics": "organisation allocation/assignment country; not physical geolocation",
        "serial": header[2], "start_date": header[4], "end_date": header[5], "utc_offset": header[6],
        "total_records": int(header[3]), "type_records": dict(sorted(actual.items())),
        "cn_records": {kind: sum(counts.values()) for kind, counts in status_counts.items()},
        "cn_status_counts": {kind: dict(sorted(counts.items())) for kind, counts in status_counts.items()},
        "unmerged_cidrs": {"ipv4": len(networks[4]), "ipv6": len(networks[6])},
        "result_cidrs": {"ipv4": len(collapsed[4]), "ipv6": len(collapsed[6])},
        "address_counts": {"ipv4": sum(net.num_addresses for net in collapsed[4]),
                           "ipv6": sum(net.num_addresses for net in collapsed[6])},
    }
    return collapsed[4] + collapsed[6], audit


def check_source_floors(audit):
    for kind, minimum in MIN_CN_RECORDS.items():
        if audit["cn_records"][kind] < minimum or not audit["result_cidrs"][kind]:
            raise ValueError(f"APNIC CN {kind} count is below source floor {minimum}")


def write_ip_source(networks, output):
    write_source(networks, output, SET_NAME, [
        "APNIC CN allocated/assigned IPv4 and IPv6 networks", "Source: " + SOURCE_URL,
        "Registration country, not a physical-location database.",
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    upstream, output = Path(args.source_dir).resolve(), Path(args.output_dir).resolve()
    if output in {upstream, Path.cwd().resolve(), Path(__file__).resolve().parents[1]}:
        parser.error("use separate upstream and isolated output directories")
    if args.fetch:
        download_sources(upstream)
    raw = upstream / SOURCE_NAME
    checksum = upstream / (SOURCE_NAME + ".md5")
    validate_checksum(raw.read_bytes(), checksum.read_text(encoding="ascii"))
    networks, audit = parse_delegated(raw.read_text(encoding="utf-8"))
    check_source_floors(audit)
    write_ip_source(networks, output)
    binary = output / (SET_NAME + ".srs")
    decompiled = output / (SET_NAME + ".compiled.json")
    compile_ruleset(output / (SET_NAME + ".json"), binary, args.sing_box)
    subprocess.run([args.sing_box, "rule-set", "decompile", "-o", str(decompiled), str(binary)], check=True)
    spec = importlib.util.spec_from_file_location("apnic_verify", Path(__file__).with_name("verify-all.py"))
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    if verifier.verify(output / (SET_NAME + ".list"), decompiled):
        raise ValueError("APNIC text/binary address coverage differs")
    verifier.verify_direct_ip_set(output)
    version_text = subprocess.run([args.sing_box, "version"], text=True, capture_output=True, check=True).stdout
    version = re.search(r"^sing-box version (\S+)", version_text)
    if not version:
        raise ValueError("could not identify sing-box compiler version")
    manifest = {
        "schema": 1, "name": "direct-ip", "generator": {"sing_box": version.group(1)},
        "sources": {
            "apnic": {"url": SOURCE_URL, **digest(raw)},
            "apnic_md5": {"url": SOURCE_URL + ".md5", **digest(checksum)},
        },
        "outputs": {name: digest(output / name) for name in (SET_NAME + ".list", SET_NAME + ".srs")},
        "apnic": audit,
    }
    (output / "metadata").mkdir(exist_ok=True)
    (output / "metadata/direct-ip.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
