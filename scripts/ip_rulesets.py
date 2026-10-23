"""Exact IPv4/IPv6 set operations and shared text/binary generation."""

import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess

from filter_ips import read_ip_rules
from ruleset_format import RULE_SET_VERSION, compile_ruleset


def collapse(networks):
    networks = list(networks)
    return [network for version in (4, 6)
            for network in ipaddress.collapse_addresses(net for net in networks if net.version == version)]


def read_networks(path):
    return collapse(ipaddress.ip_network(value) for _, value in read_ip_rules(path))


def subtract(networks, exclusions):
    """Return an exact CIDR difference, including holes inside larger prefixes."""
    networks, exclusions = collapse(networks), collapse(exclusions)
    result = []
    for version in (4, 6):
        removed = [net for net in exclusions if net.version == version]
        index = 0
        address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        for network in (net for net in networks if net.version == version):
            start, end = int(network.network_address), int(network.broadcast_address)
            while index < len(removed) and int(removed[index].broadcast_address) < start:
                index += 1
            cursor, other = start, index
            while other < len(removed) and int(removed[other].network_address) <= end:
                lower, upper = int(removed[other].network_address), int(removed[other].broadcast_address)
                if cursor < lower:
                    result.extend(ipaddress.summarize_address_range(address(cursor), address(lower - 1)))
                cursor = max(cursor, upper + 1)
                if cursor > end:
                    break
                other += 1
            if cursor <= end:
                result.extend(ipaddress.summarize_address_range(address(cursor), address(end)))
    return collapse(result)


def intersection(networks, others):
    networks = collapse(networks)
    return subtract(networks, subtract(networks, others))


def family_counts(networks):
    networks = list(networks)
    return {f"ipv{version}": sum(net.version == version for net in networks) for version in (4, 6)}


def write_ip_source(networks, output, name, comments):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    networks = collapse(networks)
    lines = ["# " + comment for comment in comments]
    for version in (4, 6):
        lines.extend(["", f"# IPv{version}"])
        kind = "IP-CIDR" if version == 4 else "IP-CIDR6"
        lines.extend(f"{kind},{network}" for network in networks if network.version == version)
    (output / (name + ".list")).write_text("\n".join(lines) + "\n", encoding="utf-8")
    rules = [{"ip_cidr": [str(network) for network in networks]}] if networks else []
    (output / (name + ".json")).write_text(
        json.dumps({"version": RULE_SET_VERSION, "rules": rules}, separators=(",", ":")) + "\n", encoding="utf-8")


def compile_pair(output, name, sing_box):
    output = Path(output)
    binary, decompiled = output / (name + ".srs"), output / (name + ".compiled.json")
    compile_ruleset(output / (name + ".json"), binary, sing_box)
    subprocess.run([sing_box, "rule-set", "decompile", "-o", str(decompiled), str(binary)], check=True)
    spec = importlib.util.spec_from_file_location("ip_pair_verify", Path(__file__).with_name("verify-all.py"))
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    if verifier.verify(output / (name + ".list"), decompiled):
        raise ValueError(f"{name}: text/binary address coverage differs")
