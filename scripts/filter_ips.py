"""Read supplementary destination IP rules and deduplicate their address coverage."""

from collections import Counter
import ipaddress
from pathlib import Path


def parse_ip_rule(line):
    parts = [part.strip() for part in line.split(",")]
    if len(parts) != 2 or parts[0] not in {"IP-CIDR", "IP-CIDR6"}:
        raise ValueError("expected IP-CIDR/IP-CIDR6,CIDR without policies or options")
    network = ipaddress.ip_network(parts[1], strict=True)
    if (network.version == 6) != (parts[0] == "IP-CIDR6"):
        raise ValueError("IP rule type does not match its address family")
    return "ip_cidr", str(network)


def read_ip_rules(path, *, allow_empty=False):
    rules = set()
    for number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        try:
            rules.add(parse_ip_rule(line))
        except ValueError as error:
            raise ValueError(f"{path}:{number}: {error}") from error
    if not rules and not allow_empty:
        raise ValueError(f"{path}: supplementary IP source is empty")
    return rules


def collapse_ip_rules(rules):
    """Collapse equivalent coverage separately for IPv4 and IPv6."""
    out = {(kind, value) for kind, value in rules if kind != "ip_cidr"}
    networks = [ipaddress.ip_network(value) for kind, value in rules if kind == "ip_cidr"]
    for version in (4, 6):
        out.update(("ip_cidr", str(network)) for network in ipaddress.collapse_addresses(
            network for network in networks if network.version == version))
    return out


def ip_source_audit(rules):
    return {"counts": dict(sorted(Counter(kind for kind, _ in rules).items())),
            "block_suffix": 0, "block_exact": 0,
            "patterns": [list(rule) for rule in sorted(rules)], "block_patterns": len(rules)}
