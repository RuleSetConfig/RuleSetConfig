"""Canonical ordering shared by the rule generators and repository checks."""

import ipaddress
from pathlib import Path

FAMILY_HEADERS = {"# IPv4", "# IPv6"}


def cidr_sort_key(value):
    network = ipaddress.ip_network(value, strict=False)
    return network.version, int(network.network_address), network.prefixlen


def domain_sort_key(entry):
    rule = entry.split("#", 1)[0].strip()
    domain = rule.lstrip(".").lower()
    is_tld = rule.startswith(".") and "." not in domain
    return (0 if is_tld else 1, domain, 0 if rule.startswith(".") else 1, entry)


def rule_sort_key(line):
    rule = line.split("#", 1)[0].strip()
    parts = [part.strip() for part in rule.split(",")]
    priority = {"AND": 0, "DOMAIN-KEYWORD": 1, "DOMAIN-SUFFIX": 2,
                "DOMAIN": 3, "DOMAIN-WILDCARD": 4, "PROTOCOL": 5, "USER-AGENT": 6}
    if parts[0] in {"IP-CIDR", "IP-CIDR6"}:
        return (8, *cidr_sort_key(parts[1]), rule)
    return (priority.get(parts[0], 7), rule.lower(), rule)


def split_records(text):
    """Keep leading metadata and attach later comments to their following entry."""
    header, records, pending = [], [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line in FAMILY_HEADERS:
            continue
        if line.startswith(("#", "//")):
            if records:
                pending.append(raw)
            else:
                header.append(raw)
            continue
        records.append((line, pending))
        pending = []
    return header, records, pending


def sort_list_text(text, domain_set=False):
    header, records, trailing = split_records(text)
    key = domain_sort_key if domain_set else rule_sort_key
    records.sort(key=lambda record: key(record[0]))
    out = list(header)
    family = None
    for line, comments in records:
        parts = line.split("#", 1)[0].strip().split(",")
        if not domain_set and parts[0] in {"IP-CIDR", "IP-CIDR6"}:
            current = ipaddress.ip_network(parts[1].strip(), strict=False).version
            if current != family:
                if out and out[-1]:
                    out.append("")
                out.append(f"# IPv{current}")
                family = current
        out.extend(comments)
        out.append(line)
    out.extend(trailing)
    return "\n".join(out) + "\n"


def ruleset_paths(root):
    root = Path(root)
    return sorted(root.glob("*.list")) + sorted((root / "source").glob("*.list"))


def is_domain_set(path):
    return all("," not in line.split("#", 1)[0]
               for line, _ in split_records(Path(path).read_text(encoding="utf-8"))[1])


def check_ruleset_order(root):
    bad = []
    for path in ruleset_paths(root):
        _, records, _ = split_records(path.read_text(encoding="utf-8"))
        rows = [line for line, _ in records]
        key = domain_sort_key if is_domain_set(path) else rule_sort_key
        if rows != sorted(rows, key=key):
            bad.append(str(path))
    if bad:
        raise ValueError("rule lists are not in ascending order: " + ", ".join(bad))
    return len(ruleset_paths(root))
