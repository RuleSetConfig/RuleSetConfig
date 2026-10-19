"""Supplementary Surge DOMAIN-SET sources with exact/suffix scope preserved."""

import ipaddress
from pathlib import Path
import re


def read_domain_rules(path):
    suffix, exact = set(), set()
    for number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        entry = raw.split("#", 1)[0].strip().lower()
        if not entry or entry.startswith("//"):
            continue
        domain = entry[1:] if entry.startswith(".") else entry
        labels = domain.split(".")
        valid = (len(domain) <= 253 and len(labels) >= 2 and
                 all(re.fullmatch(r"[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?", label)
                     for label in labels))
        try:
            ipaddress.ip_address(domain)
            valid = False
        except ValueError:
            pass
        if not valid:
            raise ValueError(f"{path}:{number}: expected a DOMAIN-SET hostname or leading-dot suffix")
        (suffix if entry.startswith(".") else exact).add(domain)
    return suffix, exact
