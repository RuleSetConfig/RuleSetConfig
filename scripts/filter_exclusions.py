"""Reviewed hostname exclusions, separate from upstream Adblock @@ rules."""

import ipaddress
from pathlib import Path
import re

from filter_patterns import covering_suffix, wildcard_regex

DEFAULT_DOMAIN_EXCLUSIONS = Path(__file__).resolve().parents[1] / "source/reject-domain-exclusions.list"


def read_domain_exclusions(path=DEFAULT_DOMAIN_EXCLUSIONS):
    domains = set()
    for number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        value = raw.split("#", 1)[0].strip().lower()
        if not value or value.startswith("//"):
            continue
        labels = value.split(".")
        valid = (len(value) <= 253 and len(labels) >= 2 and
                 all(re.fullmatch(r"[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?", part)
                     for part in labels))
        try:
            ipaddress.ip_address(value)
            valid = False
        except ValueError:
            pass
        if not valid:
            raise ValueError(f"{path}:{number}: expected a bare domain hostname")
        domains.add(value)
    return domains


def check_domain_exclusions(exclusions, suffix, exact, patterns=()):
    """Fail rather than silently allow a broader ancestor or pattern through."""
    for domain in sorted(exclusions):
        parent = covering_suffix(domain, suffix)
        if parent or domain in exact:
            raise ValueError(f"excluded domain {domain} is still blocked by {'.' + parent if parent else domain}")
        for kind, value in patterns:
            matched = (kind == "domain_keyword" and value in domain or
                       kind == "domain_wildcard" and re.search(wildcard_regex(value), domain) or
                       kind == "domain_regex" and re.search(value, domain) or
                       kind == "logical_and" and all(key in domain for key in value))
            if matched:
                raise ValueError(f"excluded domain {domain} is still blocked by {kind}: {value}")


def remove_domain_exclusions(suffix, exact, exclusions, patterns=()):
    """Remove only same-host exact/suffix entries, preserving unrelated blocks."""
    audit = {"domains": sorted(exclusions),
             "removed_suffix": sorted(suffix & exclusions),
             "removed_exact": sorted(exact & exclusions)}
    suffix, exact = suffix - exclusions, exact - exclusions
    check_domain_exclusions(exclusions, suffix, exact, patterns)
    return suffix, exact, audit
