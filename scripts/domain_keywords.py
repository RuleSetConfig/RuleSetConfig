"""Shared companion keyword and domain-suffix policy."""

import ipaddress
import json
from pathlib import Path
import re

KEYWORD_SOURCE = "source/domain-keywords.json"
IMPORT_SOURCE = "source/companion-import.json"
MIN_KEYWORD_LETTERS = 5


def _read_keyword_document(root):
    document = json.loads((Path(root) / KEYWORD_SOURCE).read_text(encoding="utf-8"))
    required = {"schema", "proxy", "direct"}
    if not isinstance(document, dict):
        raise ValueError("expected a keyword policy object")
    if document.get("schema") == 1:
        if set(document) != required:
            raise ValueError("expected keyword schema 1 with proxy and direct arrays")
    elif document.get("schema") == 2:
        if set(document) != required | {"proxy_domain_suffixes", "direct_domain_suffixes", "rule_counts"}:
            raise ValueError("expected keyword schema 2 with precise suffixes and rule counts")
    else:
        raise ValueError("unsupported keyword policy schema")
    for policy in ("proxy", "direct"):
        words = document[policy]
        if (not isinstance(words, list)
                or any(not isinstance(word, str) or not re.fullmatch(r"[a-z0-9-]+", word)
                       or len(re.findall(r"[a-z]", word)) < MIN_KEYWORD_LETTERS for word in words)
                or len(words) != len(set(words))):
            raise ValueError(f"{policy}: expected unique lowercase inline keywords with at least five ASCII letters")
        if document["schema"] == 2:
            for word in words:
                if any(other != word and other in word for other in words):
                    raise ValueError(f"{policy}: keyword {word!r} is covered by another keyword")
    if document["schema"] == 1:
        return document
    actual = {}
    for policy in ("proxy", "direct"):
        suffixes = document[policy + "_domain_suffixes"]
        if not isinstance(suffixes, list) or any(not isinstance(host, str) for host in suffixes):
            raise ValueError("expected precise companion domain suffixes")
        if len(suffixes) != len(set(suffixes)):
            raise ValueError("duplicate precise companion suffix")
        tld_path = Path(root) / (policy.upper() + "-DOMAIN-SET.list")
        tlds = {line.strip()[1:] for line in tld_path.read_text().splitlines()
                if line.startswith(".") and "." not in line[1:]} if tld_path.is_file() else set()
        suffix_set = set(suffixes)
        for host in suffixes:
            if (len(host) > 253 or "." not in host or not all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split("."))):
                raise ValueError(f"invalid precise companion suffix: {host!r}")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise ValueError("IP addresses are not companion domain suffixes")
            if host.rsplit(".", 1)[-1] in tlds or covering_keyword(host, document[policy]):
                raise ValueError(f"precise {policy} suffix already covered by TLD or keyword: {host}")
            labels = host.split(".")
            if any(".".join(labels[index:]) in suffix_set for index in range(1, len(labels))):
                raise ValueError(f"parent-covered precise companion suffix: {host}")
        actual[policy] = len(document[policy]) + len(suffixes)
    for policy in ("proxy", "direct"):
        other = "direct" if policy == "proxy" else "proxy"
        opposite_suffixes = set(document[other + "_domain_suffixes"])
        for host in document[policy + "_domain_suffixes"]:
            labels = host.split(".")
            if (covering_keyword(host, document[other]) or
                    any(".".join(labels[index:]) in opposite_suffixes for index in range(len(labels)))):
                raise ValueError(f"opposite-policy companion coverage overlaps: {host}")
    counts = document["rule_counts"]
    if (not isinstance(counts, dict) or set(counts) != {"proxy", "direct"}
            or any(type(value) is not int or value <= 0 for value in counts.values()) or counts != actual):
        raise ValueError(f"companion rule counts do not match declared targets: {actual}")
    return document


def read_inline_keywords(root):
    document = _read_keyword_document(root)
    return {policy: tuple(document[policy]) for policy in ("proxy", "direct")}


def read_companion_suffixes(root):
    document = _read_keyword_document(root)
    return {policy: tuple(document.get(policy + "_domain_suffixes", ())) for policy in ("proxy", "direct")}


def read_proxy_suffixes(root):
    return read_companion_suffixes(root)["proxy"]


def covering_keyword(entry, keywords):
    """A keyword within the fixed hostname covers its apex and all descendants."""
    hostname = entry.lstrip(".").lower()
    return next((keyword for keyword in keywords if keyword in hostname), None)


def covering_domain_or_keyword(entry, suffixes, exact, keywords=()):
    """Identify full scope coverage in an earlier domain/keyword companion union."""
    from filter_patterns import covering_domain_entry
    domain = covering_domain_entry(entry, suffixes, exact)
    if domain is not None:
        return domain
    keyword = covering_keyword(entry, keywords)
    return "DOMAIN-KEYWORD," + keyword if keyword is not None else None
