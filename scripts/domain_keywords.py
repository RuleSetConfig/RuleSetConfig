"""Shared keyword, suffix and exact-host routing companion policy."""
import ipaddress
import json
from pathlib import Path
import re

KEYWORD_SOURCE = "source/domain-keywords.json"
IMPORT_SOURCE = "source/companion-import.json"
MIN_KEYWORD_LETTERS = 5


def parents(host, include_self=True):
    labels = host.split(".")
    return (".".join(labels[i:]) for i in range(0 if include_self else 1, len(labels)))


def _domain_set(root, policy):
    path = Path(root) / (policy.upper() + "-DOMAIN-SET.list")
    if not path.is_file():
        return set(), set()
    from filter_domains import read_domain_rules
    return read_domain_rules(path)


def _hosts(values):
    if (not isinstance(values, list) or any(not isinstance(h, str) for h in values)
            or len(values) != len(set(values))):
        raise ValueError("expected unique companion hostnames")
    for host in values:
        if (len(host) > 253 or "." not in host or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split("."))):
            raise ValueError(f"invalid precise companion hostname: {host!r}")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        raise ValueError("IP addresses are not companion hostnames")
    return set(values)


def _read_keyword_document(root):
    document = json.loads((Path(root) / KEYWORD_SOURCE).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("expected a keyword policy object")
    required = {"schema", "proxy", "direct"}
    schema = document.get("schema")
    if type(schema) is not int:
        raise ValueError("expected an integer schema")
    if schema in (2, 3):
        required |= {"proxy_domain_suffixes", "direct_domain_suffixes", "rule_counts"}
        if schema == 3:
            required |= {"proxy_domains", "direct_domains"}
    elif schema != 1:
        raise ValueError("unsupported keyword policy schema")
    if set(document) != required:
        raise ValueError("unexpected companion policy fields")
    for policy in ("proxy", "direct"):
        words = document[policy]
        if (not isinstance(words, list) or len(words) != len(set(words))
                or any(not isinstance(w, str) or not re.fullmatch(r"[a-z0-9-]+", w)
                       or len(re.findall(r"[a-z]", w)) < MIN_KEYWORD_LETTERS for w in words)):
            raise ValueError(f"{policy}: expected unique lowercase inline keywords with at least five ASCII letters")
        if schema >= 2 and any(other != word and other in word for word in words for other in words):
            raise ValueError(f"{policy}: keyword is covered by another keyword")
    if any(left in right or right in left
           for left in document["proxy"] for right in document["direct"]):
        raise ValueError("opposite-policy keyword coverage overlaps")
    if schema == 1:
        return document
    scopes = {}; actual = {}
    for policy in ("proxy", "direct"):
        suffixes = _hosts(document[policy + "_domain_suffixes"])
        exact = _hosts(document.get(policy + "_domains", []))
        scopes[policy] = suffixes, exact
        set_suffixes, set_exact = _domain_set(root, policy)
        for kind, hosts in (("suffix", suffixes), ("exact", exact)):
            for host in hosts:
                if (covering_keyword(host, document[policy]) or any(p in set_suffixes for p in parents(host))
                        or (kind == "exact" and host in set_exact)):
                    raise ValueError(f"precise {policy} hostname already covered by DOMAIN-SET or keyword: {host}")
                if any(p in suffixes for p in parents(host, include_self=kind == "exact")):
                    raise ValueError(f"parent-covered precise companion hostname: {host}")
        actual[policy] = len(document[policy]) + len(suffixes) + len(exact)
    for policy in ("proxy", "direct"):
        other = "direct" if policy == "proxy" else "proxy"
        opposite_suffixes, opposite_exact = scopes[other]
        opposite_set_suffixes, opposite_set_exact = _domain_set(root, other)
        for host in set.union(*scopes[policy]):
            if (covering_keyword(host, document[other]) or host in opposite_exact
                    or any(p in opposite_suffixes or p in opposite_set_suffixes for p in parents(host))
                    or (host in scopes[policy][1] and host in opposite_set_exact)):
                raise ValueError(f"opposite-policy companion coverage overlaps: {host}")
    counts = document["rule_counts"]
    if (not isinstance(counts, dict) or set(counts) != {"proxy", "direct"}
            or any(type(v) is not int or v <= 0 for v in counts.values()) or counts != actual):
        raise ValueError(f"companion rule counts do not match declared targets: {actual}")
    return document


def read_inline_keywords(root):
    doc = _read_keyword_document(root)
    return {policy: tuple(doc[policy]) for policy in ("proxy", "direct")}


def read_companion_suffixes(root):
    doc = _read_keyword_document(root)
    return {policy: tuple(doc.get(policy + "_domain_suffixes", ())) for policy in ("proxy", "direct")}


def read_companion_domains(root):
    doc = _read_keyword_document(root)
    return {policy: tuple(doc.get(policy + "_domains", ())) for policy in ("proxy", "direct")}


def read_proxy_suffixes(root):
    return read_companion_suffixes(root)["proxy"]


def covering_keyword(entry, keywords):
    hostname = entry.lstrip(".").lower()
    return next((keyword for keyword in keywords if keyword in hostname), None)


def covering_domain_or_keyword(entry, suffixes, exact, keywords=()):
    from filter_patterns import covering_domain_entry
    domain = covering_domain_entry(entry, suffixes, exact)
    if domain is not None:
        return domain
    keyword = covering_keyword(entry, keywords)
    return "DOMAIN-KEYWORD," + keyword if keyword is not None else None
