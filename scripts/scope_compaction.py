"""Lossless finite-class compaction of exact and suffix hostname inventories.

Certificates are comments to Surge, but are checked and reversibly expanded by
repository consumers. No new arbitrary wildcard, parent or keyword is inferred.
The SRS input remains the original indexed hostname inventory.
"""
from collections import Counter, defaultdict
from functools import lru_cache
import hashlib
import itertools
from pathlib import Path
import re

from glob_optimizer import ALPHABET, STAR, parse, render

SOURCE = "scripts/scope_compaction.py"
PREFIX = "#@scope-v1 "
MAX_EXPANSION = 1000000
DOT = 1 << ALPHABET.index(".")


def records(text):
    return [s.strip() for s in text.splitlines()
            if s.strip() and not s.lstrip().startswith(("#", "//"))]


@lru_cache(maxsize=4096)
def members(mask):
    if not mask or any(c in mask for c in "*?") or "[" not in mask:
        raise ValueError("a scope certificate requires a finite character class")
    tokens = parse(mask)
    choices, count = [], 1
    for token in tokens:
        if token == STAR or token <= 0:
            raise ValueError("unbounded scope certificate")
        chars = tuple(c for i, c in enumerate(ALPHABET) if token & (1 << i))
        if "\x00" in chars or (len(chars) > 1 and "." in chars):
            raise ValueError("non-host character class in scope certificate")
        count *= len(chars)
        if count > MAX_EXPANSION:
            raise ValueError("scope certificate exceeds the expansion bound")
        choices.append(chars)
    values = tuple(sorted("".join(v) for v in itertools.product(*choices)))
    if any(len(v) > 253 or "." not in v or not re.fullmatch(r"[a-z0-9_.-]+", v) for v in values):
        raise ValueError("invalid hostname in scope certificate")
    return values


def expand_text(text):
    """Validate certificates and return exactly their represented source rows."""
    if PREFIX not in text:
        return text
    lines = text.splitlines()
    declared = []
    for raw in lines:
        if raw.strip().startswith(PREFIX):
            parts = raw.strip()[len(PREFIX):].split()
            if len(parts) != 2 or parts[0] not in {"exact", "suffix"}:
                raise ValueError("invalid scope certificate")
            kind, mask = parts
            if (kind, mask) in declared:
                raise ValueError("duplicate scope certificate")
            declared.append((kind, mask))
    counts = Counter(records(text))
    replacements, consumed = {}, set()
    for kind, mask in declared:
        original = members(mask)
        rows = ["DOMAIN-WILDCARD," + mask]
        if kind == "suffix":
            rows.append("DOMAIN-WILDCARD,*." + mask)
        if any(counts[row] != 1 or row in consumed for row in rows):
            raise ValueError("scope certificate does not match its complete wildcard rows")
        consumed.update(rows)
        rule_type = "DOMAIN" if kind == "exact" else "DOMAIN-SUFFIX"
        replacements[rows[0]] = [rule_type + "," + host for host in original]
    out = []
    for raw in lines:
        line = raw.strip()
        if line.startswith(PREFIX):
            continue
        if line in replacements:
            out.extend(replacements[line])
        elif line not in consumed:
            out.append(raw)
    return "\n".join(out) + "\n"


@lru_cache(maxsize=4)
def factor_names(names):
    """Distribute one-character unions, without adding Cartesian-product cells."""
    current = {parse(name) for name in names}
    maximum = max(map(len, current), default=0)
    while True:
        changed = False
        for position in range(maximum):
            groups = defaultdict(list)
            for tokens in current:
                if position < len(tokens) and tokens[position] != DOT:
                    groups[tokens[:position], tokens[position + 1:]].append(tokens)
            for (prefix, suffix), group in groups.items():
                if len(group) < 2:
                    continue
                union = 0
                for tokens in group:
                    union |= tokens[position]
                combined = prefix + (union,) + suffix
                if render(combined) is None:
                    continue
                current.difference_update(group)
                current.add(combined)
                changed = True
        if not changed:
            break
    return tuple(sorted(render(tokens) for tokens in current))


def inventory_digest(rows):
    return hashlib.sha256("".join(s + "\n" for s in sorted(rows)).encode()).hexdigest()


def compact_text(text, *, direct=False, minimum_rules=0):
    """Reduce both rows and bytes, proving exact reconstruction before return."""
    from rule_sorting import sort_list_text

    original = sort_list_text(expand_text(text), direct=direct)
    source_rows = records(original)
    if type(minimum_rules) is not int or not 0 <= minimum_rules <= len(source_rows):
        raise ValueError("published count floor exceeds source inventory")
    source_set = set(source_rows)
    removed, added, certificates = set(), set(), []
    stats = {"exact_groups": 0, "suffix_groups": 0}
    for rule_type, kind in (("DOMAIN", "exact"), ("DOMAIN-SUFFIX", "suffix")):
        names = tuple(sorted({r.split(",", 1)[1] for r in source_rows
                              if r.startswith(rule_type + ",")}))
        # Factorisation is exact by construction. Only beneficial groups are used.
        name_set = set(names)
        for mask in (() if minimum_rules == len(source_rows) else factor_names(names)):
            if "[" not in mask:
                continue
            originals = members(mask)
            if not set(originals) <= name_set:
                raise ValueError("factorisation introduced a missing hostname")
            old = {rule_type + "," + host for host in originals}
            new = {"DOMAIN-WILDCARD," + mask}
            if kind == "suffix":
                new.add("DOMAIN-WILDCARD,*." + mask)
            certificate = PREFIX + kind + " " + mask
            old_size = sum(len(s.encode()) + 1 for s in old)
            new_size = sum(len(s.encode()) + 1 for s in new) + len(certificate.encode()) + 1
            if (len(new) >= len(old) or new_size >= old_size
                    or new & (source_set | added)
                    or len(source_set - (removed | old)) + len(added | new) < minimum_rules):
                continue
            removed.update(old)
            added.update(new)
            certificates.append(certificate)
            stats[kind + "_groups"] += 1
    header = [s for s in original.splitlines()
              if not s.strip() or s.lstrip().startswith(("#", "//"))]
    result = "\n".join(header + sorted(certificates)
                       + sorted((source_set - removed) | added)) + "\n"
    result = sort_list_text(result, direct=direct)
    if Counter(records(expand_text(result))) != Counter(source_rows):
        raise ValueError("scope compaction changed the complete source inventory")
    if len(result.encode()) >= len(original.encode()) or len(records(result)) >= len(source_rows):
        result, certificates = original, []
        stats = {"exact_groups": 0, "suffix_groups": 0}
    expanded = records(expand_text(result))
    audit = {
        "schema": 1, "source_rules": len(source_rows), "published_rules": len(records(result)),
        "rules_removed": len(source_rows) - len(records(result)),
        "source_bytes": len(original.encode()), "published_bytes": len(result.encode()),
        "certificate_groups": len(certificates), "minimum_published_rules": minimum_rules, **stats,
        "source_inventory_sha256": inventory_digest(source_rows),
        "expanded_inventory_sha256": inventory_digest(expanded),
        "proof": "exact finite character-class union with complete inverse expansion",
        "new_matching_scope": 0,
    }
    return result, audit


def compact_file(path, *, minimum_rules=0):
    path = Path(path)
    text, audit = compact_text(path.read_text(encoding="utf-8"),
                               direct=path.name == "DIRECT-RULE-SET.list", minimum_rules=minimum_rules)
    path.write_text(text, encoding="utf-8")
    return audit
