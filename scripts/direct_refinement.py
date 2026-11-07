"""Refine direct suffixes without swallowing public suffixes or proxy scopes."""
import hashlib
from pathlib import Path

SOURCE = "scripts/direct_refinement.py"
PSL_SOURCE = "source/public-suffix-list.dat"


def parents(host):
    labels = host.split(".")
    return (".".join(labels[i:]) for i in range(len(labels)))


def covered(host, suffixes):
    return any(parent in suffixes for parent in parents(host))


def public_suffix_rules(path):
    exact, wildcard, exceptions = set(), set(), set()
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        rule = raw.split("//", 1)[0].strip()
        if not rule:
            continue
        destination = exact
        if rule.startswith("!"):
            destination, rule = exceptions, rule[1:]
        elif rule.startswith("*."):
            destination, rule = wildcard, rule[2:]
        destination.add(rule.encode("idna").decode("ascii").lower())
    return exact, wildcard, exceptions


def refine_direct(hosts, root, plan, opposite_suffixes=(), opposite_exact=(), opposite_words=()):
    config = plan.get("direct_refinement")
    if not config:
        return set(hosts), {"promoted": [], "retained_original": [], "parent_covered": 0}
    if set(config) != {"public_suffix_list"}:
        raise ValueError("unexpected direct refinement policy")
    record = config["public_suffix_list"]
    path = Path(root) / PSL_SOURCE
    data = path.read_bytes()
    if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise ValueError("public suffix list fingerprint differs")
    exact, wildcard, exceptions = public_suffix_rules(path)
    opposite_suffixes, opposite_exact = set(opposite_suffixes), set(opposite_exact)
    # Index all ancestors once; avoid a full proxy scan for every direct domain.
    opposite_ancestors = {parent for host in opposite_suffixes | opposite_exact for parent in parents(host)}
    result, promoted, retained = set(), [], []
    for host in sorted(hosts):
        labels = host.split(".")
        parent = ".".join(labels[-2:])
        reason = None
        if parent != host:
            if parent not in exceptions and (parent in exact or parent.split(".", 1)[-1] in wildcard):
                reason = "public-suffix"
            elif (parent in opposite_ancestors or covered(parent, opposite_suffixes)
                  or any(word in parent for word in opposite_words)):
                reason = "proxy-overlap"
        if reason:
            retained.append({"domain": host, "reason": reason})
            result.add(host)
        else:
            result.add(parent)
            if parent != host:
                promoted.append({"domain": host, "suffix": parent})
    pruned = {host for host in result if not any(parent in result for parent in list(parents(host))[1:])}
    if not all(covered(host, pruned) for host in hosts):
        raise ValueError("direct refinement lost input coverage")
    return pruned, {"promoted": promoted, "retained_original": retained,
                    "parent_covered": len(result) - len(pruned)}
