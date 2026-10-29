"""Resolve repository subscriptions in documented Surge fragments."""

REPOSITORY = "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/"


def repository_routes(fragment):
    """Return (type, artefact, policy) in effective order, expanding named groups."""
    sections = {}
    current = None
    for raw in fragment.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("//", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)

    def expand(kind, reference, policy, seen=()):
        if reference.startswith(REPOSITORY) and reference.endswith(".list"):
            yield kind, reference[len(REPOSITORY):-5], policy
            return
        if reference in seen:
            raise ValueError("recursive documented ruleset: " + reference)
        for line in sections.get("Ruleset " + reference, []):
            fields = [field.strip() for field in line.split(",")]
            if fields[0] in {"RULE-SET", "DOMAIN-SET"} and len(fields) >= 2:
                yield from expand(fields[0], fields[1], policy, (*seen, reference))

    result = []
    for line in sections.get("Rule", []):
        fields = [field.strip() for field in line.split(",")]
        if fields[0] in {"RULE-SET", "DOMAIN-SET"} and len(fields) >= 3:
            result.extend(expand(fields[0], fields[1], fields[2]))
    return result
