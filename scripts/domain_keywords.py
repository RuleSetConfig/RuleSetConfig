"""Shared keyword policy for companion rule sets and domain pruning."""

import json
from pathlib import Path
import re

KEYWORD_SOURCE = "source/domain-keywords.json"


def read_inline_keywords(root):
    document = json.loads((Path(root) / KEYWORD_SOURCE).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {"schema", "proxy", "direct"} or document["schema"] != 1:
        raise ValueError("expected keyword schema 1 with proxy and direct arrays")
    result = {}
    for policy in ("proxy", "direct"):
        words = document[policy]
        if (not isinstance(words, list)
                or any(not isinstance(word, str) or not re.fullmatch(r"[a-z0-9-]+", word) for word in words)
                or len(words) != len(set(words))):
            raise ValueError(f"{policy}: expected unique lowercase inline keyword strings")
        result[policy] = tuple(words)
    return result


def covering_keyword(entry, keywords):
    """A keyword within the fixed hostname covers its apex and all descendants."""
    hostname = entry.lstrip(".").lower()
    return next((keyword for keyword in keywords if keyword in hostname), None)
