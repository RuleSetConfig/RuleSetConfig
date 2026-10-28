#!/usr/bin/env python3
"""Fetch novel ad-block inputs and retain only portable [Rule] rejects."""

import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from filter_patterns import wildcard_regex, pattern_line

SOURCES = {
    "qimao": {"repository": "zhiaon/qimao-novel-adblock", "path": "qimao.sgmodule",
              "minimum": 50},
    "fanqie": {"repository": "zirawell/R-Store",
               "path": "Rule/Surge/Adblock/App/F/番茄小说/fanqie.sgmodule", "minimum": 5},
}
MAX_BYTES = 1024 * 1024


def fingerprint(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def parse_module(text, label="module", minimum=1):
    """Keep exact/suffix/keyword/glob/IP scopes; never widen URL rewrites."""
    suffix, exact, patterns = set(), set(), set()
    section = None
    counts = Counter()
    nonblocking = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "rule":
            counts["surge-only:" + (section or "preamble")] += 1
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 3:
            raise ValueError(f"{label}:{number}: expected a Surge rule with a policy")
        kind, value, policy = parts[:3]
        if policy.upper() not in {"REJECT", "REJECT-DROP", "REJECT-NO-DROP"}:
            nonblocking.append({"line": number, "rule": line})
            continue
        value = value.lower()
        flags = set(parts[3:])
        allowed = {"extended-matching", "pre-matching"}
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            allowed.add("no-resolve")
        if not flags <= allowed:
            raise ValueError(f"{label}:{number}: unsupported rule options: {sorted(flags - allowed)}")
        if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            labels = value.split(".")
            if (len(value) > 253 or len(labels) < 2 or not all(
                    re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", item)
                    for item in labels)):
                raise ValueError(f"{label}:{number}: invalid hostname: {value}")
            try:
                ipaddress.ip_address(value)
            except ValueError:
                pass
            else:
                raise ValueError(f"{label}:{number}: IP literal is not a hostname")
            (suffix if kind == "DOMAIN-SUFFIX" else exact).add(value)
        elif kind == "DOMAIN-KEYWORD":
            if not re.fullmatch(r"[a-z0-9_.-]+", value):
                raise ValueError(f"{label}:{number}: invalid keyword")
            patterns.add(("domain_keyword", value))
        elif kind == "DOMAIN-WILDCARD":
            if not value:
                raise ValueError(f"{label}:{number}: empty wildcard")
            wildcard_regex(value)
            patterns.add(("domain_wildcard", value))
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            network = ipaddress.ip_network(value, strict=True)
            if (network.version == 6) != (kind == "IP-CIDR6"):
                raise ValueError(f"{label}:{number}: IP family differs from rule type")
            patterns.add(("ip_cidr", str(network)))
        else:
            raise ValueError(f"{label}:{number}: unsupported reject rule type: {kind}")
        counts[kind.lower().replace("-", "_")] += 1
    retained = len(suffix) + len(exact) + len(patterns)
    if retained < minimum:
        raise ValueError(f"{label}: only {retained} reject rules, below its floor of {minimum}")
    return suffix, exact, patterns, {
        "block_suffix": len(suffix), "block_exact": len(exact),
        "block_patterns": len(patterns), "counts": dict(sorted(counts.items())),
        "patterns": [list(rule) for rule in sorted(patterns)],
        "ignored_nonblocking": nonblocking,
    }


def source_url(spec, revision, path):
    return ("https://raw.githubusercontent.com/" + spec["repository"] + "/" +
            revision + "/" + quote(path, safe="/"))


def download(url):
    for attempt in range(3):
        try:
            request = Request(url, headers={"User-Agent": "RuleSetConfig-novel-sync"})
            with urlopen(request, timeout=45) as response:
                data = response.read(MAX_BYTES + 1)
            if not data or len(data) > MAX_BYTES:
                raise ValueError(f"{url}: empty or oversized upstream response")
            return data
        except (HTTPError, URLError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(attempt + 1)



def fetch_rules(output_dir):
    """Resolve immutable inputs; no module, rewrite or script is published."""
    files, provenance = {}, {}
    for name, spec in SOURCES.items():
        endpoint = "https://api.github.com/repos/" + spec["repository"] + "/commits/main"
        revision = json.loads(download(endpoint)).get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError(f"{name}: GitHub returned an invalid commit revision")
        url = source_url(spec, revision, spec["path"])
        data = download(url)
        suffix, exact, patterns, _ = parse_module(data.decode("utf-8"), name, spec["minimum"])
        rules = ({("domain_suffix", value) for value in suffix} |
                 {("domain", value) for value in exact} | patterns)
        files[name + ".sgmodule"] = data  # Temporary input, never a published output.
        provenance[name + "_module"] = {
            "url": url, **fingerprint(data),
            "portable_rules": [list(rule) for rule in sorted(rules)],
        }
        print(f"{name}: {len(rules)} portable reject rules at {revision}")
    # Keep the previous candidate inputs intact if either source is invalid.
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for relative, data in files.items():
        (output_dir / relative).write_bytes(data)
    (output_dir / "novel-sources.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def manifest_rules(manifest):
    """Validate pinned source identity and its portable projection for coverage checks."""
    result = {}
    for name, spec in SOURCES.items():
        record = manifest["sources"][name + "_module"]
        prefix = "https://raw.githubusercontent.com/" + spec["repository"] + "/"
        expression = re.escape(prefix) + r"[0-9a-f]{40}/" + re.escape(quote(spec["path"], safe="/"))
        if not re.fullmatch(expression, record["url"]):
            raise ValueError(f"{name}: source must refer to a pinned upstream commit")
        projection = record.get("portable_rules")
        allowed = {"domain", "domain_suffix", "domain_keyword", "domain_wildcard", "ip_cidr"}
        if not isinstance(projection, list) or any(
                not isinstance(item, list) or len(item) != 2 or not isinstance(item[0], str) or item[0] not in allowed
                or not isinstance(item[1], str) for item in projection):
            raise ValueError(f"{name}: portable source projection is missing or invalid")
        text = "[Rule]\n" + "\n".join(pattern_line(kind, value) + ",REJECT" for kind, value in projection)
        result[name] = parse_module(text, name, spec["minimum"])[:3]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="temporary upstream input directory")
    args = parser.parse_args()
    try:
        fetch_rules(args.output_dir)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
