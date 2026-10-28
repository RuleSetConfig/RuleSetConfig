#!/usr/bin/env python3
"""Generate proxy/direct companions with keywords and precise short-name suffixes."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from domain_keywords import KEYWORD_SOURCE, read_inline_keywords, read_companion_suffixes
from ip_rulesets import compile_pair
from ruleset_format import RULE_SET_VERSION


def digest(path):
    data = Path(path).read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def build(root, output, sing_box):
    root, output = Path(root).resolve(), Path(output).resolve()
    if output == root:
        raise ValueError("use an isolated output directory")
    policies = read_inline_keywords(root)
    suffix_policies = read_companion_suffixes(root)
    with tempfile.TemporaryDirectory(prefix="keyword-build-") as temporary:
        candidate = Path(temporary)
        names = []
        for policy, keywords in policies.items():
            name = policy.upper() + "-RULE-SET"
            names.append(name)
            words = sorted(keywords)
            suffixes = sorted(suffix_policies[policy])
            scope = "keywords and precise short-name domains" if suffixes else "domain keywords"
            text = ("# Surge RULE-SET; companion " + policy + " " + scope + ".\n"
                    "# Source: " + KEYWORD_SOURCE + "; do not edit generated outputs.\n")
            text += "".join("DOMAIN-KEYWORD," + word + "\n" for word in words)
            text += "".join("DOMAIN-SUFFIX," + host + "\n" for host in suffixes)
            (candidate / (name + ".list")).write_text(text, encoding="utf-8")
            rules = [{"domain_keyword": words}] if words else []
            if suffixes:
                rules.append({"domain_suffix": suffixes})
            (candidate / (name + ".json")).write_text(
                json.dumps({"version": RULE_SET_VERSION, "rules": rules}, separators=(",", ":")) + "\n")
            compile_pair(candidate, name, sing_box)
        version_text = subprocess.run([sing_box, "version"], text=True, capture_output=True, check=True).stdout
        version = re.search(r"^sing-box version (\S+)", version_text)
        if not version:
            raise ValueError("could not identify sing-box compiler version")
        outputs = {name + extension: digest(candidate / (name + extension))
                   for name in names for extension in (".list", ".srs")}
        manifest = {
            "schema": 1, "name": "keywords", "generator": {"sing_box": version.group(1)},
            "sources": {"domain_keywords": {"url": "repository:" + KEYWORD_SOURCE,
                                            **digest(root / KEYWORD_SOURCE)}},
            "outputs": outputs,
            "keywords": {policy: sorted(words) for policy, words in policies.items()},
            "domain_suffixes": {policy: sorted(values) for policy, values in suffix_policies.items()},
        }
        output.mkdir(parents=True, exist_ok=True)
        for name in outputs:
            shutil.copyfile(candidate / name, output / name)
        (output / "metadata").mkdir(exist_ok=True)
        (output / "metadata/keywords.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--sing-box", default="sing-box")
    args = parser.parse_args()
    manifest = build(args.root, args.output_dir, args.sing_box)
    print(json.dumps(manifest["keywords"], indent=2))


if __name__ == "__main__":
    main()
