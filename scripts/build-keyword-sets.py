#!/usr/bin/env python3
"""Generate proxy/direct companions with retained keywords and bounded suffixes."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from domain_keywords import KEYWORD_SOURCE, IMPORT_SOURCE
from rust_core import CODE_ROOT, RUST_SOURCES, generate
from ip_rulesets import compile_pair
from ruleset_format import RULE_SET_VERSION


def digest(path):
    data = Path(path).read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def build(root, output, sing_box):
    root, output = Path(root).resolve(), Path(output).resolve()
    if output == root:
        raise ValueError("use an isolated output directory")
    sources = {"domain_keywords": {"url": "repository:" + KEYWORD_SOURCE,
                                    **digest(root / KEYWORD_SOURCE)}}
    import_path = root / IMPORT_SOURCE
    if import_path.is_file():
        plan = json.loads(import_path.read_text())
        for key, relative in {"import_policy": IMPORT_SOURCE,
                              "import_selector": "scripts/import-companion-domains.py",
                              "upstream_licence": "source/companion-upstream-LICENSE.txt",
                              "ranking_notice": "source/ranked-domain-NOTICE.md"}.items():
            sources[key] = {"url": "repository:" + relative, **digest(root / relative)}
        for key, record in plan["sources"].items():
            sources["upstream_" + key] = {name: record[name] for name in ("url", "bytes", "sha256")}
    for key, relative in RUST_SOURCES.items():
        sources[key] = {"url": "repository:" + relative, **digest(CODE_ROOT / relative)}
    with tempfile.TemporaryDirectory(prefix="keyword-build-") as temporary:
        candidate = Path(temporary)
        projected = generate(root, candidate)
        policies = {p: projected["keywords"][p] for p in ("proxy", "direct")}
        suffix_policies = {p: projected["domain_suffixes"][p] for p in policies}
        exact_policies = {p: projected["domains"][p] for p in policies}
        names = [p.upper() + "-RULE-SET" for p in policies]
        for name in names:
            compile_pair(candidate, name, sing_box)
        version_text = subprocess.run([sing_box, "version"], text=True, capture_output=True, check=True).stdout
        version = re.search(r"^sing-box version (\S+)", version_text)
        if not version:
            raise ValueError("could not identify sing-box compiler version")
        outputs = {name + extension: digest(candidate / (name + extension))
                   for name in names for extension in (".list", ".srs")}
        manifest = {
            "schema": 1, "name": "keywords", "generator": {"sing_box": version.group(1)},
            "sources": sources,
            "outputs": outputs,
            "keywords": {policy: sorted(words) for policy, words in policies.items()},
            "domain_suffixes": {policy: sorted(values) for policy, values in suffix_policies.items()},
            "domains": {policy: sorted(values) for policy, values in exact_policies.items()},
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
    print(json.dumps({policy: len(manifest["keywords"][policy]) + len(manifest["domain_suffixes"][policy]) + len(manifest["domains"][policy])
                      for policy in ("proxy", "direct")}, indent=2))


if __name__ == "__main__":
    main()
