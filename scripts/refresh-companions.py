#!/usr/bin/env python3
"""Reselect routing companions against candidate TLD and rejection coverage."""

import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from domain_keywords import KEYWORD_SOURCE, read_inline_keywords

CODE_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("companion_builder", CODE_ROOT / "scripts/build-keyword-sets.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
COVERAGE = ("PROXY-DOMAIN-SET.list", "DIRECT-DOMAIN-SET.list",
            "REJECT-DOMAIN-SET.list", "REJECT-RULE-SET.list")
PAIRS = ("PROXY-RULE-SET", "DIRECT-RULE-SET")


def refresh(root, output, source_dir, sing_box="sing-box", fetch=False):
    root, output, source_dir = (Path(path).resolve() for path in (root, output, source_dir))
    if output == root or source_dir in {root, output}:
        raise ValueError("use separate upstream and isolated candidate directories")

    def latest(relative):
        candidate = output / relative
        return candidate if candidate.is_file() else root / relative

    # Validate the candidate TLD pair before changing its keyword fingerprint.
    tld = json.loads(latest("metadata/tld.json").read_text())
    for policy in ("PROXY", "DIRECT"):
        for extension in (".list", ".srs"):
            name = policy + "-DOMAIN-SET" + extension
            if BUILDER.digest(latest(name)) != tld["outputs"].get(name):
                raise ValueError(f"candidate TLD fingerprint differs: {name}")

    with tempfile.TemporaryDirectory(prefix="companion-refresh-") as temporary:
        stage, built = Path(temporary) / "snapshot", Path(temporary) / "built"
        shutil.copytree(root / "source", stage / "source")
        (stage / "scripts").mkdir()
        shutil.copyfile(root / "scripts/import-companion-domains.py",
                        stage / "scripts/import-companion-domains.py")
        coverage = {}
        for name in COVERAGE:
            source = latest(name)
            shutil.copyfile(source, stage / name)
            coverage[name] = BUILDER.digest(source)
        before = json.loads((stage / KEYWORD_SOURCE).read_text())
        import_audit = Path(temporary) / "import-audit.json"
        command = [sys.executable, str(CODE_ROOT / "scripts/import-companion-domains.py"),
                   "--root", str(stage), "--source-dir", str(source_dir), "--audit", str(import_audit)]
        if fetch:
            command.append("--fetch")
        subprocess.run(command, check=True)
        # The Rust projection validates the reselected policy before any result
        # is copied back to the candidate directory or the working repository.
        BUILDER.build(stage, built, sing_box)
        after = json.loads((stage / KEYWORD_SOURCE).read_text())
        keywords = {policy: list(values) for policy, values in read_inline_keywords(stage).items()}
        if tld["domain_sync"]["inline_keywords"] != keywords:
            raise ValueError("TLD snapshot keyword inventory differs from the routing policy")
        tld["sources"]["inline_keywords"] = {
            "url": "repository:" + KEYWORD_SOURCE, **BUILDER.digest(stage / KEYWORD_SOURCE)}
        changes = {}
        for policy in ("proxy", "direct"):
            changes[policy] = {}
            for field in ("_domain_suffixes", "_domains"):
                previous = set(before.get(policy + field, []))
                current = set(after[policy + field])
                changes[policy][field[1:]] = {
                    "added": sorted(current - previous), "removed": sorted(previous - current)}
        audit = {"schema": 1, "coverage": coverage, "changes": changes,
                 "selection": json.loads(import_audit.read_text())}
        (built / "metadata/tld.json").write_text(json.dumps(tld, indent=2) + "\n")
        (built / "source").mkdir()
        shutil.copyfile(stage / KEYWORD_SOURCE, built / KEYWORD_SOURCE)
        (built / "companion-sync-audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
        domain_audit = output / "domain-sync-audit.json"
        if domain_audit.is_file():
            evidence = json.loads(domain_audit.read_text())
            evidence["sources"]["inline_keywords"] = tld["sources"]["inline_keywords"]
            (built / domain_audit.name).write_text(json.dumps(evidence, indent=2) + "\n")
        outputs = [name + extension for name in PAIRS for extension in (".list", ".srs")]
        outputs += [KEYWORD_SOURCE, "metadata/keywords.json", "metadata/tld.json", "companion-sync-audit.json"]
        if domain_audit.is_file():
            outputs.append(domain_audit.name)
        for relative in outputs:
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(built / relative, destination)
    return audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    audit = refresh(args.root, args.output_dir, args.source_dir, args.sing_box, args.fetch)
    print(json.dumps({policy: audit["selection"][policy]["total_rules"]
                      for policy in ("proxy", "direct")}, indent=2))


if __name__ == "__main__":
    main()
