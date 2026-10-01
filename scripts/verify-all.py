#!/usr/bin/env python3
"""Decompile and verify every committed .list/.srs pair in the repository."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def verify_manifests(root):
    manifests = sorted((root / "metadata").glob("*.json"))
    for manifest in manifests:
        document = json.loads(manifest.read_text(encoding="utf-8"))
        if document.get("schema") != 1:
            sys.exit(f"error: unsupported manifest schema in {manifest}")
        for relative, expected in document.get("outputs", {}).items():
            path = root / relative
            if not path.is_file():
                sys.exit(f"error: manifest output does not exist: {relative}")
            data = path.read_bytes()
            actual_hash = hashlib.sha256(data).hexdigest()
            if len(data) != expected.get("bytes") or actual_hash != expected.get("sha256"):
                sys.exit(f"error: output does not match {manifest}: {relative}")
        print(f"verified output hashes in {manifest.relative_to(root)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", default="sing-box")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    lists = {path.stem: path for path in root.glob("*.list")}
    binaries = {path.stem: path for path in root.glob("*.srs")}
    if lists.keys() != binaries.keys():
        missing_srs = sorted(lists.keys() - binaries.keys())
        missing_list = sorted(binaries.keys() - lists.keys())
        sys.exit(f"error: unpaired rule sets; missing .srs={missing_srs}, missing .list={missing_list}")
    if not lists:
        sys.exit("error: no rule-set pairs found")

    verifier = root / "scripts" / "build-filter-rulesets.py"
    with tempfile.TemporaryDirectory(prefix="ruleset-verify-") as temp:
        for name in sorted(lists):
            decompiled = Path(temp) / f"{name}.json"
            subprocess.run(
                [args.sing_box, "rule-set", "decompile", "-o", str(decompiled), str(binaries[name])],
                check=True,
            )
            subprocess.run(
                [sys.executable, str(verifier), "verify", "--list", str(lists[name]),
                 "--decompiled", str(decompiled)],
                check=True,
            )
    verify_manifests(root)
    print(f"verified all {len(lists)} committed rule-set pairs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
