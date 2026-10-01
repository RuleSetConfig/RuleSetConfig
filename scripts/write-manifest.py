#!/usr/bin/env python3
"""Write a deterministic provenance manifest for generated rule-set artifacts."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


def digest(path):
    data = Path(path).read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def parse_item(value):
    parts = value.split("|", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("expected NAME|PATH|URL")
    return parts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--sing-box-version", required=True)
    parser.add_argument("--source", action="append", default=[], type=parse_item)
    parser.add_argument("--output", action="append", default=[], required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    sources = {}
    for name, path, url in args.source:
        sources[name] = {"url": url, **digest(path)}
    outputs = {Path(path).name: digest(path) for path in args.output}
    document = {
        "schema": 1,
        "name": args.name,
        "generator": {"sing_box": args.sing_box_version},
        "sources": dict(sorted(sources.items())),
        "outputs": dict(sorted(outputs.items())),
    }
    target = Path(args.manifest)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote provenance manifest {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
