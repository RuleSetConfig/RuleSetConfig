#!/usr/bin/env python3
"""Compile and validate rule sets while keeping the published format at v5."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

RULE_SET_VERSION = 5


def compile_ruleset(source, output, sing_box="sing-box"):
    source, output = Path(source).resolve(), Path(output).resolve()
    if source == output:
        raise ValueError("rule-set source and binary output must be different files")
    document = json.loads(source.read_text(encoding="utf-8"))
    if document.get("version") != RULE_SET_VERSION:
        raise ValueError(f"expected rule-set source format version {RULE_SET_VERSION}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ruleset-compile-", dir=output.parent) as directory:
        binary = Path(directory) / "candidate.srs"
        decoded = Path(directory) / "candidate.json"
        subprocess.run([sing_box, "rule-set", "compile", "-o", str(binary), str(source)],
                       check=True)
        data = binary.read_bytes()
        if len(data) < 4 or data[:3] != b"SRS" or not 2 <= data[3] <= RULE_SET_VERSION:
            raise ValueError("compiler returned an unsupported rule-set binary format")
        # The upstream CLI lowers v5 to v2 when no newer fields are used:
        # https://github.com/SagerNet/sing-box/blob/v1.14.2/cmd/sing-box/cmd_rule_set_compile.go#L80
        # Binary formats 2-5 share the rule encoding used here; the v1 domain
        # encoding is deliberately excluded. Keep the compressed payload intact.
        if data[3] != RULE_SET_VERSION:
            binary.write_bytes(data[:3] + bytes([RULE_SET_VERSION]) + data[4:])
        subprocess.run([sing_box, "rule-set", "decompile", "-o", str(decoded), str(binary)],
                       check=True)
        if json.loads(decoded.read_text(encoding="utf-8")).get("version") != RULE_SET_VERSION:
            raise ValueError("native decoder did not confirm rule-set format version 5")
        os.replace(binary, output)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("-o", "--output", required=True, type=Path)
    parser.add_argument("--sing-box", default="sing-box")
    args = parser.parse_args()
    compile_ruleset(args.source, args.output, args.sing_box)


if __name__ == "__main__":
    main()
