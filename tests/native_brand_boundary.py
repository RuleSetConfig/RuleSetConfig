#!/usr/bin/env python3
"""Verify exact literal wildcard encoding with the pinned sing-box core."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ruleset_format import compile_ruleset

SPEC = importlib.util.spec_from_file_location("native_boundary_merge", ROOT / "scripts/merge-filter.py")
MERGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", default="sing-box")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="brand-boundary-native-") as directory:
        root = Path(directory)
        path, source, binary = root / "REJECT-RULE-SET.list", root / "rules.json", root / "rules.srs"
        MERGE.write_domain_rulesets({"suffix.qq.com"}, {"exact.qq.com"}, path, source,
                                   {("domain_wildcard", "track?.qq.com"),
                                    ("logical_and", ("ads", "zijieapi.com"))}, no_domain=True)
        if "\nDOMAIN," in "\n" + path.read_text():
            raise AssertionError("DOMAIN leaked into the published list")
        compile_ruleset(source, binary, args.sing_box)
        cases = {
            "exact.qq.com": True, "sub.exact.qq.com": False, "exact.qq.com.invalid": False,
            "suffix.qq.com": True, "sub.suffix.qq.com": True, "notsuffix.qq.com": False,
            "track1.qq.com": True, "track12.qq.com": False, "sub.track1.qq.com": False,
            "ads.zijieapi.com": True, "plain.zijieapi.com": False, "ads.example.net": False,
        }
        for host, wanted in cases.items():
            result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                     str(binary), "--", host], check=True, capture_output=True, text=True)
            actual = "match rules." in result.stdout + result.stderr
            if actual != wanted:
                raise AssertionError((host, wanted, actual))
        print(str(len(cases)) + " native exact/suffix/wildcard/AND boundary cases passed")


if __name__ == "__main__":
    main()
