#!/usr/bin/env python3
"""Compile isolated fixtures and check their actual sing-box binary matches."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("merge_filter", ROOT / "scripts/merge-filter.py")
merge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge)

CASES = [
    ("-applog*.fqnovel.com^", {
        "api-applog.fqnovel.com": True, "x.api-applog.foo.fqnovel.com": True,
        "applog.fqnovel.com": False, "www.fqnovel.com": False,
        "api-applog.fqnovel.com.evil.net": False}),
    ("||ad*.example.com^", {
        "ad.example.com": True, "x.ads.example.com": True,
        "bad.example.com": False, "ads.example.com.evil": False}),
    (r"/^(a|c)\.[0-9a-f]{56}\.com$/", {
        "a." + "a0" * 28 + ".com": True,
        "c." + "af" * 28 + ".com": True,
        "b." + "a0" * 28 + ".com": False,
        "a." + "a0" * 27 + ".com": False}),
    (r"/^94\.242\.247\.(2[0-9]|3[0-2])/", {
        "94.242.247.20": True, "94.242.247.200": True,
        "94.242.247.32": True, "94.242.247.33": False,
        "94.242.248.20": False}),
    ("||194.63.143.96^", {"194.63.143.96": True, "194.63.143.97": False}),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", default="sing-box")
    args = parser.parse_args()
    tested = 0
    with tempfile.TemporaryDirectory(prefix="native-filter-") as directory:
        root = Path(directory)
        for text, cases in CASES:
            entries, reason = merge.domain_rule(text)
            if entries is None:
                raise AssertionError((text, reason))
            suffix = {v for k, v in entries if k == "domain_suffix"}
            exact = {v for k, v in entries if k == "domain"}
            patterns = {(k, v) for k, v in entries if k not in {"domain", "domain_suffix"}}
            merge.write_domain_rulesets(suffix, exact, root/"filter.list", root/"filter.json", patterns)
            subprocess.run([args.sing_box, "rule-set", "compile", "-o", str(root/"filter.srs"), str(root/"filter.json")], check=True)
            for host, expected in cases.items():
                result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary", str(root/"filter.srs"), host],
                                        text=True, capture_output=True, check=True)
                actual = "match rules." in (result.stdout + result.stderr)
                if actual != expected:
                    raise AssertionError((text, host, expected, result.stdout, result.stderr))
                tested += 1
    print(f"native sing-box matching: {tested}/{tested} passed")


if __name__ == "__main__":
    main()
