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
    ("0.0.0.0 ads.example.com", {
        "ads.example.com": True, "child.ads.example.com": False,
        "example.com": False}),
    ("||ads.example.com^", {
        "ads.example.com": True, "child.ads.example.com": True,
        "notads.example.com": False}),
    ("-ad123-", {"x-ad123-y.example": True, "ad123.example": False}),
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
            merge.write_filter_partitions(suffix, exact, patterns, root)
            for name in merge.PARTITIONS:
                subprocess.run([args.sing_box, "rule-set", "compile", "-o",
                                str(root/f"{name}.srs"), str(root/f"{name}.json")], check=True)
            for host, expected in cases.items():
                outputs = []
                for name in merge.PARTITIONS:
                    result = subprocess.run([args.sing_box, "rule-set", "match", "-f", "binary",
                                             str(root/f"{name}.srs"), host],
                                            text=True, capture_output=True, check=True)
                    outputs.append(result.stdout + result.stderr)
                actual = any("match rules." in output for output in outputs)
                if actual != expected:
                    raise AssertionError((text, host, expected, outputs))
                tested += 1
    print(f"native sing-box matching: {tested}/{tested} passed")


if __name__ == "__main__":
    main()
