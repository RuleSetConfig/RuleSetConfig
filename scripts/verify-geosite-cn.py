#!/usr/bin/env python3
"""Sanity-check the mirrored geosite-geolocation-cn rule set.

The mirror is a byte-for-byte copy of the upstream binary, so this only has to
prove the file parses and still contains a plausible amount of data. It exists
to catch a truncated download or an upstream format change before committing.

Usage: verify-geosite-cn.py --decompiled geosite-geolocation-cn.json
"""

import argparse
import json
import sys

MIN_DOMAIN_ENTRIES = 5000
DOMAIN_FIELDS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--decompiled", required=True,
                        help="source JSON produced by `sing-box rule-set decompile`")
    args = parser.parse_args()

    doc = json.load(open(args.decompiled, encoding="utf-8"))
    counts = {}
    for rule in doc["rules"]:
        for field, value in rule.items():
            if isinstance(value, list):
                counts[field] = counts.get(field, 0) + len(value)

    total = sum(counts.get(field, 0) for field in DOMAIN_FIELDS)
    print(f"rule set: version={doc.get('version')} rules={len(doc['rules'])} entries={counts}")

    if total < MIN_DOMAIN_ENTRIES:
        print(f"error: only {total} domain entries, expected at least {MIN_DOMAIN_ENTRIES}",
              file=sys.stderr)
        sys.exit(1)

    print(f"ok: {total} domain entries")


if __name__ == "__main__":
    main()
