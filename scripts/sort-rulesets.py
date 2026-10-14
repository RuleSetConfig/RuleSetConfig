#!/usr/bin/env python3
"""Sort repository lists, retaining TLDs first and IPv4 before IPv6."""

import argparse
from pathlib import Path
import sys

from rule_sorting import check_ruleset_order, is_domain_set, ruleset_paths, sort_list_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="check ordering without modifying files (default)")
    mode.add_argument("--write", action="store_true", help="sort lists in place")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if args.write:
        for path in ruleset_paths(root):
            before = path.read_text(encoding="utf-8")
            after = sort_list_text(before, domain_set=is_domain_set(path))
            if after != before:
                path.write_text(after, encoding="utf-8")
                print(f"sorted {path.relative_to(root)}")
    try:
        count = check_ruleset_order(root)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"ascending order verified for {count} rule lists")
    return 0


if __name__ == "__main__":
    sys.exit(main())
