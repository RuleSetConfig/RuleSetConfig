#!/usr/bin/env python3
"""Reject suspiciously large generated rule-set changes before publication."""

import argparse
from pathlib import Path
import sys


def count_rules(path):
    with open(path, encoding="utf-8", errors="strict") as handle:
        return sum(1 for line in handle if line.strip() and not line.lstrip().startswith("#"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--min-ratio", type=float, default=0.80)
    parser.add_argument("--max-ratio", type=float, default=1.25)
    parser.add_argument("--max-rules", type=int, required=True)
    parser.add_argument("--allow-large-change", action="store_true")
    parser.add_argument("--allow-empty", action="store_true",
                        help="allow a legitimately empty IP/pattern partition; change ratios still apply")
    args = parser.parse_args()

    candidate = count_rules(args.candidate)
    if candidate == 0 and not args.allow_empty:
        sys.exit("error: candidate rule set is empty")
    if candidate > args.max_rules:
        sys.exit(f"error: candidate has {candidate} rules, above limit {args.max_rules}")

    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        print(f"no baseline at {baseline_path}; accepted {candidate} candidate rules")
        return 0

    baseline = count_rules(baseline_path)
    ratio = candidate / baseline if baseline else (1.0 if candidate == 0 else float("inf"))
    print(f"change guard: {baseline} -> {candidate} rules ({ratio:.3f}x)")
    if not args.allow_large_change and not args.min_ratio <= ratio <= args.max_ratio:
        sys.exit(
            f"error: rule count ratio {ratio:.3f} is outside "
            f"[{args.min_ratio:.3f}, {args.max_ratio:.3f}]; review and rerun manually "
            "with accept_large_change enabled"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
