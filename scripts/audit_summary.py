#!/usr/bin/env python3
"""
audit_summary.py — Read continuityd-audit.jsonl and report.

Prints metrics aligned with Codex' maturing-plan:
  - event count by intake_class
  - disposition distribution
  - top filenames
  - rate per second over the run
  - false-positive candidates (operator review hint)

Usage:
  python3 audit_summary.py --audit /var/log/tibet/continuityd-audit.jsonl
  python3 audit_summary.py --audit ./audit.jsonl --since 60   # last 60 sec
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--audit", required=True, type=Path)
    p.add_argument("--since", type=float, default=0,
                   help="Only consider events from last N seconds")
    p.add_argument("--top", type=int, default=10,
                   help="Top N filenames to show")
    args = p.parse_args()

    if not args.audit.exists():
        print(f"audit log not found: {args.audit}", file=sys.stderr)
        return 1

    cutoff = time.time() - args.since if args.since else 0
    records = []
    for line in args.audit.read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("ts", 0) < cutoff:
            continue
        records.append(r)

    if not records:
        print("no records (after filter)")
        return 0

    by_class = Counter(r["intake_class"] for r in records)
    by_disposition = Counter(r["disposition_hint"] for r in records)
    by_extension = Counter(r["extension"] for r in records)
    top_names = Counter(r["name"] for r in records).most_common(args.top)

    ts_min = min(r["ts"] for r in records)
    ts_max = max(r["ts"] for r in records)
    span = max(ts_max - ts_min, 0.001)

    print("─" * 60)
    print(f"  audit summary: {args.audit}")
    print(f"  events:        {len(records)}")
    print(f"  span:          {span:.2f}s")
    print(f"  rate:          {len(records) / span:.1f} ev/sec")
    print("─" * 60)
    print()
    print("  By intake class:")
    for cls, n in by_class.most_common():
        bar = "█" * min(n, 40)
        print(f"    {cls:22s} {n:5d}  {bar}")
    print()
    print("  By disposition:")
    for dis, n in by_disposition.most_common():
        print(f"    {dis:22s} {n:5d}")
    print()
    print(f"  By extension (top 10):")
    for ext, n in by_extension.most_common(10):
        ext_disp = ext if ext else "(none)"
        print(f"    {ext_disp:22s} {n:5d}")
    print()
    print(f"  Top filenames (top {args.top}):")
    for name, n in top_names:
        print(f"    {n:5d}  {name}")
    print()

    # Operator-review hints
    fps = [r for r in records
           if r["intake_class"] in ("disguised", "executable", "pdf")
           and "burst" not in r["name"]
           and "impostor" not in r["name"]
           and "binary" not in r["name"]
           and "document" not in r["name"]]
    if fps:
        print(f"  ⚠ Possible false positives (non-stress filenames):")
        for r in fps[:5]:
            print(f"    {r['intake_class']:18s}  {r['name']}")
        if len(fps) > 5:
            print(f"    ... + {len(fps) - 5} more")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
