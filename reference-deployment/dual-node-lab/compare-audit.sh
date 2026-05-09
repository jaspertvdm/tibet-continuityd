#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="${1:-${TIBET_DUAL_NODE_LAB_ROOT:-/tmp/continuityd-dual-node-lab}}"

python3 - "$LAB_ROOT/node-a/audit.jsonl" "$LAB_ROOT/node-b/audit.jsonl" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

a_path = Path(sys.argv[1])
b_path = Path(sys.argv[2])

def load(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

def summarize(records):
    return {
        "count": len(records),
        "stages": Counter(r.get("stage") for r in records),
        "by_disposition": Counter(
            r.get("disposition") or r.get("disposition_hint")
            for r in records
            if r.get("disposition") or r.get("disposition_hint")
        ),
        "surface_hashes": sorted({
            r.get("surface_hash") for r in records if r.get("surface_hash")
        }),
    }

a = summarize(load(a_path))
b = summarize(load(b_path))

print("node-a:")
print(f"  audit_records={a['count']}")
print(f"  stages={dict(a['stages'])}")
print(f"  dispositions={dict(a['by_disposition'])}")
print()
print("node-b:")
print(f"  audit_records={b['count']}")
print(f"  stages={dict(b['stages'])}")
print(f"  dispositions={dict(b['by_disposition'])}")
print()

same_stage_pattern = dict(a["stages"]) == dict(b["stages"])
same_disposition_pattern = dict(a["by_disposition"]) == dict(b["by_disposition"])
print(f"same_stage_pattern={same_stage_pattern}")
print(f"same_disposition_pattern={same_disposition_pattern}")

shared_hashes = sorted(set(a["surface_hashes"]) & set(b["surface_hashes"]))
print(f"shared_surface_hashes={len(shared_hashes)}")
if not shared_hashes:
    print("  note: zero shared surface hashes is acceptable here because reseal")
    print("        changes the filename/surface on the forwarded bundle")
for h in shared_hashes[:10]:
    print(f"  {h}")

required = {"sniff", "verify-fork", "seal"}
a_ok = required.issubset(a["stages"])
b_ok = required.issubset(b["stages"])
if a_ok and b_ok and same_stage_pattern and same_disposition_pattern:
    print("dual_node_compare_status=PASS")
else:
    print("dual_node_compare_status=FAIL")
    raise SystemExit(1)
PY
