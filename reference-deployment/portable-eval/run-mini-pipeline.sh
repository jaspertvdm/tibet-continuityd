#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REF_BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$REF_BASE/../../../.." && pwd)}"

CONT_SRC="$REPO_ROOT/packages/tibet-continuityd/src"
FIXTURE_BASE="$REPO_ROOT/sandbox/ai/codex/continuityd-test-packages"
AUDIT_SUMMARY="$REPO_ROOT/packages/tibet-continuityd/scripts/audit_summary.py"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/continuityd-portable-eval.XXXXXX")"
INBOX="$TMP_ROOT/inbox"
AUDIT="$TMP_ROOT/audit.jsonl"
LOG="$TMP_ROOT/daemon.log"
mkdir -p "$INBOX"

cleanup() {
  if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "mini-pipeline temp_root: $TMP_ROOT"
echo

PYTHONPATH="$CONT_SRC${PYTHONPATH:+:$PYTHONPATH}" \
TIBET_CONTINUITYD_INBOX="$INBOX" \
TIBET_CONTINUITYD_AUDIT="$AUDIT" \
TIBET_CONTINUITYD_MODE="passive" \
TIBET_CONTINUITYD_COALESCE_DEBOUNCE_MS="80" \
TIBET_CONTINUITYD_LOG_LEVEL="WARNING" \
python3 -m tibet_continuityd >"$LOG" 2>&1 &
DAEMON_PID="$!"

sleep 0.3

drop_one() {
  local src="$1"
  local name="$2"
  cp "$src" "$INBOX/$name"
}

# Two fixtures intentionally share the same semantic surface name.
# Replay them as two distinct settled arrivals, not one churned path.
drop_one "$FIXTURE_BASE/trusted/2026-05-09.demo.claude" "2026-05-09.demo.claude"
sleep 0.25
rm -f "$INBOX/2026-05-09.demo.claude"
sleep 0.15
drop_one "$FIXTURE_BASE/triage/2026-05-09.demo.claude" "2026-05-09.demo.claude"
sleep 0.25

drop_one "$FIXTURE_BASE/reseal/2026-05-09.session-resume.json" "2026-05-09.session-resume.json"
sleep 0.20
drop_one "$FIXTURE_BASE/quarantine/2026-05-09.agent-drop.exe" "2026-05-09.agent-drop.exe"
sleep 0.20
drop_one "$FIXTURE_BASE/reject/2026-05-09.operator-note.pdf" "2026-05-09.operator-note.pdf"
sleep 0.50

kill -TERM "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

python3 - "$AUDIT" <<'PY'
import json
import sys
from pathlib import Path

audit = Path(sys.argv[1])
records = [json.loads(line) for line in audit.read_text().splitlines() if line.strip()]

expected = {
    "2026-05-09.demo.claude": ("sealed-tbz", "trusted-candidate"),
    "2026-05-09.session-resume.json": ("json-text", "reseal-candidate"),
    "2026-05-09.agent-drop.exe": ("executable", "quarantine"),
    "2026-05-09.operator-note.pdf": ("pdf", "reject"),
}

# two files intentionally share the same basename; assert both dispositions appear
demo_records = [r for r in records if r["name"] == "2026-05-09.demo.claude"]
ok = True

if len(records) != 5:
    ok = False
    print(f"FAIL audit_count expected=5 actual={len(records)}")

demo_pairs = {(r["intake_class"], r["disposition_hint"]) for r in demo_records}
required_demo_pairs = {
    ("sealed-tbz", "trusted-candidate"),
    ("disguised", "triage-disguised"),
}
if demo_pairs != required_demo_pairs:
    ok = False
    print(f"FAIL demo_pairs expected={sorted(required_demo_pairs)} actual={sorted(demo_pairs)}")

for rec in records:
    if rec["name"] == "2026-05-09.demo.claude":
        continue
    exp = expected.get(rec["name"])
    if exp is None:
        ok = False
        print(f"FAIL unexpected_record name={rec['name']}")
        continue
    pair = (rec["intake_class"], rec["disposition_hint"])
    if pair != exp:
        ok = False
        print(f"FAIL name={rec['name']} expected={exp} actual={pair}")

if ok:
    print("mini_pipeline_status=PASS")
else:
    print("mini_pipeline_status=FAIL")
    raise SystemExit(1)
PY

echo
python3 "$AUDIT_SUMMARY" --audit "$AUDIT"
echo
echo "mini_pipeline_artifacts:"
echo "  inbox=$INBOX"
echo "  audit=$AUDIT"
echo "  log=$LOG"
