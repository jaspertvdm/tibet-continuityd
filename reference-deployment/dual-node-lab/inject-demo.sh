#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REF_BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../_lib.sh
source "$REF_BASE/_lib.sh"
_setup_all_paths

LAB_ROOT="${1:-${TIBET_DUAL_NODE_LAB_ROOT:-/tmp/continuityd-dual-node-lab}}"
WORK="$LAB_ROOT/inject-work"
IDDIR="$WORK/id"
SRC="$WORK/src"
OUT="$LAB_ROOT/node-a/inbox/2026-05-09.dual-node-demo.claude.normal.tza"

mkdir -p "$SRC"
printf 'dual-node lab demo\n' >"$SRC/00-README.md"
printf '{"kind":"dual-node-demo","created_by":"inject-demo.sh"}\n' >"$SRC/payload.json"

PYTHONPATH="$DROP_SRC${PYTHONPATH:+:$PYTHONPATH}" python3 -m tibet_drop init --out "$IDDIR" --aint dualnode.sender >/dev/null
PYTHONPATH="$DROP_SRC${PYTHONPATH:+:$PYTHONPATH}" python3 -m tibet_drop pack \
  --identity "$IDDIR" \
  --receiver-aint dualnode.receiver \
  --receiver-pubkey 0000000000000000000000000000000000000000000000000000000000000000 \
  --input "$SRC" \
  --output "$OUT" \
  --surface-time 2026-05-09 \
  --surface-context dual-node-demo \
  --surface-profile claude \
  --surface-priority normal >/dev/null

echo "injected demo bundle into node-a:"
echo "  $OUT"
