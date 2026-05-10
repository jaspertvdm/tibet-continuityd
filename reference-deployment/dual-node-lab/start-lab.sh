#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REF_BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../_lib.sh
source "$REF_BASE/_lib.sh"
_setup_all_paths

LAB_ROOT="${1:-${TIBET_DUAL_NODE_LAB_ROOT:-/tmp/continuityd-dual-node-lab}}"

start_node() {
  local node="$1"
  local base="$LAB_ROOT/$node"
  if [ ! -f "$base/env" ]; then
    echo "missing env for $node: $base/env" >&2
    exit 1
  fi
  if [ -f "$base/pid" ] && kill -0 "$(cat "$base/pid")" 2>/dev/null; then
    echo "$node already running with pid $(cat "$base/pid")"
    return
  fi
  set -a
  # shellcheck disable=SC1090
  . "$base/env"
  set +a
  nohup env \
    PYTHONPATH="$CONT_SRC:$DROP_SRC${PYTHONPATH:+:$PYTHONPATH}" \
    TIBET_CONTINUITYD_INBOX="$TIBET_CONTINUITYD_INBOX" \
    TIBET_CONTINUITYD_QUARANTINE="$TIBET_CONTINUITYD_QUARANTINE" \
    TIBET_CONTINUITYD_TRIAGE="$TIBET_CONTINUITYD_TRIAGE" \
    TIBET_CONTINUITYD_OUTBOX="$TIBET_CONTINUITYD_OUTBOX" \
    TIBET_CONTINUITYD_OUTBOX_STAGING="$TIBET_CONTINUITYD_OUTBOX_STAGING" \
    TIBET_CONTINUITYD_AUDIT="$TIBET_CONTINUITYD_AUDIT" \
    TIBET_CONTINUITYD_MODE="$TIBET_CONTINUITYD_MODE" \
    TIBET_CONTINUITYD_ENABLE_SEAL="$TIBET_CONTINUITYD_ENABLE_SEAL" \
    TIBET_CONTINUITYD_LOG_LEVEL="$TIBET_CONTINUITYD_LOG_LEVEL" \
    TIBET_CONTINUITYD_OUTBOX_RECEIVER="$TIBET_CONTINUITYD_OUTBOX_RECEIVER" \
    TIBET_CONTINUITYD_COALESCE_DEBOUNCE_MS="$TIBET_CONTINUITYD_COALESCE_DEBOUNCE_MS" \
    TIBET_CONTINUITYD_COALESCE_MAX_PENDING_AGE_MS="$TIBET_CONTINUITYD_COALESCE_MAX_PENDING_AGE_MS" \
    TIBET_CONTINUITYD_COALESCE_HIGH_CHURN_THRESHOLD="$TIBET_CONTINUITYD_COALESCE_HIGH_CHURN_THRESHOLD" \
    python3 -m tibet_continuityd >>"$base/daemon.log" 2>&1 < /dev/null &
  echo $! >"$base/pid"
  echo "started $node pid=$(cat "$base/pid")"
}

start_node node-a
start_node node-b
sleep 0.4
