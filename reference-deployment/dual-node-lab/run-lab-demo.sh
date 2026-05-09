#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="${1:-${TIBET_DUAL_NODE_LAB_ROOT:-/tmp/continuityd-dual-node-lab}}"
CONT_SRC="/srv/jtel-stack/packages/tibet-continuityd/src"
DROP_SRC="/srv/jtel-stack/sandbox/airdrop-cli/src"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
  for node in node-a node-b; do
    local base="$LAB_ROOT/$node"
    if [ -f "$base/pid" ]; then
      local pid
      pid="$(cat "$base/pid")"
      kill -TERM "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      rm -f "$base/pid"
    fi
  done
}
trap cleanup EXIT

bash "$SELF_DIR/prepare-lab.sh" "$LAB_ROOT" >/dev/null

start_node_inline() {
  local node="$1"
  local base="$LAB_ROOT/$node"
  set -a
  # shellcheck disable=SC1090
  . "$base/env"
  set +a
  PYTHONPATH="$CONT_SRC:$DROP_SRC${PYTHONPATH:+:$PYTHONPATH}" \
    python3 -m tibet_continuityd >>"$base/daemon.log" 2>&1 &
  echo $! >"$base/pid"
}

start_node_inline node-a
start_node_inline node-b
sleep 0.4

bash "$SELF_DIR/inject-demo.sh" "$LAB_ROOT" >/dev/null
sleep 1.2
bash "$SELF_DIR/bridge-a-to-b.sh" "$LAB_ROOT" >/dev/null
sleep 1.2

bash "$SELF_DIR/compare-audit.sh" "$LAB_ROOT"
echo
bash "$SELF_DIR/show-status.sh" "$LAB_ROOT"
