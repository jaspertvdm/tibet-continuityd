#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="${1:-${TIBET_DUAL_NODE_LAB_ROOT:-/tmp/continuityd-dual-node-lab}}"

stop_node() {
  local node="$1"
  local base="$LAB_ROOT/$node"
  if [ ! -f "$base/pid" ]; then
    echo "$node not running (no pid file)"
    return
  fi
  local pid
  pid="$(cat "$base/pid")"
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    sleep 0.2
    wait "$pid" 2>/dev/null || true
    echo "stopped $node pid=$pid"
  else
    echo "$node pid $pid already dead"
  fi
  rm -f "$base/pid"
}

stop_node node-a
stop_node node-b
