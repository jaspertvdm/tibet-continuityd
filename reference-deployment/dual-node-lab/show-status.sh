#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="${1:-${TIBET_DUAL_NODE_LAB_ROOT:-/tmp/continuityd-dual-node-lab}}"

show_node() {
  local node="$1"
  local base="$LAB_ROOT/$node"
  echo "== $node =="
  if [ -f "$base/pid" ]; then
    local pid
    pid="$(cat "$base/pid")"
    if kill -0 "$pid" 2>/dev/null; then
      echo "pid=$pid status=running"
    else
      echo "pid=$pid status=dead"
    fi
  else
    echo "status=stopped"
  fi
  for dir in inbox quarantine triage outbox outbox.staging; do
    echo "-- $dir"
    if [ -d "$base/$dir" ]; then
      find "$base/$dir" -maxdepth 1 -type f | sed "s#^$base/$dir/##" | sort
    else
      echo "(missing)"
    fi
  done
  echo "-- audit_tail"
  if [ -f "$base/audit.jsonl" ]; then
    tail -n 10 "$base/audit.jsonl"
  else
    echo "(missing)"
  fi
  echo
}

show_node node-a
show_node node-b
