#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="${1:-${TIBET_DUAL_NODE_LAB_ROOT:-/tmp/continuityd-dual-node-lab}}"
A_OUT="$LAB_ROOT/node-a/outbox"
B_IN="$LAB_ROOT/node-b/inbox"

latest="$(find "$A_OUT" -maxdepth 1 -type f -name '*.tza' | sort | tail -n 1)"
if [ -z "$latest" ]; then
  echo "no sealed bundle found in node-a outbox" >&2
  exit 1
fi

target="$B_IN/$(basename "$latest")"
cp "$latest" "$target"
echo "bridged:"
echo "  from=$latest"
echo "  to=$target"
