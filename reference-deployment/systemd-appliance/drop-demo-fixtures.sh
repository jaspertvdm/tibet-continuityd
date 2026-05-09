#!/usr/bin/env bash
set -euo pipefail

FIXTURE_SCRIPT="/srv/jtel-stack/sandbox/ai/codex/continuityd-test-packages/drop-fixtures.sh"
TARGET_DIR="${1:-${TIBET_APPLIANCE_STATE_ROOT:-/var/lib/tibet}/inbox}"

if [ ! -d "$TARGET_DIR" ]; then
  echo "target inbox does not exist: $TARGET_DIR" >&2
  exit 1
fi

bash "$FIXTURE_SCRIPT" "$TARGET_DIR"
