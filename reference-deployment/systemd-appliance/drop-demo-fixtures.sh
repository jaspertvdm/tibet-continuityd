#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REF_BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../_lib.sh
source "$REF_BASE/_lib.sh"
_setup_all_paths

FIXTURE_SCRIPT="$FIXTURE_BASE/drop-fixtures.sh"
TARGET_DIR="${1:-${TIBET_APPLIANCE_STATE_ROOT:-/var/lib/tibet}/inbox}"

if [ ! -d "$TARGET_DIR" ]; then
  echo "target inbox does not exist: $TARGET_DIR" >&2
  exit 1
fi

bash "$FIXTURE_SCRIPT" "$TARGET_DIR"
