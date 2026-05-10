#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REF_BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../_lib.sh
source "$REF_BASE/_lib.sh"
_setup_all_paths

AUDIT="${1:-${TIBET_APPLIANCE_LOG_ROOT:-/var/log/tibet}/continuityd-audit.jsonl}"
SCRIPT="$REPO_ROOT/packages/tibet-continuityd/scripts/audit_summary.py"

python3 "$SCRIPT" --audit "$AUDIT"
