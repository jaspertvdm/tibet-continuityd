#!/usr/bin/env bash
set -euo pipefail

AUDIT="${1:-${TIBET_APPLIANCE_LOG_ROOT:-/var/log/tibet}/continuityd-audit.jsonl}"
SCRIPT="/srv/jtel-stack/packages/tibet-continuityd/scripts/audit_summary.py"

python3 "$SCRIPT" --audit "$AUDIT"
