#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="${1:-${TIBET_DUAL_NODE_LAB_ROOT:-/tmp/continuityd-dual-node-lab}}"
mkdir -p "$LAB_ROOT"

make_node() {
  local node="$1"
  local base="$LAB_ROOT/$node"
  mkdir -p \
    "$base/inbox" \
    "$base/quarantine" \
    "$base/triage" \
    "$base/outbox" \
    "$base/outbox.staging"
  : >"$base/audit.jsonl"
  : >"$base/daemon.log"
  cat >"$base/env" <<EOF
TIBET_CONTINUITYD_INBOX=$base/inbox
TIBET_CONTINUITYD_QUARANTINE=$base/quarantine
TIBET_CONTINUITYD_TRIAGE=$base/triage
TIBET_CONTINUITYD_OUTBOX=$base/outbox
TIBET_CONTINUITYD_OUTBOX_STAGING=$base/outbox.staging
TIBET_CONTINUITYD_AUDIT=$base/audit.jsonl
TIBET_CONTINUITYD_MODE=active
TIBET_CONTINUITYD_ENABLE_SEAL=true
TIBET_CONTINUITYD_LOG_LEVEL=WARNING
TIBET_CONTINUITYD_OUTBOX_RECEIVER=self.aint
TIBET_CONTINUITYD_COALESCE_DEBOUNCE_MS=120
TIBET_CONTINUITYD_COALESCE_MAX_PENDING_AGE_MS=5000
TIBET_CONTINUITYD_COALESCE_HIGH_CHURN_THRESHOLD=5
EOF
}

make_node node-a
make_node node-b

echo "dual-node lab prepared: $LAB_ROOT"
echo "  node-a env: $LAB_ROOT/node-a/env"
echo "  node-b env: $LAB_ROOT/node-b/env"
