#!/usr/bin/env bash
set -euo pipefail

ENV_OUT="${1:-/tmp/tibet-continuityd-appliance.env}"
STATE_ROOT="${TIBET_APPLIANCE_STATE_ROOT:-/var/lib/tibet}"
LOG_ROOT="${TIBET_APPLIANCE_LOG_ROOT:-/var/log/tibet}"

echo "preparing continuityd appliance lanes"

mkdir -p \
  "$STATE_ROOT/inbox" \
  "$STATE_ROOT/quarantine" \
  "$STATE_ROOT/triage" \
  "$STATE_ROOT/outbox" \
  "$STATE_ROOT/outbox.staging" \
  "$LOG_ROOT"

touch "$LOG_ROOT/continuityd-audit.jsonl"

cat >"$ENV_OUT" <<'EOF'
TIBET_CONTINUITYD_INBOX=__INBOX__
TIBET_CONTINUITYD_QUARANTINE=__QUARANTINE__
TIBET_CONTINUITYD_TRIAGE=__TRIAGE__
TIBET_CONTINUITYD_OUTBOX=__OUTBOX__
TIBET_CONTINUITYD_OUTBOX_STAGING=__OUTBOX_STAGING__
TIBET_CONTINUITYD_AUDIT=__AUDIT__
TIBET_CONTINUITYD_MODE=active
TIBET_CONTINUITYD_LOG_LEVEL=INFO
TIBET_CONTINUITYD_COALESCE_DEBOUNCE_MS=350
TIBET_CONTINUITYD_COALESCE_MAX_PENDING_AGE_MS=5000
TIBET_CONTINUITYD_COALESCE_HIGH_CHURN_THRESHOLD=5
EOF

sed -i \
  -e "s#__INBOX__#$STATE_ROOT/inbox#g" \
  -e "s#__QUARANTINE__#$STATE_ROOT/quarantine#g" \
  -e "s#__TRIAGE__#$STATE_ROOT/triage#g" \
  -e "s#__OUTBOX__#$STATE_ROOT/outbox#g" \
  -e "s#__OUTBOX_STAGING__#$STATE_ROOT/outbox.staging#g" \
  -e "s#__AUDIT__#$LOG_ROOT/continuityd-audit.jsonl#g" \
  "$ENV_OUT"

echo
echo "prepared:"
echo "  inbox=$STATE_ROOT/inbox"
echo "  quarantine=$STATE_ROOT/quarantine"
echo "  triage=$STATE_ROOT/triage"
echo "  outbox=$STATE_ROOT/outbox"
echo "  outbox_staging=$STATE_ROOT/outbox.staging"
echo "  audit=$LOG_ROOT/continuityd-audit.jsonl"
echo "  env=$ENV_OUT"
