#!/usr/bin/env bash
set -euo pipefail

STATE_ROOT="${TIBET_APPLIANCE_STATE_ROOT:-/var/lib/tibet}"
LOG_ROOT="${TIBET_APPLIANCE_LOG_ROOT:-/var/log/tibet}"

echo "== systemd status =="
if command -v systemctl >/dev/null 2>&1; then
  systemctl status tibet-continuityd --no-pager || true
else
  echo "systemctl not found"
fi

echo
echo "== lane state =="
for dir in \
  "$STATE_ROOT/inbox" \
  "$STATE_ROOT/quarantine" \
  "$STATE_ROOT/triage" \
  "$STATE_ROOT/outbox" \
  "$STATE_ROOT/outbox.staging"
do
  echo "-- $dir"
  if [ -d "$dir" ]; then
    find "$dir" -maxdepth 1 -type f | sort
  else
    echo "(missing)"
  fi
  echo
done

echo "== audit tail =="
if [ -f "$LOG_ROOT/continuityd-audit.jsonl" ]; then
  tail -n 20 "$LOG_ROOT/continuityd-audit.jsonl"
else
  echo "(missing)"
fi
