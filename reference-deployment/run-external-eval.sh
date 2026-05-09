#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
  cat <<'EOF'
usage:
  bash run-external-eval.sh portable [bundle.tza]
  bash run-external-eval.sh systemd
  bash run-external-eval.sh dual-node

tracks:
  portable   peer-eval kit without systemd
  systemd    appliance runbook + prepare flow
  dual-node  one-shot handoff lab demo
EOF
}

if [ "$#" -lt 1 ]; then
  usage
  exit 1
fi

track="$1"
shift || true

case "$track" in
  portable)
    exec bash "$BASE_DIR/portable-eval/run-eval.sh" "$@"
    ;;
  systemd)
    echo "== systemd appliance =="
    echo
    echo "read first:"
    echo "  $BASE_DIR/systemd-appliance/RUNBOOK.md"
    echo
    echo "quick prepare:"
    echo "  bash $BASE_DIR/systemd-appliance/prepare-appliance.sh /tmp/tibet-continuityd-appliance.env"
    echo
    echo "status helper:"
    echo "  bash $BASE_DIR/systemd-appliance/show-status.sh"
    ;;
  dual-node)
    exec bash "$BASE_DIR/dual-node-lab/run-lab-demo.sh" "$@"
    ;;
  *)
    usage
    exit 1
    ;;
esac
