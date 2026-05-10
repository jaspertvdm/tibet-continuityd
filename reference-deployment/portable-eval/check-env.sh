#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REF_BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../_lib.sh
source "$REF_BASE/_lib.sh"
_setup_all_paths
VECTOR_FILE="$FIXTURE_BASE/conformance-vectors-v1.jsonl"

status_ok=0
status_warn=0

say_ok() {
  printf '  [OK]   %s\n' "$1"
  status_ok=$((status_ok + 1))
}

say_warn() {
  printf '  [WARN] %s\n' "$1"
  status_warn=$((status_warn + 1))
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

echo "continuityd portable-eval preflight"
echo "repo_root: $REPO_ROOT"
echo

if has_cmd python3; then
  say_ok "python3 aanwezig"
else
  say_warn "python3 ontbreekt"
fi

if has_cmd sha256sum; then
  say_ok "sha256sum aanwezig"
else
  say_warn "sha256sum ontbreekt"
fi

if has_cmd xxd || has_cmd od; then
  say_ok "hexdump tool aanwezig (xxd of od)"
else
  say_warn "geen hexdump tool gevonden (xxd of od)"
fi

if has_cmd file; then
  say_ok "file aanwezig"
else
  say_warn "file ontbreekt"
fi

if has_cmd tbz; then
  say_ok "tbz CLI aanwezig"
else
  say_warn "tbz CLI niet gevonden"
fi

if [ -d "$CONT_SRC" ]; then
  say_ok "continuityd source gevonden"
else
  say_warn "continuityd source ontbreekt: $CONT_SRC"
fi

if [ -d "$DROP_SRC" ]; then
  say_ok "tibet_drop source gevonden"
else
  say_warn "tibet_drop source ontbreekt: $DROP_SRC"
fi

if [ -d "$FIXTURE_BASE" ]; then
  say_ok "fixture kit gevonden"
else
  say_warn "fixture kit ontbreekt: $FIXTURE_BASE"
fi

if [ -f "$VECTOR_FILE" ]; then
  say_ok "conformance vectors aanwezig"
else
  say_warn "conformance vectors ontbreken: $VECTOR_FILE"
fi

echo
echo "samenvatting: ok=$status_ok warn=$status_warn"
if [ "$status_warn" -eq 0 ]; then
  echo "preflight_status=PASS"
else
  echo "preflight_status=PARTIAL"
fi
