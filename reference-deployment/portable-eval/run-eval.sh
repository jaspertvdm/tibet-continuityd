#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REF_BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../_lib.sh
source "$REF_BASE/_lib.sh"
_setup_all_paths

CHECK_ENV="$SCRIPT_DIR/check-env.sh"
RUN_MINI="$SCRIPT_DIR/run-mini-pipeline.sh"
VECTOR_FILE="$FIXTURE_BASE/conformance-vectors-v1.jsonl"
VECTOR_CHECK="$FIXTURE_BASE/check-conformance-vectors.py"

BUNDLE_PATH="${1:-}"

bundle_status="SKIP"
vector_status="SKIP"
pipeline_status="SKIP"
bundle_verifier="NONE"
bundle_unpack_status="SKIP"
bundle_extract_dir=""

show_hex32() {
  local path="$1"
  if command -v xxd >/dev/null 2>&1; then
    xxd -l 32 "$path"
  elif command -v od >/dev/null 2>&1; then
    od -An -tx1 -N32 "$path"
  else
    echo "note: no hexdump tool available"
  fi
}

maybe_show_readme() {
  local dir="$1"
  local readme=""
  readme="$(find "$dir" -maxdepth 2 -type f \( -iname '00-README.md' -o -iname 'README.md' \) | head -n 1 || true)"
  if [ -n "$readme" ] && [ -f "$readme" ]; then
    echo
    echo "-- readme preview --"
    sed -n '1,40p' "$readme"
  fi
}

try_tbz_bundle() {
  local bundle="$1"
  local extract_dir="$2"
  tbz verify "$bundle" || return 1
  tbz inspect "$bundle" || return 1
  mkdir -p "$extract_dir"
  tbz unpack "$bundle" "$extract_dir" || return 1
}

try_tibet_drop_bundle() {
  local bundle="$1"
  local extract_dir="$2"
  PYTHONPATH="$DROP_SRC${PYTHONPATH:+:$PYTHONPATH}" python3 -m tibet_drop verify "$bundle" || return 1
  PYTHONPATH="$DROP_SRC${PYTHONPATH:+:$PYTHONPATH}" python3 -m tibet_drop inspect "$bundle" || return 1
  mkdir -p "$extract_dir"
  PYTHONPATH="$DROP_SRC${PYTHONPATH:+:$PYTHONPATH}" python3 -m tibet_drop unpack "$bundle" --out "$extract_dir" || return 1
}

echo "== preflight =="
bash "$CHECK_ENV"
echo

if [ -n "$BUNDLE_PATH" ]; then
  echo "== bundle check =="
  if [ ! -f "$BUNDLE_PATH" ]; then
    echo "bundle_status=FAIL missing_bundle"
    bundle_status="FAIL"
  else
    file "$BUNDLE_PATH" || true
    show_hex32 "$BUNDLE_PATH" || true
    sha256sum "$BUNDLE_PATH" || true
    wc -c "$BUNDLE_PATH" || true
    bundle_extract_dir="$(mktemp -d "${TMPDIR:-/tmp}/continuityd-bundle-eval.XXXXXX")"

    if command -v tbz >/dev/null 2>&1; then
      if try_tbz_bundle "$BUNDLE_PATH" "$bundle_extract_dir"; then
        bundle_verifier="tbz"
        bundle_unpack_status="PASS"
        bundle_status="PASS"
      else
        echo "note: tbz path did not validate this bundle"
      fi
    fi

    if [ "$bundle_status" != "PASS" ] && python3 -c "import sys; sys.path.insert(0, '$DROP_SRC'); import tibet_drop" 2>/dev/null; then
      if try_tibet_drop_bundle "$BUNDLE_PATH" "$bundle_extract_dir"; then
        bundle_verifier="tibet_drop"
        bundle_unpack_status="PASS"
        bundle_status="PASS"
      else
        bundle_status="FAIL"
      fi
    fi

    if [ "$bundle_status" != "PASS" ]; then
      bundle_status="PARTIAL"
      echo "note: no compatible verifier path validated this bundle; this may indicate a format-family mismatch rather than transport corruption"
    else
      echo
      echo "bundle_verifier=$bundle_verifier"
      echo "bundle_unpack_status=$bundle_unpack_status"
      echo "bundle_extract_dir=$bundle_extract_dir"
      echo "-- extracted files --"
      find "$bundle_extract_dir" -maxdepth 2 -type f | sed "s#^$bundle_extract_dir/##" | sort
      maybe_show_readme "$bundle_extract_dir"
    fi
  fi
  echo
fi

echo "== conformance vectors =="
if python3 "$VECTOR_CHECK" --vectors "$VECTOR_FILE" --continuityd-src "$CONT_SRC"; then
  vector_status="PASS"
else
  vector_status="FAIL"
fi
echo

echo "== mini pipeline =="
if bash "$RUN_MINI"; then
  pipeline_status="PASS"
else
  pipeline_status="FAIL"
fi
echo

echo "== summary =="
echo "bundle_status=$bundle_status"
echo "bundle_verifier=$bundle_verifier"
echo "bundle_unpack_status=$bundle_unpack_status"
echo "vector_status=$vector_status"
echo "pipeline_status=$pipeline_status"

overall="PASS"
if [ "$vector_status" != "PASS" ] || [ "$pipeline_status" != "PASS" ]; then
  overall="FAIL"
elif [ "$bundle_status" = "FAIL" ]; then
  overall="FAIL"
elif [ "$bundle_status" = "PARTIAL" ]; then
  overall="PARTIAL"
fi

echo "overall_status=$overall"

if [ "$overall" = "FAIL" ]; then
  exit 1
fi
