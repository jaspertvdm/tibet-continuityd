#!/usr/bin/env bash
# Shared helpers for reference-deployment scripts.
# Source via:  source "$(dirname "$0")/../_lib.sh"

# Detect REPO_ROOT by climbing up to find the marker file
# packages/tibet-continuityd/pyproject.toml. Works from any
# location that lives below the repository root.
_detect_repo_root() {
    local d="$1"
    while [ "$d" != "/" ] && [ -n "$d" ]; do
        if [ -f "$d/packages/tibet-continuityd/pyproject.toml" ]; then
            echo "$d"
            return 0
        fi
        d="$(dirname "$d")"
    done
    return 1
}

# Set REPO_ROOT (env-override wins, then auto-detect, then error).
# Caller must define SCRIPT_DIR before sourcing this file.
_setup_repo_root() {
    if [ -z "${SCRIPT_DIR:-}" ]; then
        echo "ERROR: SCRIPT_DIR not set before sourcing _lib.sh" >&2
        return 1
    fi
    if [ -n "${REPO_ROOT:-}" ]; then
        return 0
    fi
    REPO_ROOT="$(_detect_repo_root "$SCRIPT_DIR")"
    if [ -z "$REPO_ROOT" ]; then
        cat <<EOF >&2
ERROR: REPO_ROOT auto-detect failed.

  Searched for 'packages/tibet-continuityd/pyproject.toml'
  upward from: $SCRIPT_DIR

  Set REPO_ROOT manually:
    REPO_ROOT=/path/to/repo $0
EOF
        return 1
    fi
    export REPO_ROOT
}

# Set CONT_SRC default (env-override wins).
_setup_cont_src() {
    if [ -z "${CONT_SRC:-}" ]; then
        CONT_SRC="$REPO_ROOT/packages/tibet-continuityd/src"
    fi
    export CONT_SRC
}

# Set DROP_SRC default (env-override wins).
# Note: tibet-drop is shadow until v0.4 TBZ convergence —
# canonical PyPI tibet-zip integration is parker-ticket-002.
_setup_drop_src() {
    if [ -z "${DROP_SRC:-}" ]; then
        DROP_SRC="$REPO_ROOT/sandbox/airdrop-cli/src"
    fi
    export DROP_SRC
}

# Set FIXTURE_BASE default (env-override wins).
_setup_fixture_base() {
    if [ -z "${FIXTURE_BASE:-}" ]; then
        FIXTURE_BASE="$REPO_ROOT/sandbox/ai/codex/continuityd-test-packages"
    fi
    export FIXTURE_BASE
}

# Convenience: set all four at once.
_setup_all_paths() {
    _setup_repo_root || return 1
    _setup_cont_src
    _setup_drop_src
    _setup_fixture_base
}
