"""End-to-end daemon test — Watch + Sniff + audit.

Spawns the daemon in a thread, drops files into the inbox via
inotify, waits a moment, asserts audit log captured them.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest

_PKG = Path("/srv/jtel-stack/packages/tibet-continuityd/src")
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from tibet_continuityd.daemon import (  # noqa: E402
    ContinuityDaemon,
    DaemonConfig,
)
from tibet_continuityd.sniff import TBZ_MAGIC  # noqa: E402


def test_daemon_captures_arrival_and_classifies(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    audit = tmp_path / "audit.jsonl"

    cfg = DaemonConfig(
        inbox=inbox,
        audit_jsonl=audit,
        mode="passive",
        log_level="WARNING",
    )
    daemon = ContinuityDaemon(cfg)

    # Run daemon in a thread; stop after a short window.
    thread = threading.Thread(target=daemon.run, daemon=True)
    thread.start()

    # Give the daemon a moment to set up the inotify watch.
    time.sleep(0.2)

    # Drop two files: one sealed (TBZ magic), one disguised
    sealed = inbox / "trusted.claude.tza"
    sealed.write_bytes(TBZ_MAGIC + b"\x00" * 100)

    disguised = inbox / "fake.claude"
    disguised.write_bytes(b"this is plain text, no magic")

    # Plus a binary that should quarantine
    binary = inbox / "binary"
    binary.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50)

    # Wait for daemon to process
    time.sleep(0.6)

    # Stop daemon
    daemon._stop = True
    thread.join(timeout=2.0)

    assert audit.exists(), "audit jsonl must be written"
    lines = audit.read_text().strip().splitlines()
    assert len(lines) == 3, f"expected 3 audit lines, got {len(lines)}"

    records = [json.loads(line) for line in lines]
    by_class = {r["intake_class"]: r for r in records}

    assert "sealed-tbz" in by_class
    assert by_class["sealed-tbz"]["disposition_hint"] == \
        "trusted-candidate"

    assert "disguised" in by_class
    assert by_class["disguised"]["disposition_hint"] == \
        "triage-disguised"

    assert "executable" in by_class
    assert by_class["executable"]["disposition_hint"] == "quarantine"


def test_daemon_stats_reflect_processing(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    cfg = DaemonConfig(
        inbox=inbox,
        audit_jsonl=tmp_path / "audit.jsonl",
        mode="passive",
        log_level="WARNING",
    )
    daemon = ContinuityDaemon(cfg)

    thread = threading.Thread(target=daemon.run, daemon=True)
    thread.start()
    time.sleep(0.2)

    for i in range(5):
        (inbox / f"sample-{i}.tza").write_bytes(TBZ_MAGIC + bytes([i]) * 10)

    time.sleep(0.5)
    daemon._stop = True
    thread.join(timeout=2.0)

    assert daemon._stats["events_arrival"] >= 5
    assert daemon._stats["events_sniffed"] >= 5
    assert daemon._stats["by_class"].get("sealed-tbz", 0) >= 5
