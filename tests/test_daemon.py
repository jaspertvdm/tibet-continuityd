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

_TIBET_DROP = Path("/srv/jtel-stack/sandbox/airdrop-cli/src")
if str(_TIBET_DROP) not in sys.path:
    sys.path.insert(0, str(_TIBET_DROP))
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


def test_daemon_coalesces_multiple_writes_to_same_path(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    audit = tmp_path / "audit.jsonl"
    cfg = DaemonConfig(
        inbox=inbox,
        audit_jsonl=audit,
        mode="passive",
        log_level="WARNING",
        coalesce_debounce_ms=80,
    )
    daemon = ContinuityDaemon(cfg)

    thread = threading.Thread(target=daemon.run, daemon=True)
    thread.start()
    time.sleep(0.2)

    target = inbox / "churned.tza"
    target.write_bytes(TBZ_MAGIC + b"A" * 8)
    time.sleep(0.02)
    target.write_bytes(TBZ_MAGIC + b"B" * 16)
    time.sleep(0.02)
    target.write_bytes(TBZ_MAGIC + b"C" * 24)

    time.sleep(0.4)
    daemon._stop = True
    thread.join(timeout=2.0)

    records = [json.loads(line) for line in audit.read_text().splitlines()]
    assert len(records) == 1
    record = records[0]
    assert record["name"] == "churned.tza"
    assert record["coalesced"] is True
    assert record["coalesced_event_count"] >= 2
    assert daemon._stats["events_arrival"] == 1
    assert daemon._stats["events_coalesced"] == 1


def test_daemon_strict_mode_rejects_non_sealed_arrivals(tmp_path):
    """v0.3.3 Mode strict: non-sealed arrivals are rejected
    immediately (no verify-fork-seal pipeline waste)."""
    from tibet_drop.crypto import IdentityKey
    from tibet_continuityd.sniff import TBZ_MAGIC

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    quarantine = tmp_path / "quarantine"

    cfg = DaemonConfig(
        inbox=inbox,
        audit_jsonl=tmp_path / "audit.jsonl",
        mode="strict",
        log_level="WARNING",
        quarantine_dir=quarantine,
    )
    daemon = ContinuityDaemon(cfg)

    thread = threading.Thread(target=daemon.run, daemon=True)
    thread.start()
    time.sleep(0.3)

    # Drop a non-sealed file (= disguised .claude with plain text)
    (inbox / "fake.claude").write_bytes(b"plain text, no TBZ magic")
    # Plus a sealed bundle that should pass
    (inbox / "real.tza").write_bytes(TBZ_MAGIC + b"\x01" + b"\x00" * 50)

    time.sleep(0.5)
    daemon._stop = True
    thread.join(timeout=2.0)

    records = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
        if line.strip()
    ]

    # Should have strict-reject for fake.claude
    rejects = [r for r in records if r.get("stage") == "strict-reject"]
    assert len(rejects) >= 1
    rejected = next(r for r in rejects if r["name"] == "fake.claude")
    assert rejected["intake_class"] == "disguised"
    assert rejected["moved_to"] is not None
    assert rejected["mode"] == "strict"

    # Disguised file moved to quarantine
    assert not (inbox / "fake.claude").exists()
    quarantined = list(quarantine.glob("fake.claude*"))
    assert len(quarantined) == 1

    # Sealed bundle stays in inbox (passes through to verify-fork)
    assert (inbox / "real.tza").exists()

    # Stats reflect the strict-reject
    assert daemon._stats.get("strict_rejects", 0) >= 1


def test_daemon_police_scan_finds_unpacked_state(tmp_path):
    """v0.3.1 — daemon's periodic police scan detects existing
    unpacked state in the inbox lane and emits audit records."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    quarantine = tmp_path / "quarantine"

    # Pre-populate inbox with unpacked state (= what police should find)
    (inbox / "good.tza").write_bytes(TBZ_MAGIC + b"\x01" + b"\x00" * 50)
    (inbox / "fake.claude").write_bytes(b"plain text, not sealed")
    (inbox / "evil").write_bytes(b"\x7fELF" + b"\x00" * 60)

    cfg = DaemonConfig(
        inbox=inbox,
        audit_jsonl=tmp_path / "audit.jsonl",
        mode="strict",
        log_level="WARNING",
        enable_police=True,
        police_scan_interval_sec=0.05,  # quick scans for test
        quarantine_dir=quarantine,
    )
    daemon = ContinuityDaemon(cfg)

    thread = threading.Thread(target=daemon.run, daemon=True)
    thread.start()
    time.sleep(0.6)
    daemon._stop = True
    thread.join(timeout=2.0)

    # Audit should have police records for all three pre-existing files
    records = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
        if line.strip()
    ]
    police_records = [r for r in records if r.get("stage") == "police"]
    assert len(police_records) >= 3

    # Critical evil binary should be quarantined in strict mode
    evil_records = [r for r in police_records if r["name"] == "evil"]
    assert len(evil_records) >= 1
    assert evil_records[0]["severity"] == "critical"
    assert evil_records[0]["action"] == "quarantine"

    # And actually moved on disk
    assert not (inbox / "evil").exists()
    moved_files = list(quarantine.glob("evil*"))
    assert len(moved_files) >= 1

    # Sealed bundle stays put (INFO severity = observe only)
    assert (inbox / "good.tza").exists()

    # Stats reflect work done
    assert daemon._stats["police_scans"] >= 1
    assert daemon._stats["police_findings"] >= 3


def test_daemon_full_pipeline_sniff_verify_seal(tmp_path):
    """End-to-end v0.3.0: arrival → sniff → verify-fork → seal → outbox.

    Drops a real signed TBZ bundle into inbox under MODE=active +
    enable_seal=True. Verifies all four audit-stages emit and a
    sealed bundle lands in outbox.
    """
    from tibet_drop.bundle import pack_bundle, verify_bundle
    from tibet_drop.crypto import IdentityKey
    from tibet_drop.handshake import new_tpid

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    outbox = tmp_path / "outbox"
    staging = tmp_path / "outbox.staging"

    cfg = DaemonConfig(
        inbox=inbox,
        audit_jsonl=tmp_path / "audit.jsonl",
        mode="active",
        log_level="WARNING",
        enable_seal=True,
        outbox_dir=outbox,
        outbox_staging_dir=staging,
        outbox_receiver_aint="next-host.aint",
    )
    daemon = ContinuityDaemon(cfg)

    thread = threading.Thread(target=daemon.run, daemon=True)
    thread.start()
    time.sleep(0.3)

    # Pack a real signed TBZ bundle into inbox
    alice, bob = IdentityKey.generate(), IdentityKey.generate()
    bundle = inbox.parent / "src.tza"
    pack_bundle(
        output_path=bundle,
        blocks=[("payload.json", b'{"e2e":"v0.3.0"}')],
        sender_aint="alice.aint",
        sender_signer=alice,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        payload_type="ai_state",
        tpid=new_tpid(),
        surface_time_fragment="2026-05-09",
        surface_context="e2e-test",
        surface_profile="claude",
        surface_priority="normal",
    )
    # Move into watched inbox via atomic mv
    final = inbox / "2026-05-09.e2e-test.claude.normal.tza"
    bundle.rename(final)

    time.sleep(0.6)
    daemon._stop = True
    thread.join(timeout=2.0)

    # Audit should have 3 stages: sniff + verify-fork + seal
    records = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
        if line.strip()
    ]
    stages = [r["stage"] for r in records]
    assert "sniff" in stages
    assert "verify-fork" in stages
    assert "seal" in stages, f"seal stage missing; got {stages}"

    # Outbox should contain the resealed bundle
    sealed_files = list(outbox.glob("*.tza"))
    assert len(sealed_files) == 1, \
        f"expected 1 sealed bundle in outbox, got {len(sealed_files)}"

    # Sealed bundle must be cryptographically valid
    valid, manifest, errors = verify_bundle(sealed_files[0])
    assert valid, f"sealed bundle should verify: {errors}"

    # Daemon stats
    assert daemon._stats["events_sniffed"] >= 1
    assert daemon._stats["events_verified"] >= 1
    assert daemon._stats["events_forked"] >= 1
    assert daemon._stats["events_sealed"] >= 1

    # Causal lineage chain visible in audit
    sniff_record = next(r for r in records if r["stage"] == "sniff")
    verify_record = next(r for r in records if r["stage"] == "verify-fork")
    seal_record = next(r for r in records if r["stage"] == "seal")

    # All three stages share continuity_id
    assert sniff_record["continuity_id"] == \
        verify_record["continuity_id"] == \
        seal_record["continuity_id"]

    # Generation increments: 0 (sniff) → 1 (verify) → 2 (seal)
    assert sniff_record["generation"] == 0
    assert verify_record["generation"] == 1
    assert seal_record["generation"] == 2

    # parent_action chain: verify ← sniff, seal ← verify
    assert verify_record["parent_action_id"] == sniff_record["action_id"]
    assert seal_record["parent_action_id"] == verify_record["action_id"]
