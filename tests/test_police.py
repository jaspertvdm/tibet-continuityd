"""Tests for v0.3.1 Police stage."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

_TIBET_DROP = Path("/srv/jtel-stack/sandbox/airdrop-cli/src")
if str(_TIBET_DROP) not in sys.path:
    sys.path.insert(0, str(_TIBET_DROP))
_PKG = Path("/srv/jtel-stack/packages/tibet-continuityd/src")
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from tibet_continuityd.police import (  # noqa: E402
    FindingSeverity,
    PoliceAction,
    PoliceScanner,
    apply_action,
)
from tibet_continuityd.sniff import TBZ_MAGIC  # noqa: E402


# ─── Scanner: empty lane ────────────────────────────────────────


def test_empty_lane_no_findings(tmp_path):
    lane = tmp_path / "inbox"
    lane.mkdir()
    scanner = PoliceScanner(lane=lane)
    assert scanner.scan() == []


def test_nonexistent_lane_no_findings(tmp_path):
    scanner = PoliceScanner(lane=tmp_path / "doesnt-exist")
    assert scanner.scan() == []


# ─── Scanner: detect each unpacked-state class ──────────────────


def test_sealed_tbz_findings_are_info(tmp_path):
    lane = tmp_path / "inbox"
    lane.mkdir()
    (lane / "good.tza").write_bytes(TBZ_MAGIC + b"\x01" + b"\x00" * 100)
    findings = PoliceScanner(lane=lane).scan()
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.INFO
    assert findings[0].intake_class == "sealed-tbz"


def test_executable_finding_is_critical(tmp_path):
    lane = tmp_path / "inbox"
    lane.mkdir()
    (lane / "evil").write_bytes(b"\x7fELF" + b"\x00" * 60)
    findings = PoliceScanner(lane=lane).scan()
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert findings[0].intake_class == "executable"


def test_disguised_finding_is_alert(tmp_path):
    lane = tmp_path / "inbox"
    lane.mkdir()
    (lane / "fake.claude").write_bytes(b"plain text, not sealed")
    findings = PoliceScanner(lane=lane).scan()
    assert findings[0].severity == FindingSeverity.ALERT
    assert findings[0].intake_class == "disguised"


def test_json_text_finding_is_warn(tmp_path):
    lane = tmp_path / "inbox"
    lane.mkdir()
    (lane / "session.json").write_bytes(b'{"k":"v"}')
    findings = PoliceScanner(lane=lane).scan()
    assert findings[0].severity == FindingSeverity.WARN
    assert findings[0].intake_class == "json-text"


def test_pdf_finding_is_warn(tmp_path):
    lane = tmp_path / "inbox"
    lane.mkdir()
    (lane / "doc.pdf").write_bytes(b"%PDF-1.7\n")
    findings = PoliceScanner(lane=lane).scan()
    assert findings[0].severity == FindingSeverity.WARN


# ─── Scanner: staging suffix skipped ────────────────────────────


def test_staging_part_files_skipped_by_default(tmp_path):
    """*.part files are in-flight writes — police should ignore."""
    lane = tmp_path / "inbox"
    lane.mkdir()
    (lane / "writing.tza.part").write_bytes(TBZ_MAGIC + b"\x00" * 50)
    (lane / "real.tza").write_bytes(TBZ_MAGIC + b"\x01" + b"\x00" * 50)
    findings = PoliceScanner(lane=lane).scan()
    # only real.tza should produce a finding
    assert len(findings) == 1
    assert findings[0].name == "real.tza"


def test_staging_can_be_included_explicitly(tmp_path):
    lane = tmp_path / "inbox"
    lane.mkdir()
    (lane / "writing.tza.part").write_bytes(TBZ_MAGIC + b"\x00" * 50)
    findings = PoliceScanner(lane=lane, skip_staging=False).scan()
    assert len(findings) == 1


# ─── Scanner: aging logic ───────────────────────────────────────


def test_lingering_file_bumps_severity(tmp_path):
    """A file older than age_alert_threshold bumps INFO to WARN."""
    lane = tmp_path / "inbox"
    lane.mkdir()
    sealed = lane / "old-but-good.tza"
    sealed.write_bytes(TBZ_MAGIC + b"\x01" + b"\x00" * 50)
    # Backdate file mtime to 600s ago
    old_ts = time.time() - 600
    os.utime(sealed, (old_ts, old_ts))

    scanner = PoliceScanner(lane=lane, age_alert_threshold_sec=300.0)
    findings = scanner.scan()

    assert findings[0].severity == FindingSeverity.WARN  # bumped from INFO
    assert "lingering" in findings[0].reason
    assert findings[0].age_seconds > 300


# ─── apply_action: mode-driven outcomes ─────────────────────────


def _mock_finding(severity=FindingSeverity.ALERT, name="evil.exe"):
    from tibet_continuityd.police import PoliceFinding
    return PoliceFinding(
        name=name,
        full_path=Path(f"/tmp/{name}"),
        lane=Path("/tmp/inbox"),
        severity=severity,
        intake_class="executable",
        disposition_hint="quarantine",
        reason="test fixture",
        age_seconds=10.0,
        size_bytes=100,
    )


def test_passive_mode_observes(tmp_path):
    f = _mock_finding()
    action = apply_action(f, mode="passive")
    assert action.action == "observe"
    assert action.moved_to is None


def test_active_mode_triages_in_log_only(tmp_path):
    f = _mock_finding()
    action = apply_action(f, mode="active")
    assert action.action == "triage"
    assert action.moved_to is None


def test_strict_mode_quarantines_critical(tmp_path):
    """Critical finding in strict mode → file gets moved."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    quarantine = tmp_path / "quarantine"

    target = inbox / "evil"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)

    findings = PoliceScanner(lane=inbox).scan()
    assert findings[0].severity == FindingSeverity.CRITICAL

    action = apply_action(
        findings[0], mode="strict", quarantine_dir=quarantine,
    )
    assert action.action == "quarantine"
    assert action.moved_to is not None
    assert action.moved_to.exists()
    assert not target.exists()
    assert action.moved_to.parent == quarantine.resolve()


def test_strict_mode_observes_low_severity(tmp_path):
    """INFO findings in strict mode = still just observe."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    sealed = inbox / "good.tza"
    sealed.write_bytes(TBZ_MAGIC + b"\x01" + b"\x00" * 50)

    findings = PoliceScanner(lane=inbox).scan()
    assert findings[0].severity == FindingSeverity.INFO

    action = apply_action(
        findings[0], mode="strict",
        quarantine_dir=tmp_path / "quarantine",
    )
    assert action.action == "observe"
    assert sealed.exists()  # NOT moved


def test_strict_quarantine_collision_handled(tmp_path):
    """If quarantine target already exists, suffix with timestamp."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()

    # Pre-existing file in quarantine with same name
    (quarantine / "evil").write_bytes(b"old quarantined file")

    new_target = inbox / "evil"
    new_target.write_bytes(b"\x7fELF" + b"\x00" * 60)

    findings = PoliceScanner(lane=inbox).scan()
    action = apply_action(
        findings[0], mode="strict", quarantine_dir=quarantine,
    )
    assert action.action == "quarantine"
    assert action.moved_to is not None
    assert action.moved_to.name != "evil"  # suffixed with ts
    assert "evil." in action.moved_to.name


def test_strict_no_quarantine_dir_returns_error(tmp_path):
    f = _mock_finding(severity=FindingSeverity.CRITICAL)
    action = apply_action(f, mode="strict", quarantine_dir=None)
    assert action.action == "strict-no-quarantine-dir"
    assert action.error is not None


def test_unknown_mode_returns_error():
    f = _mock_finding()
    action = apply_action(f, mode="some-future-mode")
    assert action.action == "unknown-mode"
    assert action.error is not None


# ─── Severity classification corners ────────────────────────────


def test_finding_to_dict_serializable(tmp_path):
    lane = tmp_path / "inbox"
    lane.mkdir()
    (lane / "test.tza").write_bytes(TBZ_MAGIC + b"\x01" + b"\x00" * 50)
    findings = PoliceScanner(lane=lane).scan()
    d = findings[0].to_dict()
    assert d["intake_class"] == "sealed-tbz"
    assert d["severity"] == "info"
    assert "ts_unix" in d
