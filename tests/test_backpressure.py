"""Tests for v0.3.2 BackpressureMonitor (axe 3)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PKG = Path("/srv/jtel-stack/packages/tibet-continuityd/src")
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from tibet_continuityd.backpressure import (  # noqa: E402
    BackpressureMonitor,
    BackpressureSnapshot,
    BackpressureState,
)


def _populate_inbox(inbox: Path, count: int) -> None:
    """Drop `count` empty files in inbox."""
    inbox.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (inbox / f"file-{i:05d}.tza").touch()


# ─── Init validation ────────────────────────────────────────────


def test_init_rejects_inverted_water_marks(tmp_path):
    with pytest.raises(ValueError):
        BackpressureMonitor(
            lane=tmp_path / "inbox",
            low_water=5000,
            high_water=2000,
        )


def test_init_rejects_equal_water_marks(tmp_path):
    with pytest.raises(ValueError):
        BackpressureMonitor(
            lane=tmp_path / "inbox",
            low_water=100,
            high_water=100,
        )


# ─── Empty / non-existent lane ──────────────────────────────────


def test_empty_lane_normal_state(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monitor = BackpressureMonitor(lane=inbox, low_water=10, high_water=20)
    snap = monitor.check()
    assert snap.state == BackpressureState.NORMAL
    assert snap.inbox_depth == 0
    assert not snap.transitioned  # initial NORMAL is not a transition


def test_nonexistent_lane_normal_state(tmp_path):
    monitor = BackpressureMonitor(
        lane=tmp_path / "missing",
        low_water=10, high_water=20,
    )
    snap = monitor.check()
    assert snap.state == BackpressureState.NORMAL
    assert snap.inbox_depth == 0


# ─── State transitions ─────────────────────────────────────────


def test_transition_normal_to_pressure_rising(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monitor = BackpressureMonitor(lane=inbox, low_water=5, high_water=15)

    # Below low_water → NORMAL
    _populate_inbox(inbox, 3)
    snap = monitor.check()
    assert snap.state == BackpressureState.NORMAL
    assert not snap.transitioned

    # Above low_water → PRESSURE_RISING
    _populate_inbox(inbox, 7)  # total 10
    snap = monitor.check()
    assert snap.state == BackpressureState.PRESSURE_RISING
    assert snap.transitioned
    assert snap.prev_state == BackpressureState.NORMAL


def test_transition_to_overloaded(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monitor = BackpressureMonitor(lane=inbox, low_water=5, high_water=15)

    _populate_inbox(inbox, 20)
    snap = monitor.check()
    assert snap.state == BackpressureState.OVERLOADED
    assert snap.transitioned
    assert snap.inbox_depth == 20


def test_overloaded_recovers_to_recovering_then_normal(tmp_path):
    """Hysteresis: OVERLOADED → RECOVERING → NORMAL, not directly."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monitor = BackpressureMonitor(lane=inbox, low_water=5, high_water=15)

    # Overload
    _populate_inbox(inbox, 20)
    snap = monitor.check()
    assert snap.state == BackpressureState.OVERLOADED

    # Drain below low_water
    for f in inbox.glob("*.tza"):
        f.unlink()
    _populate_inbox(inbox, 2)

    # Should go to RECOVERING first (not directly NORMAL)
    snap = monitor.check()
    assert snap.state == BackpressureState.RECOVERING
    assert snap.transitioned
    assert snap.prev_state == BackpressureState.OVERLOADED

    # Next check with stable depth → NORMAL
    snap = monitor.check()
    assert snap.state == BackpressureState.NORMAL
    assert snap.transitioned
    assert snap.prev_state == BackpressureState.RECOVERING


def test_overloaded_can_drop_to_pressure_rising(tmp_path):
    """If depth drops to between low_water and high_water,
    NOT to recovering — partial relief is still pressure."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monitor = BackpressureMonitor(lane=inbox, low_water=5, high_water=15)

    _populate_inbox(inbox, 20)
    monitor.check()  # OVERLOADED

    # Remove down to 8 (in the low<x<high band)
    files = sorted(inbox.glob("*.tza"))
    for f in files[:12]:
        f.unlink()

    snap = monitor.check()
    assert snap.state == BackpressureState.PRESSURE_RISING
    assert snap.transitioned


def test_recovering_back_to_overloaded_if_spike(tmp_path):
    """RECOVERING + new spike → straight back to OVERLOADED."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monitor = BackpressureMonitor(lane=inbox, low_water=5, high_water=15)

    _populate_inbox(inbox, 20)
    monitor.check()  # OVERLOADED

    for f in list(inbox.glob("*.tza")):
        f.unlink()
    _populate_inbox(inbox, 2)
    monitor.check()  # RECOVERING

    # Burst back
    _populate_inbox(inbox, 25)
    snap = monitor.check()
    assert snap.state == BackpressureState.OVERLOADED


def test_no_transition_when_state_stable(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monitor = BackpressureMonitor(lane=inbox, low_water=5, high_water=15)

    _populate_inbox(inbox, 10)
    snap1 = monitor.check()
    assert snap1.state == BackpressureState.PRESSURE_RISING

    snap2 = monitor.check()
    assert snap2.state == BackpressureState.PRESSURE_RISING
    assert not snap2.transitioned
    assert snap2.prev_state is None


# ─── Snapshot serialization ────────────────────────────────────


def test_snapshot_serializable(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    _populate_inbox(inbox, 6)
    monitor = BackpressureMonitor(lane=inbox, low_water=5, high_water=15)
    snap = monitor.check()
    d = snap.to_dict()
    assert d["state"] == "pressure-rising"
    assert d["inbox_depth"] == 6
    assert d["transitioned"] is True
    assert d["prev_state"] == "normal"
    assert "ts_unix" in d


def test_snapshot_no_prev_state_when_no_transition(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monitor = BackpressureMonitor(lane=inbox, low_water=5, high_water=15)
    snap = monitor.check()
    d = snap.to_dict()
    assert d["prev_state"] is None
    assert d["transitioned"] is False
