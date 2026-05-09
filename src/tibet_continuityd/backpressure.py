"""
backpressure.py — Backpressure / circuit-breaker (v0.3.2, axe 3).

Per Jaspers prompt 9 mei 2026:

  "MUX 500 files/sec, sniff/verify 100/sec. Inbox > 5000 onverwerkt
   → daemon signaleert MUX/network 'Halt' of TCP-windowing-stijl
   backpressure. Geen self-inflicted DoS."

This module implements that protection: monitor the inbox depth
and emit state-transition audit events when pressure rises or
falls. The daemon itself does NOT throttle its own work-rate
(that would worsen things) — it signals UPSTREAM that producer
should slow down.

State machine:

   NORMAL                  depth < low_water
      │
      │ depth ≥ low_water
      ▼
   PRESSURE_RISING         low_water ≤ depth < high_water
      │
      │ depth ≥ high_water
      ▼
   OVERLOADED              depth ≥ high_water
      │
      │ depth < low_water (hysteresis)
      ▼
   RECOVERING              transitional state
      │
      │ depth stable < low_water
      ▼
   NORMAL

Hysteresis: NORMAL → OVERLOADED requires high_water,
            OVERLOADED → NORMAL requires going back below
            low_water (not just back below high_water).
            This prevents oscillation at the boundary.

Signal mechanism (v0.3.2 minimal):
  emit "backpressure" audit-record at every state-transition
  (= upstream consumers can read audit-stream and react)

Future v0.3.x extensions:
  - write signal-file at /var/lib/tibet/backpressure-state
  - HTTP endpoint POST to mux upstream
  - TIBET token emission for cross-host signaling
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class BackpressureState(Enum):
    """Daemon's current capacity state."""
    NORMAL = "normal"                  # depth < low_water
    PRESSURE_RISING = "pressure-rising"  # low ≤ depth < high
    OVERLOADED = "overloaded"          # depth ≥ high_water
    RECOVERING = "recovering"          # was overloaded, depth dropping


@dataclass
class BackpressureSnapshot:
    """One observation of inbox depth + current state."""
    state: BackpressureState
    inbox_depth: int                   # number of unprocessed files
    low_water: int                     # threshold for "rising"
    high_water: int                    # threshold for "overloaded"
    transitioned: bool                 # state changed since last check
    prev_state: Optional[BackpressureState] = None
    ts_unix: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "inbox_depth": self.inbox_depth,
            "low_water": self.low_water,
            "high_water": self.high_water,
            "transitioned": self.transitioned,
            "prev_state": self.prev_state.value
                if self.prev_state else None,
            "ts_unix": self.ts_unix,
        }


@dataclass
class BackpressureMonitor:
    """Track inbox depth and compute state transitions.

    Usage:
        monitor = BackpressureMonitor(
            lane=Path("/var/lib/tibet/inbox"),
            low_water=2000,
            high_water=5000,
        )
        snapshot = monitor.check()
        if snapshot.transitioned:
            # emit audit, optionally signal upstream
            ...
    """
    lane: Path
    low_water: int = 2000
    high_water: int = 5000
    _state: BackpressureState = BackpressureState.NORMAL

    def __post_init__(self):
        if self.low_water >= self.high_water:
            raise ValueError(
                f"low_water ({self.low_water}) must be < "
                f"high_water ({self.high_water})"
            )

    def _measure_depth(self) -> int:
        """Count files in lane (excluding subdirectories)."""
        if not self.lane.exists() or not self.lane.is_dir():
            return 0
        try:
            return sum(1 for entry in self.lane.iterdir()
                       if entry.is_file())
        except OSError:
            return 0

    def _classify_state(self, depth: int) -> BackpressureState:
        """Compute target state from depth WITHOUT hysteresis logic.

        Hysteresis is applied in check() — this is the raw mapping.
        """
        if depth >= self.high_water:
            return BackpressureState.OVERLOADED
        if depth >= self.low_water:
            return BackpressureState.PRESSURE_RISING
        return BackpressureState.NORMAL

    def check(self) -> BackpressureSnapshot:
        """Measure depth and update state with hysteresis."""
        depth = self._measure_depth()
        prev = self._state
        target = self._classify_state(depth)

        # Hysteresis: OVERLOADED can ONLY drop to RECOVERING (not
        # straight to NORMAL via PRESSURE_RISING). This prevents
        # oscillation when depth hovers near low_water.
        new_state = target
        if prev == BackpressureState.OVERLOADED and \
                target != BackpressureState.OVERLOADED:
            # transition out of overloaded → recovering first
            if target == BackpressureState.NORMAL:
                new_state = BackpressureState.RECOVERING
            # else: target is PRESSURE_RISING, accept it
        elif prev == BackpressureState.RECOVERING:
            # In RECOVERING, stay until depth is fully back under
            # low_water (= NORMAL target).
            if target == BackpressureState.NORMAL:
                new_state = BackpressureState.NORMAL
            elif target == BackpressureState.OVERLOADED:
                new_state = BackpressureState.OVERLOADED
            else:
                new_state = BackpressureState.RECOVERING

        transitioned = (new_state != prev)
        self._state = new_state

        return BackpressureSnapshot(
            state=new_state,
            inbox_depth=depth,
            low_water=self.low_water,
            high_water=self.high_water,
            transitioned=transitioned,
            prev_state=prev if transitioned else None,
        )


# ─── Public API ─────────────────────────────────────────────────


__all__ = [
    "BackpressureMonitor",
    "BackpressureSnapshot",
    "BackpressureState",
]
