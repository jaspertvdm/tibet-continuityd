"""
coalesce.py — object-level intake coalescing for continuityd v0.3.

The watcher stays syscall/event-level. This module collapses a burst of
related arrival events for the same path into one settled object so the
daemon reasons about files, not write-close noise.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tibet_continuityd.watch import WatchEvent


@dataclass(frozen=True)
class FileSnapshot:
    size_bytes: int
    mtime_ns: int


@dataclass
class PendingArrival:
    latest_event: WatchEvent
    first_seen_ts: float
    last_seen_ts: float
    event_count: int
    last_snapshot: Optional[FileSnapshot]


@dataclass
class SettledArrival:
    lane: Path
    name: str
    full_path: Path
    flags: int
    is_dir: bool
    ts_unix: float
    coalesced: bool
    coalesced_event_count: int
    coalesced_window_ms: int
    settled_after_ms: int
    path_churn_detected: bool


def _safe_snapshot(path: Path) -> Optional[FileSnapshot]:
    try:
        st = path.stat()
    except OSError:
        return None
    return FileSnapshot(size_bytes=st.st_size, mtime_ns=st.st_mtime_ns)


class ArrivalCoalescer:
    """Collapse repeated arrivals for the same path into settled objects."""

    def __init__(
        self,
        debounce_window_ms: int = 350,
        max_pending_age_ms: int = 5000,
        high_churn_threshold: int = 5,
    ):
        self.debounce_window_ms = debounce_window_ms
        self.max_pending_age_ms = max_pending_age_ms
        self.high_churn_threshold = high_churn_threshold
        self._pending: dict[Path, PendingArrival] = {}

    def ingest(self, event: WatchEvent) -> None:
        snapshot = _safe_snapshot(event.full_path)
        entry = self._pending.get(event.full_path)
        if entry is None:
            self._pending[event.full_path] = PendingArrival(
                latest_event=event,
                first_seen_ts=event.ts_unix,
                last_seen_ts=event.ts_unix,
                event_count=1,
                last_snapshot=snapshot,
            )
            return

        entry.latest_event = event
        entry.last_seen_ts = event.ts_unix
        entry.event_count += 1
        entry.last_snapshot = snapshot

    def flush_ready(
        self,
        now: Optional[float] = None,
    ) -> list[SettledArrival]:
        now = time.time() if now is None else now
        ready: list[SettledArrival] = []
        expired_paths: list[Path] = []

        for path, entry in list(self._pending.items()):
            age_ms = int((now - entry.last_seen_ts) * 1000)
            total_age_ms = int((now - entry.first_seen_ts) * 1000)

            if age_ms < self.debounce_window_ms:
                continue

            current = _safe_snapshot(path)
            if current is None:
                expired_paths.append(path)
                continue

            if current != entry.last_snapshot:
                entry.last_snapshot = current
                entry.last_seen_ts = now
                continue

            if total_age_ms > self.max_pending_age_ms:
                entry.last_seen_ts = now

            event = entry.latest_event
            ready.append(
                SettledArrival(
                    lane=event.lane,
                    name=event.name,
                    full_path=event.full_path,
                    flags=int(event.flags),
                    is_dir=event.is_dir,
                    ts_unix=event.ts_unix,
                    coalesced=entry.event_count > 1,
                    coalesced_event_count=entry.event_count,
                    coalesced_window_ms=self.debounce_window_ms,
                    settled_after_ms=total_age_ms,
                    path_churn_detected=(
                        entry.event_count > self.high_churn_threshold
                    ),
                )
            )
            expired_paths.append(path)

        for path in expired_paths:
            self._pending.pop(path, None)

        return ready

    @property
    def pending_count(self) -> int:
        return len(self._pending)
