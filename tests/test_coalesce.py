from __future__ import annotations

import sys
import time
from pathlib import Path

_PKG = Path("/srv/jtel-stack/packages/tibet-continuityd/src")
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from tibet_continuityd.coalesce import ArrivalCoalescer  # noqa: E402
from tibet_continuityd.watch import InotifyFlag, WatchEvent  # noqa: E402


def _event(path: Path, ts: float) -> WatchEvent:
    return WatchEvent(
        lane=path.parent,
        name=path.name,
        full_path=path,
        flags=InotifyFlag.IN_CLOSE_WRITE,
        is_dir=False,
        ts_unix=ts,
    )


def test_single_event_settles_without_coalescing(tmp_path):
    target = tmp_path / "single.tza"
    target.write_bytes(b"abc")
    ts = time.time()
    coalescer = ArrivalCoalescer(debounce_window_ms=10)

    coalescer.ingest(_event(target, ts))
    settled = coalescer.flush_ready(now=ts + 0.02)

    assert len(settled) == 1
    assert settled[0].coalesced is False
    assert settled[0].coalesced_event_count == 1
    assert settled[0].path_churn_detected is False


def test_multiple_events_for_same_path_become_one_settled_object(tmp_path):
    target = tmp_path / "multi.tza"
    target.write_bytes(b"abc")
    ts = time.time()
    coalescer = ArrivalCoalescer(
        debounce_window_ms=10,
        high_churn_threshold=2,
    )

    coalescer.ingest(_event(target, ts))
    target.write_bytes(b"abcdef")
    coalescer.ingest(_event(target, ts + 0.001))
    target.write_bytes(b"abcdefgh")
    coalescer.ingest(_event(target, ts + 0.002))

    settled = coalescer.flush_ready(now=ts + 0.03)

    assert len(settled) == 1
    assert settled[0].coalesced is True
    assert settled[0].coalesced_event_count == 3
    assert settled[0].path_churn_detected is True
    assert settled[0].full_path == target
