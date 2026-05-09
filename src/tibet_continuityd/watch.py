"""
watch.py — Lane watcher (inotify Watch stage).

Uses Linux inotify via the in-tree `inotify_simple` minimal
implementation (or falls back to polling on non-Linux).

Per Codex' axiom: "Arrival is event."

The Watcher reports file events bound to a lane. Each event is
either a CREATE, MOVED_TO, or CLOSE_WRITE — i.e., something
arrived or finished writing in the watched directory.
"""
from __future__ import annotations

import os
import select
import struct
import time
from dataclasses import dataclass
from enum import IntFlag
from pathlib import Path
from typing import Callable, Iterator, Optional


# ─── inotify constants (linux/inotify.h) ────────────────────────


class InotifyFlag(IntFlag):
    IN_ACCESS = 0x00000001
    IN_MODIFY = 0x00000002
    IN_ATTRIB = 0x00000004
    IN_CLOSE_WRITE = 0x00000008
    IN_CLOSE_NOWRITE = 0x00000010
    IN_OPEN = 0x00000020
    IN_MOVED_FROM = 0x00000040
    IN_MOVED_TO = 0x00000080
    IN_CREATE = 0x00000100
    IN_DELETE = 0x00000200
    IN_DELETE_SELF = 0x00000400
    IN_MOVE_SELF = 0x00000800
    IN_ISDIR = 0x40000000


_DEFAULT_MASK = (
    InotifyFlag.IN_CLOSE_WRITE
    | InotifyFlag.IN_MOVED_TO
    | InotifyFlag.IN_CREATE
)


# ─── ctypes-based inotify_init1 / inotify_add_watch ─────────────


def _libc():
    import ctypes
    return ctypes.CDLL("libc.so.6", use_errno=True)


def _inotify_init() -> int:
    """inotify_init1(IN_NONBLOCK = 0x800)"""
    libc = _libc()
    fd = libc.inotify_init1(0x800)
    if fd < 0:
        import ctypes
        raise OSError(ctypes.get_errno(), "inotify_init1 failed")
    return fd


def _inotify_add_watch(fd: int, path: Path, mask: int) -> int:
    libc = _libc()
    wd = libc.inotify_add_watch(
        fd,
        str(path).encode(),
        mask,
    )
    if wd < 0:
        import ctypes
        raise OSError(ctypes.get_errno(),
                      f"inotify_add_watch({path}) failed")
    return wd


# ─── Event ──────────────────────────────────────────────────────


@dataclass
class WatchEvent:
    lane: Path                  # the watched directory
    name: str                   # filename relative to lane
    full_path: Path             # absolute path
    flags: InotifyFlag          # raw mask
    is_dir: bool                # event affected a subdirectory
    ts_unix: float              # time.time() at event read

    @property
    def is_arrival(self) -> bool:
        """True if this event represents a fresh arrival worth sniffing.

        We deliberately count only CLOSE_WRITE (writer is done) and
        MOVED_TO (rename into the watched dir). IN_CREATE fires too
        early — the file may still be empty when it arrives.
        """
        return bool(
            self.flags & (InotifyFlag.IN_CLOSE_WRITE
                          | InotifyFlag.IN_MOVED_TO)
        ) and not self.is_dir


# ─── Watcher ────────────────────────────────────────────────────


class LaneWatcher:
    """
    Watches one or more lanes (directories) for arrival events.

    Usage:
        w = LaneWatcher([Path("/var/lib/tibet/inbox")])
        for event in w.events(timeout_sec=1.0):
            ...

    On non-Linux platforms, raises OSError on construction; this
    daemon is Linux-first.
    """

    def __init__(self, lanes: list[Path], mask: int = _DEFAULT_MASK):
        self.lanes = [Path(p).resolve() for p in lanes]
        self.mask = mask
        self.fd = _inotify_init()
        self._wd_to_path: dict[int, Path] = {}
        for p in self.lanes:
            if not p.is_dir():
                raise NotADirectoryError(p)
            wd = _inotify_add_watch(self.fd, p, mask)
            self._wd_to_path[wd] = p

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "LaneWatcher":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def events(
        self,
        timeout_sec: float = 1.0,
        stop_cb: Optional[Callable[[], bool]] = None,
        timeout_cb: Optional[Callable[[], None]] = None,
    ) -> Iterator[WatchEvent]:
        """Yield WatchEvents until stop_cb() returns True or fd closes.

        stop_cb is checked after every select() timeout AND after
        every yielded event, so SIGTERM-driven shutdown is honored
        within `timeout_sec` regardless of arrival rate.

        This matters: without stop_cb, a daemon receiving SIGTERM
        on an idle inbox would hang forever in select.select()
        because the inner generator only checks state after each
        new file-event, which may never come. systemd would then
        force-kill after TimeoutStopSec (default 90s) — operationally
        unacceptable.
        """
        while True:
            if stop_cb and stop_cb():
                return
            r, _, _ = select.select([self.fd], [], [], timeout_sec)
            if not r:
                if timeout_cb:
                    timeout_cb()
                continue
            buf = os.read(self.fd, 65536)
            offset = 0
            while offset < len(buf):
                # struct inotify_event { int wd; u32 mask;
                #                        u32 cookie; u32 len; }
                hdr = buf[offset:offset + 16]
                if len(hdr) < 16:
                    break
                wd, mask, _cookie, name_len = struct.unpack(
                    "iIII", hdr)
                offset += 16
                name = buf[offset:offset + name_len] \
                    .rstrip(b"\x00").decode("utf-8", errors="replace")
                offset += name_len

                lane = self._wd_to_path.get(wd)
                if lane is None or not name:
                    continue

                flags = InotifyFlag(mask)
                yield WatchEvent(
                    lane=lane,
                    name=name,
                    full_path=lane / name,
                    flags=flags,
                    is_dir=bool(flags & InotifyFlag.IN_ISDIR),
                    ts_unix=time.time(),
                )
                if stop_cb and stop_cb():
                    return
