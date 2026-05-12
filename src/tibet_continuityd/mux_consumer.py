"""
tibet-mux consumer thread for tibet-continuityd (v0.6.2+).

Wraps the v0.6.1 `tcd mux-consumer` CLI logic in a stoppable
thread so the daemon can run an inotify-watcher AND a mux-poll-
consumer concurrently. Materialized frames land in the same
inbox dir → daemon's normal Watch/Sniff/Verify/Seal pipeline
picks them up.

  inotify watcher           ┐
                            ├──→ daemon Sniff/Verify/Seal pipeline
  mux consumer thread       ┘
       │
       │ poll /api/mux/by-target
       │ fetch recent_frames
       │ decode bundle_b64 → atomic write inbox/<name>
       │ close channel
       ▼
  inbox/<name>.tza  → inotify event → daemon pipeline

Activation: daemon reads TIBET_CONTINUITYD_MUX_SERVER env-var.
If set, also requires TIBET_CONTINUITYD_MUX_AGENT. Defaults:
    TIBET_CONTINUITYD_MUX_INTENT   = continuityd:inbox
    TIBET_CONTINUITYD_MUX_INTERVAL = 1.0
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional


_log = logging.getLogger("tibet_continuityd.mux_consumer")


class MuxConsumerThread:
    """Poll a tibet-mux server (v1.0.1+) and materialize frames."""

    def __init__(
        self,
        server: str,
        agent: str,
        inbox_dir: Path,
        intent: str = "continuityd:inbox",
        interval: float = 1.0,
        seen_file: Optional[Path] = None,
    ):
        self.server = server.rstrip("/")
        self.agent = agent
        self.inbox_dir = inbox_dir
        self.intent = intent
        self.interval = max(0.1, float(interval))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # v0.6.8: persist _seen across daemon restarts so we don't
        # re-materialize stale frames the mux server still holds in
        # recent_frames. Without this, every daemon-restart caused a
        # full re-consume of historical channels (= the v0.6.x mux
        # replay-on-startup problem).
        self._seen_file = seen_file
        self._seen: set = set()  # (channel_id, seq) pairs
        if seen_file and seen_file.exists():
            self._load_seen()
        self._stats = {
            "polls": 0,
            "poll_errors": 0,
            "materialized": 0,
            "channels_seen": 0,
            "dedup_persisted": len(self._seen),
        }

    def _load_seen(self) -> None:
        """Read persisted (channel_id, seq) tuples from disk."""
        try:
            data = json.loads(
                self._seen_file.read_text(encoding="utf-8")
            )
            seen_list = data.get("seen", []) if isinstance(data, dict) else []
            for entry in seen_list:
                if isinstance(entry, list) and len(entry) == 2:
                    self._seen.add((entry[0], entry[1]))
            _log.info(
                f"mux-consumer: loaded {len(self._seen)} persisted "
                f"seen entries from {self._seen_file}"
            )
        except (OSError, json.JSONDecodeError) as e:
            _log.warning(
                f"mux-consumer: could not load seen file: {e}"
            )

    def _persist_seen(self) -> None:
        """Write current _seen set to disk (best-effort)."""
        if not self._seen_file:
            return
        try:
            self._seen_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._seen_file.with_suffix(
                self._seen_file.suffix + ".part"
            )
            payload = {
                "version": "v0.6.8",
                "agent": self.agent,
                "intent": self.intent,
                "count": len(self._seen),
                "seen": [list(t) for t in self._seen],
            }
            tmp.write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            tmp.replace(self._seen_file)
        except OSError as e:
            _log.debug(f"mux-consumer: persist failed: {e}")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.inbox_dir.mkdir(parents=True, exist_ok=True)
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="continuityd-mux-consumer",
            daemon=True,
        )
        self._thread.start()
        _log.info(
            f"mux-consumer started: server={self.server} "
            f"agent={self.agent} intent={self.intent} "
            f"interval={self.interval}s inbox={self.inbox_dir}"
        )

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None
        _log.info(f"mux-consumer stopped: stats={self._stats}")

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def _poll_by_target(self) -> list:
        q = urllib.parse.urlencode({
            "target": self.agent,
            "intent": self.intent or "",
            "include_closed": "true",
        })
        url = f"{self.server}/api/mux/by-target?{q}"
        with urllib.request.urlopen(url, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("channels", []) or []

    def _fetch_channel_frames(self, ch_id: str) -> list:
        url = f"{self.server}/api/mux/channel/{ch_id}"
        with urllib.request.urlopen(url, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("recent_frames", []) or []

    def _close_channel(self, ch_id: str, reason: str) -> None:
        body = json.dumps({
            "channel_id": ch_id, "reason": reason,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.server}/api/mux/close",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=3.0).read()
        except Exception as e:
            _log.debug(f"close({ch_id}) failed: {e}")

    def _materialize_frame(
        self, ch_id: str, frame: dict
    ) -> bool:
        payload = frame.get("payload") or {}
        if not isinstance(payload, dict):
            return False
        name = payload.get("name")
        body_b64 = payload.get("bundle_b64")
        if not name or not body_b64:
            return False
        # Path-traversal safety
        if "/" in name or "\\" in name or ".." in name:
            _log.warning(f"reject unsafe name: {name}")
            return False
        try:
            body = base64.b64decode(body_b64)
        except Exception as e:
            _log.warning(f"b64 decode failed for {name}: {e}")
            return False
        part = self.inbox_dir / (name + ".part")
        final = self.inbox_dir / name
        part.write_bytes(body)
        part.rename(final)
        _log.info(
            f"materialized: name={name} size={len(body)} "
            f"channel={ch_id} seq={frame.get('seq')}"
        )
        return True

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                channels = self._poll_by_target()
                self._stats["polls"] += 1
            except Exception as e:
                self._stats["poll_errors"] += 1
                _log.debug(f"poll error: {e}")
                self._stop.wait(self.interval)
                continue

            for c in channels:
                ch_id = c.get("id") or c.get("channel_id")
                if not ch_id:
                    continue
                if self.intent and c.get("intent") != self.intent:
                    continue
                self._stats["channels_seen"] += 1
                try:
                    frames = self._fetch_channel_frames(ch_id)
                except Exception as e:
                    _log.debug(
                        f"channel-fetch error {ch_id}: {e}"
                    )
                    continue
                materialized_any = False
                for frame in frames:
                    seq = frame.get("seq")
                    key = (ch_id, seq)
                    if key in self._seen:
                        continue
                    self._seen.add(key)
                    if self._materialize_frame(ch_id, frame):
                        materialized_any = True
                        self._stats["materialized"] += 1
                        # v0.6.8: persist after every successful
                        # materialization so a crash-before-poll
                        # doesn't lose dedup state.
                        self._persist_seen()
                if materialized_any:
                    self._close_channel(
                        ch_id, "daemon_consumer_received"
                    )

            self._stop.wait(self.interval)
