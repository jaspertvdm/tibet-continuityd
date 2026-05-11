"""
Liveness tracker for tibet-continuityd (v0.6.6+).

Adds a time-bound presence dimension on top of the causal substrate:
heartbeats from verified peers update an in-memory table with TTL,
and the daemon (or any peer) can answer "is X alive right now?"
without polling DNS or pinging.

State per peer:
    {
        sender_did:        "jis:org:service@host",
        last_seen_iso:     "2026-05-11T20:42:13Z",
        last_seen_unix:    1778544133.0,
        last_kind_detail:  "liveness" | "shutdown" | "reboot" | "custom",
        last_note:         "<free-form>",
        beat_count:        N,
        first_seen_iso:    "...",
    }

Transitions:
    kind=liveness  → peer marked alive, TTL clock resets
    kind=shutdown  → peer marked stopped, no expected_back
    kind=reboot    → peer marked rebooting, expected_back ≈ 30s

is_alive(did, ttl_sec=60) returns True iff:
    last_kind_detail != "shutdown"
    AND (now - last_seen_unix) < ttl_sec

Persistence:
    Optional JSON write on every update if liveness_file is set.
    On startup, reads the file back to recover state across restarts.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Optional


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class LivenessTracker:
    """Thread-safe peer-presence tracker.

    Single source of truth for "who has been heard from recently"
    on this daemon. Updated by the heartbeat-lane in _on_arrival;
    queried by HTTP endpoint and `tcd liveness` CLI.
    """

    def __init__(self, persist_file: Optional[Path] = None):
        self._lock = threading.Lock()
        self._peers: dict[str, dict] = {}
        self._persist_file = persist_file
        if persist_file and persist_file.exists():
            self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._persist_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                peers = data.get("peers", {})
                if isinstance(peers, dict):
                    self._peers = peers
        except (OSError, json.JSONDecodeError):
            # Corrupt or missing — start fresh
            self._peers = {}

    def _persist(self) -> None:
        if not self._persist_file:
            return
        try:
            self._persist_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._persist_file.with_suffix(
                self._persist_file.suffix + ".part"
            )
            payload = {
                "version": "v0.6.6",
                "written_at_iso": _now_iso(),
                "peers": self._peers,
            }
            tmp.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            tmp.replace(self._persist_file)
        except OSError:
            pass  # persistence is best-effort

    def record_heartbeat(
        self,
        sender_did: str,
        kind_detail: str = "liveness",
        note: str = "",
        surface_hash: Optional[str] = None,
    ) -> Optional[dict]:
        """Update presence for a peer. Returns the new state record,
        or None if the heartbeat was deduplicated.

        Idempotency: when `surface_hash` is provided, we skip the
        update if the same hash was seen for this sender within the
        last `dedup_window_sec`. This protects against the mux-replay
        pattern (= consumer re-fetches recent_frames and sees the
        same bundle twice).
        """
        dedup_window_sec = 30.0
        now_unix = time.time()
        now_iso = _now_iso()
        with self._lock:
            existing = self._peers.get(sender_did, {})
            if surface_hash:
                last_hash = existing.get("last_surface_hash")
                last_unix = existing.get("last_seen_unix", 0)
                age = now_unix - last_unix
                if (
                    last_hash == surface_hash
                    and age < dedup_window_sec
                ):
                    # Same bundle, recently seen — skip update.
                    return None
            record = {
                "sender_did": sender_did,
                "last_seen_iso": now_iso,
                "last_seen_unix": now_unix,
                "last_kind_detail": kind_detail,
                "last_note": note,
                "last_surface_hash": surface_hash,
                "beat_count": existing.get("beat_count", 0) + 1,
                "first_seen_iso": existing.get(
                    "first_seen_iso", now_iso
                ),
            }
            self._peers[sender_did] = record
            self._persist()
            return dict(record)

    def get(
        self, sender_did: str, ttl_sec: float = 60.0
    ) -> Optional[dict]:
        """Return presence record + derived alive/age fields."""
        with self._lock:
            r = self._peers.get(sender_did)
            if not r:
                return None
            out = dict(r)
        age = time.time() - out["last_seen_unix"]
        out["age_seconds"] = round(age, 2)
        out["alive"] = (
            out["last_kind_detail"] != "shutdown"
            and age < ttl_sec
        )
        # Convention: reboot announces ~30s downtime
        if out["last_kind_detail"] == "reboot":
            out["expected_back_sec"] = max(0, 30 - age)
        else:
            out["expected_back_sec"] = None
        return out

    def all(self, ttl_sec: float = 60.0) -> list[dict]:
        with self._lock:
            dids = list(self._peers.keys())
        return [r for d in dids if (r := self.get(d, ttl_sec))]

    def is_alive(self, sender_did: str, ttl_sec: float = 60.0) -> bool:
        r = self.get(sender_did, ttl_sec)
        return bool(r and r.get("alive"))


def kind_detail_from_surface_context(ctx: Optional[str]) -> str:
    """Extract kind_detail from `surface_context` field.

    Sender writes `surface_context = f"heartbeat-{kind_detail}"`
    in _cmd_heartbeat. We parse it back here to avoid having to
    open + unpack the bundle just to read the JSON payload.
    """
    if not ctx or not isinstance(ctx, str):
        return "liveness"
    if ctx.startswith("heartbeat-"):
        return ctx[len("heartbeat-"):]
    return "liveness"
