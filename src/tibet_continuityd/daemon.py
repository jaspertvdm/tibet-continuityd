"""
daemon.py — main continuity-guardian loop (v0.1).

v0.1 scope (Codex MVP stappen 1-4):
- Watch ONE inbox directory for arrivals
- Sniff arrived payloads for intake-class
- Log to journald (or stdout) + JSONL audit trail
- Mode 1 (Passive Guardian) only — no auto-intervention
- v0.2 will add Verify + Fork (via phantom.icc)
- v0.3 will add Seal + Police
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tibet_continuityd.sniff import sniff_payload
from tibet_continuityd.watch import LaneWatcher


# ─── Configuration ──────────────────────────────────────────────


@dataclass
class DaemonConfig:
    """Runtime configuration for tibet-continuityd."""
    inbox: Path                                  # primary watched lane
    audit_jsonl: Path                            # operational audit log
    mode: str = "passive"                        # passive|sealing|strict
    log_level: str = "INFO"
    quarantine_dir: Optional[Path] = None        # v0.2+
    triage_dir: Optional[Path] = None            # v0.2+
    extra_lanes: list = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "DaemonConfig":
        """Build from environment variables (systemd-friendly)."""
        return cls(
            inbox=Path(os.environ.get(
                "TIBET_CONTINUITYD_INBOX",
                "/var/lib/tibet/inbox")),
            audit_jsonl=Path(os.environ.get(
                "TIBET_CONTINUITYD_AUDIT",
                "/var/log/tibet/continuityd-audit.jsonl")),
            mode=os.environ.get("TIBET_CONTINUITYD_MODE", "passive"),
            log_level=os.environ.get(
                "TIBET_CONTINUITYD_LOG_LEVEL", "INFO"),
            quarantine_dir=Path(os.environ.get(
                "TIBET_CONTINUITYD_QUARANTINE",
                "/var/lib/tibet/quarantine")),
            triage_dir=Path(os.environ.get(
                "TIBET_CONTINUITYD_TRIAGE",
                "/var/lib/tibet/triage")),
        )


# ─── Daemon ─────────────────────────────────────────────────────


class ContinuityDaemon:
    """
    The residential continuity guardian.

    v0.1 behavior:
      arrival → sniff → emit audit JSONL line + log
      no automatic intervention (Mode 1 only)
    """

    def __init__(self, cfg: DaemonConfig):
        self.cfg = cfg
        self.log = self._setup_logging()
        self._stop = False
        self._stats = {
            "events_total": 0,
            "events_arrival": 0,
            "events_sniffed": 0,
            "by_class": {},
        }

    def _setup_logging(self) -> logging.Logger:
        log = logging.getLogger("tibet-continuityd")
        log.setLevel(self.cfg.log_level.upper())
        if not log.handlers:
            h = logging.StreamHandler(sys.stderr)
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s"))
            log.addHandler(h)
        return log

    def _emit_audit(self, event_dict: dict) -> None:
        """Append one JSONL line to audit log. Best-effort."""
        try:
            self.cfg.audit_jsonl.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cfg.audit_jsonl, "a") as f:
                f.write(json.dumps(event_dict, sort_keys=True) + "\n")
        except OSError as e:
            self.log.warning(f"audit write failed: {e}")

    def _on_arrival(self, event) -> None:
        self._stats["events_arrival"] += 1

        # Brief settle delay so writers can flush
        time.sleep(0.05)

        result = sniff_payload(event.full_path)
        self._stats["events_sniffed"] += 1
        self._stats["by_class"][result.intake_class.value] = \
            self._stats["by_class"].get(result.intake_class.value, 0) + 1

        record = {
            "ts": event.ts_unix,
            "lane": str(event.lane),
            "name": event.name,
            "stage": "sniff",
            "mode": self.cfg.mode,
            "flags": int(event.flags),
            **result.to_dict(),
        }
        self._emit_audit(record)
        self.log.info(
            f"arrival: {event.name!r} → "
            f"{result.intake_class.value} "
            f"({result.disposition_hint}, {result.size_bytes}B)"
        )

    def _install_signals(self) -> None:
        """Install SIGTERM/SIGINT handlers — only works in main thread.

        When the daemon is run from a test thread, signal installation
        is silently skipped; the test owner is responsible for setting
        `daemon._stop = True` to terminate the loop.
        """
        def _handler(signum, _frame):
            self.log.info(f"signal {signum} received, shutting down")
            self._stop = True
        try:
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT, _handler)
        except ValueError:
            # signal handlers can only be installed from the main thread
            self.log.debug("signal handlers skipped (not main thread)")

    def run(self) -> int:
        self.log.info(
            f"tibet-continuityd v0.1 starting "
            f"(mode={self.cfg.mode}, inbox={self.cfg.inbox})"
        )
        self._install_signals()

        # Ensure inbox exists
        self.cfg.inbox.mkdir(parents=True, exist_ok=True)

        with LaneWatcher([self.cfg.inbox]) as watcher:
            self.log.info(f"watching: {self.cfg.inbox}")
            for event in watcher.events(timeout_sec=1.0):
                if self._stop:
                    break
                self._stats["events_total"] += 1
                if not event.is_arrival:
                    continue
                self._on_arrival(event)

        self.log.info(f"shutdown stats: {self._stats}")
        return 0


def main() -> int:
    cfg = DaemonConfig.from_env()
    return ContinuityDaemon(cfg).run()


if __name__ == "__main__":
    sys.exit(main())
