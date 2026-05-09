"""
daemon.py — main continuity-guardian loop (v0.1 + v0.2).

v0.1 scope (Codex MVP stappen 1-4):
- Watch ONE inbox directory for arrivals
- Sniff arrived payloads for intake-class
- Log to journald (or stdout) + JSONL audit trail
- Mode "passive" — no automatic verify/fork

v0.2 ADDS (this version):
- Verify stage  — cryptographic check via tibet_drop.verify_bundle()
                  + surface consistency (filename ↔ manifest)
- Fork stage    — forward-causal materialize event with 7-layer
                  causal ID model (action_id/object_id/parents/
                  continuity/generation/causal_reason/surface_hash)
- Mode "active" — sniff + verify + fork voor sealed-tbz
                  (other classes blijven sniff-only)
- Mode "passive" blijft default = sniff-only (= v0.1 backward
                  compatibility)

v0.3 will add: Seal (continuous reseal) + Police + Mode "strict"
v0.2.1 will add: trust_verdict_id via trust-kernel airlock hook
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import signal
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tibet_continuityd.sniff import IntakeClass, sniff_payload
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

    Behavior per mode:
      "passive" (v0.1 default):
          arrival → sniff → emit sniff audit line
      "active" (v0.2):
          arrival → sniff → emit sniff audit line
          if intake_class == sealed-tbz:
              verify + fork → emit verify-fork audit line
      "strict" (v0.3 future):
          only sealed-tbz admitted, others quarantined
    """

    # Daemon's own JIS-style actor ID (will be replaced with real
    # JIS DID once trust-kernel hook lands in v0.2.1)
    _ACTOR_ID_TEMPLATE = "jis:humotica:continuityd@{host}"

    def __init__(self, cfg: DaemonConfig):
        self.cfg = cfg
        self.log = self._setup_logging()
        self._stop = False
        self._stats = {
            "events_total": 0,
            "events_arrival": 0,
            "events_sniffed": 0,
            "events_verified": 0,
            "events_forked": 0,
            "by_class": {},
            "by_disposition": {},
        }
        self._actor_id = self._ACTOR_ID_TEMPLATE.format(
            host=socket.gethostname() or "unknown"
        )

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

        # ─── Sniff stage (v0.1) ────────────────────────────
        sniff_result = sniff_payload(event.full_path)
        self._stats["events_sniffed"] += 1
        self._stats["by_class"][sniff_result.intake_class.value] = \
            self._stats["by_class"].get(
                sniff_result.intake_class.value, 0) + 1

        # Mint causal IDs for this intake-cycle (per Codex spec
        # continuity-plan-causal-ids-and-loops.md). Each fresh
        # arrival opens a new continuity_id. Verify/Fork stage
        # will inherit and chain forward.
        from tibet_continuityd.verify_fork import (
            CausalIDs,
            compute_surface_hash,
            mint_action_id,
            mint_continuity_id,
            mint_object_id,
            verify_and_fork,
        )

        intake_causal_ids = CausalIDs(
            actor_id=self._actor_id,
            action_id=mint_action_id(),
            object_id=mint_object_id(),
            continuity_id=mint_continuity_id(),
            generation=0,
            causal_reason="initial-intake",
            parent_action_id=None,
            parent_object_id=None,
            surface_hash=compute_surface_hash(event.name, None),
            prev_surface_hash=None,
            trust_verdict_id=None,
        )

        sniff_record = {
            "ts": event.ts_unix,
            "lane": str(event.lane),
            "name": event.name,
            "stage": "sniff",
            "mode": self.cfg.mode,
            "flags": int(event.flags),
            **sniff_result.to_dict(),
            **intake_causal_ids.to_dict(),
        }
        self._emit_audit(sniff_record)
        self.log.info(
            f"arrival: {event.name!r} → "
            f"{sniff_result.intake_class.value} "
            f"({sniff_result.disposition_hint}, "
            f"{sniff_result.size_bytes}B) "
            f"[continuity={intake_causal_ids.continuity_id}]"
        )

        # ─── Verify + Fork stages (v0.2, only in active mode) ──
        if self.cfg.mode != "active":
            return

        # Only sealed-tbz arrivals get verify + fork in v0.2.
        # (sealed-tbz-no-ext also qualifies — same magic, no ext)
        sealed_classes = {
            IntakeClass.SEALED_TBZ,
            IntakeClass.SEALED_TBZ_NO_EXT,
        }
        if sniff_result.intake_class not in sealed_classes:
            return

        # Run verify + fork
        try:
            vf_result = verify_and_fork(
                event.full_path,
                actor_id=self._actor_id,
                intake_causal_ids=intake_causal_ids,
            )
        except Exception as e:
            self.log.warning(f"verify_fork failed: {e}")
            return

        self._stats["events_verified"] += 1
        if vf_result.disposition.endswith("-fork"):
            self._stats["events_forked"] += 1
        self._stats["by_disposition"][vf_result.disposition] = \
            self._stats["by_disposition"].get(
                vf_result.disposition, 0) + 1

        verify_record = {
            "ts": time.time(),
            "lane": str(event.lane),
            "name": event.name,
            "stage": "verify-fork",
            "mode": self.cfg.mode,
            "verify_valid": vf_result.valid,
            "surface_status": vf_result.surface_status,
            "disposition": vf_result.disposition,
            "verify_errors": vf_result.verify_errors,
            **vf_result.causal_ids.to_dict(),
        }
        self._emit_audit(verify_record)
        self.log.info(
            f"verify-fork: {event.name!r} → "
            f"{vf_result.disposition} "
            f"(verify={'valid' if vf_result.valid else 'invalid'}, "
            f"surface={vf_result.surface_status}) "
            f"[gen={vf_result.causal_ids.generation}, "
            f"action={vf_result.causal_ids.action_id}]"
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
            f"tibet-continuityd v0.2 starting "
            f"(mode={self.cfg.mode}, actor={self._actor_id}, "
            f"inbox={self.cfg.inbox})"
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
