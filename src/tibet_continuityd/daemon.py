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

from tibet_continuityd.coalesce import ArrivalCoalescer
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
    coalesce_debounce_ms: int = 350
    coalesce_max_pending_age_ms: int = 5000
    coalesce_high_churn_threshold: int = 5
    # v0.3.0 Seal stage
    enable_seal: bool = False
    outbox_dir: Optional[Path] = None
    outbox_staging_dir: Optional[Path] = None
    outbox_receiver_aint: str = "self.aint"
    # v0.3.1 Police stage
    enable_police: bool = False
    police_scan_interval_sec: float = 30.0       # how often to scan
    police_age_alert_threshold_sec: float = 300.0  # lingering bumps WARN

    @classmethod
    def from_env(cls) -> "DaemonConfig":
        """Build from environment variables (systemd-friendly)."""
        return cls(  # noqa: E1102
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
            coalesce_debounce_ms=int(os.environ.get(
                "TIBET_CONTINUITYD_COALESCE_DEBOUNCE_MS",
                "350")),
            coalesce_max_pending_age_ms=int(os.environ.get(
                "TIBET_CONTINUITYD_COALESCE_MAX_PENDING_AGE_MS",
                "5000")),
            coalesce_high_churn_threshold=int(os.environ.get(
                "TIBET_CONTINUITYD_COALESCE_HIGH_CHURN_THRESHOLD",
                "5")),
            enable_seal=os.environ.get(
                "TIBET_CONTINUITYD_ENABLE_SEAL", "0") in ("1", "true", "yes"),
            outbox_dir=Path(os.environ["TIBET_CONTINUITYD_OUTBOX"])
                if os.environ.get("TIBET_CONTINUITYD_OUTBOX") else None,
            outbox_staging_dir=Path(
                os.environ["TIBET_CONTINUITYD_OUTBOX_STAGING"])
                if os.environ.get("TIBET_CONTINUITYD_OUTBOX_STAGING")
                else None,
            outbox_receiver_aint=os.environ.get(
                "TIBET_CONTINUITYD_OUTBOX_RECEIVER",
                "self.aint"),
            enable_police=os.environ.get(
                "TIBET_CONTINUITYD_ENABLE_POLICE", "0")
                in ("1", "true", "yes"),
            police_scan_interval_sec=float(os.environ.get(
                "TIBET_CONTINUITYD_POLICE_INTERVAL_SEC", "30")),
            police_age_alert_threshold_sec=float(os.environ.get(
                "TIBET_CONTINUITYD_POLICE_AGE_ALERT_SEC", "300")),
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
            "events_coalesced": 0,
            "events_sealed": 0,
            "police_scans": 0,
            "police_findings": 0,
            "police_actions": {},
            "by_class": {},
            "by_disposition": {},
        }
        self._actor_id = self._ACTOR_ID_TEMPLATE.format(
            host=socket.gethostname() or "unknown"
        )
        self._last_police_scan_ts: float = 0.0

        # v0.3.1 Police stage — opt-in. Periodic scan via watcher's
        # timeout_cb hook (= no extra thread, uses existing timer
        # tick). Findings emit audit records + apply_action per mode.
        self._police_scanner = None
        if cfg.enable_police:
            from tibet_continuityd.police import PoliceScanner
            self._police_scanner = PoliceScanner(
                lane=cfg.inbox,
                age_alert_threshold_sec=cfg.police_age_alert_threshold_sec,
            )
            self.log.info(
                f"police stage enabled: lane={cfg.inbox}, "
                f"interval={cfg.police_scan_interval_sec}s, "
                f"age_alert={cfg.police_age_alert_threshold_sec}s"
            )

        # v0.3.0 Seal stage — opt-in. If enabled, mint an ephemeral
        # signer for this daemon-run. Production deployments should
        # provide a hardware-bound JIS keypair via a future
        # TIBET_CONTINUITYD_SIGNER_KEYPATH config. For now: ephemeral.
        self._seal_engine = None
        if cfg.enable_seal:
            from tibet_continuityd.seal import SealEngine
            from tibet_drop.crypto import IdentityKey  # type: ignore

            outbox = cfg.outbox_dir or Path("/var/lib/tibet/outbox")
            staging = cfg.outbox_staging_dir or \
                Path("/var/lib/tibet/outbox.staging")
            self._seal_signer = IdentityKey.generate()
            self._seal_engine = SealEngine(
                signer=self._seal_signer,
                actor_id=self._actor_id,
                outbox=outbox,
                staging=staging,
            )
            self.log.info(
                f"seal stage enabled: outbox={outbox}, "
                f"staging={staging}, "
                f"signer pub={self._seal_signer.pub_bytes().hex()[:16]}..."
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
            "coalesced": event.coalesced,
            "coalesced_event_count": event.coalesced_event_count,
            "coalesced_window_ms": event.coalesced_window_ms,
            "settled_after_ms": event.settled_after_ms,
            "path_churn_detected": event.path_churn_detected,
            **sniff_result.to_dict(),
            **intake_causal_ids.to_dict(),
        }
        if event.coalesced:
            self._stats["events_coalesced"] += 1
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

        # Run verify + fork (with v0.2.1 trust-kernel hook)
        # zone_name derived from lane basename (e.g. /var/lib/tibet/
        # inbox → "inbox"). Falls back to "inbox" if path is empty.
        zone_name = event.lane.name or "inbox"
        try:
            vf_result = verify_and_fork(
                event.full_path,
                actor_id=self._actor_id,
                intake_causal_ids=intake_causal_ids,
                intake_class=sniff_result.intake_class.value,
                zone_name=zone_name,
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
            "coalesced": event.coalesced,
            "coalesced_event_count": event.coalesced_event_count,
            "coalesced_window_ms": event.coalesced_window_ms,
            "settled_after_ms": event.settled_after_ms,
            "path_churn_detected": event.path_churn_detected,
            **vf_result.causal_ids.to_dict(),
        }
        self._emit_audit(verify_record)
        self.log.info(
            f"verify-fork: {event.name!r} → "
            f"{vf_result.disposition} "
            f"(verify={'valid' if vf_result.valid else 'invalid'}, "
            f"surface={vf_result.surface_status}) "
            f"[gen={vf_result.causal_ids.generation}, "
            f"action={vf_result.causal_ids.action_id}, "
            f"verdict={vf_result.causal_ids.trust_verdict_id}]"
        )

        # ─── Seal stage (v0.3.0, only on trusted-fork) ─────────
        if self._seal_engine is None:
            return
        if vf_result.disposition != "trusted-fork":
            # Only trusted disposition gets resealed to outbox.
            # Triage/reject/reseal-required dispositions are
            # handled by Police stage (v0.3.x future work).
            return

        try:
            # Re-pack the verified bundle as a single payload-block.
            # Daemon's actor identity becomes sender (= self-attest:
            # "I observed and accepted this state"). Receiver_aint
            # is the configured outbox-target (default "self.aint"
            # for local pipeline-resume scenarios).
            original_bytes = event.full_path.read_bytes()
            ephemeral_receiver = self._seal_signer  # self-target
            seal_result = self._seal_engine.reseal(
                prior_causal_ids=vf_result.causal_ids,
                receiver_aint=self.cfg.outbox_receiver_aint,
                receiver_pubkey_hex=ephemeral_receiver.pub_bytes().hex(),
                sender_aint=f"continuityd@{socket.gethostname() or 'host'}",
                blocks=[(event.name, original_bytes)],
                surface_context="resealed",
                surface_profile=vf_result.manifest.get(
                    "surface_profile", "tza"),
                surface_priority=vf_result.manifest.get(
                    "surface_priority", "normal"),
                causal_reason="trusted-resealed",
            )
        except Exception as e:
            self.log.warning(f"seal failed: {e}")
            return

        self._stats["events_sealed"] += 1
        seal_record = {
            "ts": time.time(),
            "lane": str(event.lane),
            "name": event.name,
            "stage": "seal",
            "mode": self.cfg.mode,
            "sealed_path": str(seal_result.sealed_path),
            "bytes_written": seal_result.bytes_written,
            "duration_ms": seal_result.duration_ms,
            **seal_result.causal_ids.to_dict(),
        }
        self._emit_audit(seal_record)
        self.log.info(
            f"seal: {event.name!r} → "
            f"{seal_result.sealed_path.name} "
            f"({seal_result.bytes_written}B, "
            f"{seal_result.duration_ms:.1f}ms) "
            f"[gen={seal_result.causal_ids.generation}, "
            f"action={seal_result.causal_ids.action_id}]"
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
        coalescer = ArrivalCoalescer(
            debounce_window_ms=self.cfg.coalesce_debounce_ms,
            max_pending_age_ms=self.cfg.coalesce_max_pending_age_ms,
            high_churn_threshold=self.cfg.coalesce_high_churn_threshold,
        )

        with LaneWatcher([self.cfg.inbox]) as watcher:
            self.log.info(f"watching: {self.cfg.inbox}")

            def _flush_settled() -> None:
                for settled in coalescer.flush_ready():
                    self._on_arrival(settled)

            def _periodic_tasks() -> None:
                """Called on every watcher select-timeout. Hosts both
                the coalesce-flush and the police-scan rhythms."""
                _flush_settled()
                self._maybe_run_police_scan()

            # stop_cb pattern: watcher checks self._stop on every
            # select-timeout AND after every yielded event, so
            # SIGTERM is honored within ~timeout_sec regardless of
            # arrival rate. Without this, an idle inbox would block
            # shutdown indefinitely (systemd force-kill after 90s).
            for event in watcher.events(
                timeout_sec=0.1,
                stop_cb=lambda: self._stop,
                timeout_cb=_periodic_tasks,
            ):
                if self._stop:
                    break
                self._stats["events_total"] += 1
                if not event.is_arrival:
                    continue
                coalescer.ingest(event)
                _flush_settled()

            _flush_settled()

        self.log.info(f"shutdown stats: {self._stats}")
        return 0

    def _maybe_run_police_scan(self) -> None:
        """Run a police scan if enabled AND interval-elapsed.

        Per Codex' timeout_cb hook design — no separate thread,
        rhythm shared with coalesce-flush via watcher's select-
        timeout.
        """
        if self._police_scanner is None:
            return
        now = time.time()
        if now - self._last_police_scan_ts < \
                self.cfg.police_scan_interval_sec:
            return
        self._last_police_scan_ts = now

        from tibet_continuityd.police import apply_action

        try:
            findings = self._police_scanner.scan()
        except Exception as e:
            self.log.warning(f"police scan failed: {e}")
            return

        if not findings:
            return

        self._stats["police_scans"] += 1
        self._stats["police_findings"] += len(findings)

        for finding in findings:
            try:
                action = apply_action(
                    finding,
                    mode=self.cfg.mode,
                    quarantine_dir=self.cfg.quarantine_dir,
                )
            except Exception as e:
                self.log.warning(
                    f"police apply_action failed for "
                    f"{finding.name!r}: {e}"
                )
                continue

            self._stats["police_actions"][action.action] = \
                self._stats["police_actions"].get(action.action, 0) + 1

            police_record = {
                "ts": time.time(),
                "stage": "police",
                "mode": self.cfg.mode,
                "actor_id": self._actor_id,
                "action": action.action,
                "moved_to": str(action.moved_to)
                    if action.moved_to else None,
                "error": action.error,
                **finding.to_dict(),
            }
            self._emit_audit(police_record)
            self.log.info(
                f"police: {finding.name!r} → "
                f"{finding.severity.value}/{action.action} "
                f"({finding.intake_class})"
            )


def main() -> int:
    cfg = DaemonConfig.from_env()
    return ContinuityDaemon(cfg).run()


if __name__ == "__main__":
    sys.exit(main())
