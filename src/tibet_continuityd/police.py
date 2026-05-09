"""
police.py — Police stage (v0.3.1).

Police scans watched lanes for "unpacked state": files that
shouldn't be there per the zone-policy, OR files that are
sitting around without a forward-causal-step anchor.

Examples of unpacked state:
  • plain JSON in inbox (sealed-only zone)
  • executable / PDF files in sealed-only zone
  • old files in inbox that should have been processed
    but were not (= dropped event = kernel overflow trace)
  • directory mutations not bound to a causal step

Police complements Sniff:
  Sniff handles arrival events (push from inotify).
  Police handles standing state (pull, periodic scan).

Both feed the same disposition table from trust-kernel.

Per Codex' axiom 'Arrival is event' + this module's
companion: 'Persistence is state — also an event when it
shouldn't be persistent.'

Mode interactions (per zone-policy verdict):
  passive : observe + audit-only (= log it, do nothing)
  active  : audit + triage-fork (= forward-causal triage event)
  strict  : audit + quarantine (= mv to quarantine_dir)
"""
from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from tibet_continuityd.sniff import (
    IntakeClass,
    SniffResult,
    sniff_payload,
)


# ─── Finding types ──────────────────────────────────────────────


class FindingSeverity(Enum):
    """Severity classes per finding."""
    INFO = "info"           # observed, expected (e.g. trusted in active)
    WARN = "warn"           # operator attention
    ALERT = "alert"         # likely policy violation
    CRITICAL = "critical"   # immediate quarantine candidate


@dataclass
class PoliceFinding:
    """One outcome of a police scan over a lane."""
    name: str                            # filename relative to lane
    full_path: Path                      # absolute
    lane: Path                           # which lane
    severity: FindingSeverity
    intake_class: str                    # from sniff_payload
    disposition_hint: str
    reason: str                          # human-readable
    age_seconds: float                   # how long the file has lingered
    size_bytes: int
    ts_unix: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "full_path": str(self.full_path),
            "lane": str(self.lane),
            "severity": self.severity.value,
            "intake_class": self.intake_class,
            "disposition_hint": self.disposition_hint,
            "reason": self.reason,
            "age_seconds": round(self.age_seconds, 2),
            "size_bytes": self.size_bytes,
            "ts_unix": self.ts_unix,
        }


# ─── Severity table ─────────────────────────────────────────────


# Map (zone_purpose, intake_class) → severity for police findings.
# Default zone_purpose = "sealed-only" = strict zone like inbox.
# For mixed/scratch zones, severity is downgraded.
_SEVERITY_DEFAULTS = {
    # sealed-only zone defaults:
    IntakeClass.SEALED_TBZ: FindingSeverity.INFO,
    IntakeClass.SEALED_TBZ_NO_EXT: FindingSeverity.INFO,
    IntakeClass.STAGING: FindingSeverity.INFO,  # in-flight, expected
    IntakeClass.JSON_TEXT: FindingSeverity.WARN,
    IntakeClass.DISGUISED: FindingSeverity.ALERT,
    IntakeClass.EXECUTABLE: FindingSeverity.CRITICAL,
    IntakeClass.PDF: FindingSeverity.WARN,
    IntakeClass.UNKNOWN: FindingSeverity.WARN,
    IntakeClass.EMPTY: FindingSeverity.INFO,
}


def _classify_severity(
    sniff: SniffResult,
    age_seconds: float,
    age_alert_threshold_sec: float = 300.0,
) -> FindingSeverity:
    """Determine severity for a police finding.

    Plus: any file that lingers too long (> age_alert_threshold)
    bumps to at least WARN even if intake_class is benign.
    """
    base = _SEVERITY_DEFAULTS.get(
        sniff.intake_class, FindingSeverity.WARN
    )

    # Lingering files bump severity (= dropped events sign?)
    if age_seconds > age_alert_threshold_sec:
        if base == FindingSeverity.INFO:
            return FindingSeverity.WARN
    return base


# ─── Police scanner ─────────────────────────────────────────────


@dataclass
class PoliceScanner:
    """Periodic scanner for unpacked state in watched lanes.

    Usage:
        scanner = PoliceScanner(lane=Path("/var/lib/tibet/inbox"))
        findings = scanner.scan()
        for f in findings:
            ...
    """
    lane: Path
    age_alert_threshold_sec: float = 300.0      # 5 min lingering = warn
    skip_staging: bool = True                   # ignore .part / .tmp

    def scan(self) -> list[PoliceFinding]:
        """Scan the lane for ALL files and produce a finding per."""
        if not self.lane.exists() or not self.lane.is_dir():
            return []

        findings: list[PoliceFinding] = []
        now = time.time()

        for entry in self.lane.iterdir():
            if not entry.is_file():
                continue

            sniff = sniff_payload(entry)

            if self.skip_staging and \
                    sniff.intake_class == IntakeClass.STAGING:
                continue

            try:
                stat = entry.stat()
                age = now - stat.st_mtime
                size = stat.st_size
            except OSError:
                continue

            severity = _classify_severity(
                sniff, age, self.age_alert_threshold_sec
            )

            # Reason text
            reason_parts = [
                f"intake_class={sniff.intake_class.value}",
                f"disposition={sniff.disposition_hint}",
            ]
            if age > self.age_alert_threshold_sec:
                reason_parts.append(
                    f"lingering {age:.0f}s "
                    f"(>{self.age_alert_threshold_sec:.0f}s threshold)"
                )

            reason = " · ".join(reason_parts)

            findings.append(PoliceFinding(
                name=entry.name,
                full_path=entry.resolve(),
                lane=self.lane,
                severity=severity,
                intake_class=sniff.intake_class.value,
                disposition_hint=sniff.disposition_hint,
                reason=reason,
                age_seconds=age,
                size_bytes=size,
            ))

        return findings


# ─── Mode-driven action ─────────────────────────────────────────


@dataclass
class PoliceAction:
    """Outcome of applying mode-driven action to a finding."""
    finding: PoliceFinding
    action: str                              # observe | triage | quarantine
    moved_to: Optional[Path] = None          # if quarantined
    error: Optional[str] = None


def apply_action(
    finding: PoliceFinding,
    mode: str,
    quarantine_dir: Optional[Path] = None,
) -> PoliceAction:
    """Apply the mode-driven action to a police finding.

    Mode:
      passive  → "observe" (audit only, no file move)
      active   → "triage" (audit only — actual triage-fork is
                   driven by daemon's verify_fork integration)
      strict   → "quarantine" (mv to quarantine_dir if severe)
    """
    # observe-only modes
    if mode in ("passive", "active"):
        action_name = "observe" if mode == "passive" else "triage"
        return PoliceAction(finding=finding, action=action_name)

    # strict mode: severe findings get quarantined
    if mode == "strict":
        if finding.severity in (FindingSeverity.ALERT,
                                 FindingSeverity.CRITICAL):
            if quarantine_dir is None:
                return PoliceAction(
                    finding=finding,
                    action="strict-no-quarantine-dir",
                    error="quarantine_dir not configured",
                )
            try:
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                target = quarantine_dir / finding.name
                # Avoid collision: if target exists, suffix with ts
                if target.exists():
                    target = quarantine_dir / \
                        f"{finding.name}.{int(finding.ts_unix)}"
                os.rename(str(finding.full_path), str(target))
                return PoliceAction(
                    finding=finding,
                    action="quarantine",
                    moved_to=target.resolve(),
                )
            except OSError as e:
                return PoliceAction(
                    finding=finding,
                    action="quarantine-failed",
                    error=str(e),
                )
        # less-severe in strict mode = still observe only
        return PoliceAction(finding=finding, action="observe")

    # unknown mode
    return PoliceAction(
        finding=finding,
        action="unknown-mode",
        error=f"unknown mode {mode!r}",
    )


# ─── Public API ─────────────────────────────────────────────────


__all__ = [
    "FindingSeverity",
    "PoliceAction",
    "PoliceFinding",
    "PoliceScanner",
    "apply_action",
]
