"""
tibet-continuityd — Continuous Integrity System Daemon
=======================================================

A residential trust guardian that runs in the background of
every machine where TIBET cryptographic discipline must be
continuously enforced.

  Watch  → inotify
  Sniff  → libmagic / TBZ magic-byte recognition
  Verify → (v0.2) cryptographic verification
  Fork   → (v0.2) forward-causal materialize via phantom.icc
  Triage → (v0.2) quarantine on mismatch
  Reseal → (v0.3) periodic reseal of materialized state

Three operating modes:
  Mode 1  Passive Guardian  observe + log + advise
  Mode 2  Sealing Guardian  auto-reseal + active intake
  Mode 3  Strict Continuity zero-trust, ICC/TBZ only

Spec: /srv/jtel-stack/hersenspinsels/tibet-continuityd-spec.md
Plus: /srv/jtel-stack/hersenspinsels/tibet-continuity-guardian.md
       (Codex' parallel intake-discipline guide)

  "Name is hint. Content is truth. Arrival is event."
                                — Codex, 9 mei 2026
"""

__version__ = "0.3.1"
__author__ = "Jasper van de Meent, Root AI, Codex"

from tibet_continuityd.daemon import ContinuityDaemon
from tibet_continuityd.police import (
    FindingSeverity,
    PoliceAction,
    PoliceFinding,
    PoliceScanner,
    apply_action,
)
from tibet_continuityd.seal import SealEngine, SealResult
from tibet_continuityd.sniff import IntakeClass, sniff_payload
from tibet_continuityd.trust_kernel import (
    TrustQuery,
    TrustVerdict,
    apply_verdict_to_disposition,
    load_policies,
    query_trust_kernel,
)
from tibet_continuityd.verify_fork import (
    CausalIDs,
    VerifyForkResult,
    verify_and_fork,
)
from tibet_continuityd.watch import LaneWatcher, WatchEvent

__all__ = [
    "ContinuityDaemon",
    "LaneWatcher",
    "WatchEvent",
    "IntakeClass",
    "sniff_payload",
    "CausalIDs",
    "VerifyForkResult",
    "verify_and_fork",
    "TrustQuery",
    "TrustVerdict",
    "query_trust_kernel",
    "apply_verdict_to_disposition",
    "load_policies",
    "SealEngine",
    "SealResult",
    "PoliceFinding",
    "PoliceScanner",
    "PoliceAction",
    "FindingSeverity",
    "apply_action",
]
