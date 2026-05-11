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

__version__ = "0.5.5"
__author__ = "Jasper van de Meent, Root AI, Codex"

# Core stages — pure stdlib, always available
from tibet_continuityd.backpressure import (
    BackpressureMonitor,
    BackpressureSnapshot,
    BackpressureState,
)
from tibet_continuityd.police import (
    FindingSeverity,
    PoliceAction,
    PoliceFinding,
    PoliceScanner,
    apply_action,
)
from tibet_continuityd.sniff import IntakeClass, sniff_payload
from tibet_continuityd.trust_kernel import (
    TrustQuery,
    TrustVerdict,
    apply_verdict_to_disposition,
    load_policies,
    query_trust_kernel,
)
from tibet_continuityd.watch import LaneWatcher, WatchEvent

# Verify + Fork + Seal — require tibet-drop (install via [verify] extra)
# Defensive imports: core daemon works without these.
try:
    from tibet_continuityd.verify_fork import (
        CausalIDs,
        VerifyForkResult,
        verify_and_fork,
    )
    from tibet_continuityd.seal import SealEngine, SealResult
    from tibet_continuityd.daemon import ContinuityDaemon
    _HAS_VERIFY = True
except ImportError:
    # tibet-drop not on sys.path — verify/fork/seal/daemon unavailable.
    # Core sniff/police/trust_kernel/watch/backpressure still work.
    CausalIDs = None  # type: ignore
    VerifyForkResult = None  # type: ignore
    verify_and_fork = None  # type: ignore
    SealEngine = None  # type: ignore
    SealResult = None  # type: ignore
    ContinuityDaemon = None  # type: ignore
    _HAS_VERIFY = False

__all__ = [
    # Core (always available)
    "LaneWatcher",
    "WatchEvent",
    "IntakeClass",
    "sniff_payload",
    "TrustQuery",
    "TrustVerdict",
    "query_trust_kernel",
    "apply_verdict_to_disposition",
    "load_policies",
    "PoliceFinding",
    "PoliceScanner",
    "PoliceAction",
    "FindingSeverity",
    "apply_action",
    "BackpressureMonitor",
    "BackpressureSnapshot",
    "BackpressureState",
    # Verify-stage (None when tibet-drop unavailable)
    "ContinuityDaemon",
    "CausalIDs",
    "VerifyForkResult",
    "verify_and_fork",
    "SealEngine",
    "SealResult",
    # Capability flag
    "_HAS_VERIFY",
]
