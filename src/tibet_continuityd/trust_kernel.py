"""
trust_kernel.py — Zone-policy decision layer (v0.2.1).

This module implements Gate D ("zone clarity") of Codex'
maturing-plan via a TOML-driven policy engine.

Role in the pipeline:

    arrival → SNIFF (v0.1)
              → emit sniff record
            → VERIFY + FORK (v0.2)
              → mint causal IDs, decide disposition
            → TRUST-KERNEL QUERY (v0.2.1, this module)
              → look up zone-policy for (lane, intake_class)
              → return TrustVerdict
              → trust_verdict_id stamped onto causal-IDs
              → disposition MAY be downgraded
                  (e.g. trusted-fork → triage-fork
                   if zone policy denies sealed-tbz)
            → emit verify-fork audit record with verdict

Zone policy TOML schema:

    [zone."inbox"]
    description = "Default sealed intake lane"
    allow = ["sealed-tbz", "sealed-tbz-no-ext"]
    triage = ["disguised"]
    reseal = ["json-text"]
    deny = ["executable", "pdf", "unknown", "empty"]

    [zone."triage"]
    description = "Operator review staging"
    allow = ["sealed-tbz", "sealed-tbz-no-ext", "disguised",
             "json-text", "executable", "pdf"]
    triage = []
    reseal = []
    deny = ["empty"]

Default search path:
  /etc/tibet/policies/zone-rules.toml

If no policy file exists, embedded sane defaults apply.

Future extension: delegate verdict to tibet-airlock SnaftMonitor
for kernel-level intent verification when running in production
strict-mode. v0.2.1 stays Python-only for boring-is-the-goal
deployment simplicity.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None


DEFAULT_POLICY_PATH = Path(
    os.environ.get(
        "TIBET_CONTINUITYD_POLICY",
        "/etc/tibet/policies/zone-rules.toml",
    )
)


# ─── Embedded defaults ──────────────────────────────────────────


# Sane defaults if no policy file is present. Same shape as the
# TOML schema. Each zone declares which intake-classes are
# allowed / triaged / resealed / denied.
EMBEDDED_DEFAULT_POLICIES: dict = {
    "zone": {
        "inbox": {
            "description": "Default sealed intake lane",
            "allow": ["sealed-tbz", "sealed-tbz-no-ext"],
            "triage": ["disguised"],
            "reseal": ["json-text"],
            "deny": ["executable", "pdf", "unknown", "empty"],
        },
        "triage": {
            "description": "Operator review staging",
            "allow": [
                "sealed-tbz", "sealed-tbz-no-ext",
                "disguised", "json-text",
                "executable", "pdf",
            ],
            "triage": [],
            "reseal": [],
            "deny": ["empty"],
        },
        "scratch": {
            "description": "Permissive dev/test lane",
            "allow": [
                "sealed-tbz", "sealed-tbz-no-ext",
                "disguised", "json-text", "unknown",
            ],
            "triage": [],
            "reseal": [],
            "deny": ["executable", "pdf", "empty"],
        },
    }
}


# ─── Verdict types ──────────────────────────────────────────────


@dataclass
class TrustVerdict:
    """Result of a trust-kernel zone-policy query.

    Verdict semantics:

      ALLOW     → disposition stays as verify_fork decided
      TRIAGE    → disposition is DOWNGRADED to triage-fork
                  regardless of what verify_fork wanted
      RESEAL    → disposition becomes reseal-required
                  (operator must seal before further processing)
      DENY      → disposition becomes reject-by-policy
                  (no fork, no continuation)
    """
    verdict: str                 # ALLOW | TRIAGE | RESEAL | DENY
    verdict_id: str              # tv_<16-hex> deterministic per query
    zone_name: str               # which zone-policy applied
    intake_class: str            # what was queried
    reason: str                  # human-readable explanation
    policy_source: str           # "embedded" | "toml:/path"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "verdict_id": self.verdict_id,
            "zone_name": self.zone_name,
            "intake_class": self.intake_class,
            "reason": self.reason,
            "policy_source": self.policy_source,
            "timestamp": self.timestamp,
        }


@dataclass
class TrustQuery:
    """Input for query_trust_kernel()."""
    intake_class: str            # e.g. "sealed-tbz", "disguised"
    zone_name: str               # e.g. "inbox", "triage", "scratch"
    actor_id: str                # JIS DID of the daemon
    object_id: str               # the object being queried about


# ─── Policy loader ──────────────────────────────────────────────


_POLICY_CACHE: tuple[dict, str] | None = None


def load_policies(
    path: Optional[Path] = None,
    *,
    use_cache: bool = True,
) -> tuple[dict, str]:
    """Load zone policies from TOML; fall back to embedded defaults.

    Returns (policies_dict, source_string).

    Cached by default (re-read on daemon restart only). Pass
    use_cache=False to force re-read (e.g. for tests).
    """
    global _POLICY_CACHE
    if use_cache and _POLICY_CACHE is not None:
        return _POLICY_CACHE

    target = path or DEFAULT_POLICY_PATH
    if target.exists() and tomllib is not None:
        try:
            with open(target, "rb") as f:
                data = tomllib.load(f)
            source = f"toml:{target}"
            _POLICY_CACHE = (data, source)
            return _POLICY_CACHE
        except Exception:
            # If TOML parse fails, fall through to embedded
            pass

    _POLICY_CACHE = (EMBEDDED_DEFAULT_POLICIES, "embedded")
    return _POLICY_CACHE


def _reset_cache() -> None:
    """For tests."""
    global _POLICY_CACHE
    _POLICY_CACHE = None


# ─── Verdict computation ────────────────────────────────────────


def _compute_verdict_id(query: TrustQuery, verdict: str,
                         policy_source: str) -> str:
    """Deterministic verdict_id over (query + verdict + source).

    Same inputs → same id, so verdict-stream is reproducible
    for testing and audit-replay. NOT a unique-per-call UUID;
    THAT is action_id's role.
    """
    canonical = json.dumps({
        "intake_class": query.intake_class,
        "zone_name": query.zone_name,
        "actor_id": query.actor_id,
        "object_id": query.object_id,
        "verdict": verdict,
        "policy_source": policy_source,
    }, sort_keys=True, separators=(",", ":")).encode()
    return "tv_" + hashlib.sha256(canonical).hexdigest()[:16]


def query_trust_kernel(
    query: TrustQuery,
    *,
    policy_path: Optional[Path] = None,
) -> TrustVerdict:
    """
    Look up zone-policy for the given (zone, intake_class) and
    return a TrustVerdict.

    If the zone is not in the policy, defaults to TRIAGE
    (= unknown zone is unsafe, downgrade to triage-fork).
    If the intake_class is not declared, defaults to TRIAGE
    (= same reasoning, fail-safe).
    """
    policies, source = load_policies(policy_path)

    zones = policies.get("zone", {})
    zone = zones.get(query.zone_name)

    if zone is None:
        verdict = "TRIAGE"
        reason = (f"zone {query.zone_name!r} not in policy table; "
                  f"default = TRIAGE (fail-safe)")
        return TrustVerdict(
            verdict=verdict,
            verdict_id=_compute_verdict_id(query, verdict, source),
            zone_name=query.zone_name,
            intake_class=query.intake_class,
            reason=reason,
            policy_source=source,
        )

    allow = zone.get("allow", [])
    triage = zone.get("triage", [])
    reseal = zone.get("reseal", [])
    deny = zone.get("deny", [])

    if query.intake_class in allow:
        verdict = "ALLOW"
        reason = (f"intake-class {query.intake_class!r} explicitly "
                  f"allowed in zone {query.zone_name!r}")
    elif query.intake_class in triage:
        verdict = "TRIAGE"
        reason = (f"intake-class {query.intake_class!r} routes to "
                  f"triage in zone {query.zone_name!r}")
    elif query.intake_class in reseal:
        verdict = "RESEAL"
        reason = (f"intake-class {query.intake_class!r} requires "
                  f"reseal in zone {query.zone_name!r}")
    elif query.intake_class in deny:
        verdict = "DENY"
        reason = (f"intake-class {query.intake_class!r} explicitly "
                  f"denied in zone {query.zone_name!r}")
    else:
        verdict = "TRIAGE"
        reason = (f"intake-class {query.intake_class!r} not "
                  f"declared in zone {query.zone_name!r}; "
                  f"default = TRIAGE (fail-safe)")

    return TrustVerdict(
        verdict=verdict,
        verdict_id=_compute_verdict_id(query, verdict, source),
        zone_name=query.zone_name,
        intake_class=query.intake_class,
        reason=reason,
        policy_source=source,
    )


# ─── Disposition merging ────────────────────────────────────────


def apply_verdict_to_disposition(
    base_disposition: str,
    verdict: TrustVerdict,
) -> tuple[str, str]:
    """Merge verify_fork's disposition with trust-kernel verdict.

    Returns (final_disposition, merge_reason).

    Rules:
      • verdict ALLOW  → keep base_disposition unchanged
      • verdict TRIAGE → downgrade to triage-fork unless already
                          triage/reject (= no-op then)
      • verdict RESEAL → reseal-required (overrides everything
                          except reject-invalid)
      • verdict DENY   → reject-by-policy (overrides everything)

    Note: reject-invalid stays reject-invalid regardless of
    verdict (cryptographic-failure is a HARDER signal than
    policy-decision; we already know the bundle is broken).
    """
    if base_disposition == "reject-invalid":
        # Crypto failure is final; policy doesn't override
        return ("reject-invalid",
                f"verify failed (crypto); verdict {verdict.verdict} ignored")

    if verdict.verdict == "ALLOW":
        return (base_disposition,
                f"zone-policy ALLOW (kept verify-fork disposition)")

    if verdict.verdict == "DENY":
        return ("reject-by-policy",
                f"zone-policy DENY: {verdict.reason}")

    if verdict.verdict == "RESEAL":
        return ("reseal-required",
                f"zone-policy RESEAL: {verdict.reason}")

    if verdict.verdict == "TRIAGE":
        if base_disposition in ("triage-fork",):
            # Already triage; verdict confirms but doesn't change
            return (base_disposition,
                    f"zone-policy TRIAGE (already triage-fork)")
        return ("triage-fork",
                f"zone-policy TRIAGE downgraded {base_disposition}: "
                f"{verdict.reason}")

    # Unknown verdict (shouldn't happen)
    return (base_disposition,
            f"unknown verdict {verdict.verdict!r}; kept disposition")


# ─── Public API ─────────────────────────────────────────────────


__all__ = [
    "DEFAULT_POLICY_PATH",
    "EMBEDDED_DEFAULT_POLICIES",
    "TrustQuery",
    "TrustVerdict",
    "load_policies",
    "query_trust_kernel",
    "apply_verdict_to_disposition",
]
