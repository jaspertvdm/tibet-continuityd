"""
verify_fork.py — Verify + Fork stages (v0.2).

After Sniff classifies an arrival as sealed-tbz, v0.2 adds:

  Stage VERIFY  — cryptographic check via tibet_drop.verify_bundle()
                  + surface consistency check (filename ↔ manifest)
  Stage FORK    — forward-causal "materialize" event with 7-layer
                  causal ID model (per Codex spec
                  continuity-plan-causal-ids-and-loops.md)

Decision tree:

  verify INVALID                    → causal_reason="verify-failed-reject"
                                      disposition="reject-invalid"
  verify VALID + surface MATCH      → causal_reason="trusted-materialization"
                                      disposition="trusted-fork"
  verify VALID + surface MISMATCH   → causal_reason="surface-mismatch-triage-fork"
                                      disposition="triage-fork"
  verify VALID + surface PARTIAL    → causal_reason="surface-partial-triage-fork"
                                      disposition="triage-fork"
  verify VALID + surface NONE       → causal_reason="legacy-bundle-trusted"
                                      disposition="trusted-fork"

Per Jasper's directieven:
  - Raw view = canonical audit (we emit ALL fields including
    operational meta + 7-layer causal IDs)
  - v0.2 = "voordeur beveiligen → levenslijn garanderen"
  - JIS+ ruggengraat: actor_id + parent_*_id + generation +
    surface_hash form the lineage chain

trust_verdict_id is reserved for v0.2.1 (trust-kernel zone-clarity
hook). For v0.2: emitted as None.
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

# Bridge to tibet_drop for cryptographic verify primitives.
# Path-imported in v0.2; v0.3 will move tibet-drop to PyPI dep.
_TIBET_DROP_SRC = Path("/srv/jtel-stack/sandbox/airdrop-cli/src")
if _TIBET_DROP_SRC.exists() and str(_TIBET_DROP_SRC) not in sys.path:
    sys.path.insert(0, str(_TIBET_DROP_SRC))

try:
    from tibet_drop.bundle import (  # type: ignore
        compare_surfaces,
        parse_filename_surface,
        verify_bundle,
    )
except ImportError as e:
    raise ImportError(
        "verify_fork requires tibet-drop. Install via PyPI (v0.3+) "
        "or ensure /srv/jtel-stack/sandbox/airdrop-cli/src is on "
        "sys.path."
    ) from e


# ─── Causal ID minting ──────────────────────────────────────────


def mint_action_id() -> str:
    """Per Codex spec §1: act_<16-hex>."""
    return f"act_{uuid.uuid4().hex[:16]}"


def mint_object_id() -> str:
    """Per Codex spec §3: obj_<16-hex>."""
    return f"obj_{uuid.uuid4().hex[:16]}"


def mint_continuity_id() -> str:
    """Per Codex spec §6: cont_<16-hex>. Bind handoffs / forks /
    triage / interventions in one story-line."""
    return f"cont_{uuid.uuid4().hex[:16]}"


# ─── Surface hashing ────────────────────────────────────────────


def compute_surface_hash(name: str, manifest: dict | None) -> str:
    """sha256 over canonical surface representation.

    Surface is filename + mirrored manifest surface_* fields.
    Used for lineage tracking + downstream change-detection.

    Per spec (causal-IDs §"surface_hash"): "Handig om aan te
    tonen: surface gewijzigd / surface gelijk gebleven /
    routing posture verschoof."

    Plus per side-by-side report finding: surface_hash MUST be
    computed over normalized canonical JSON (sort_keys=True,
    no whitespace) to be transport-independent.
    """
    if manifest is None:
        manifest = {}
    surface_obj = {
        "filename": name,
        "manifest_surface_time_fragment":
            manifest.get("surface_time_fragment"),
        "manifest_surface_context": manifest.get("surface_context"),
        "manifest_surface_profile": manifest.get("surface_profile"),
        "manifest_surface_priority": manifest.get("surface_priority"),
    }
    canonical = json.dumps(
        surface_obj, sort_keys=True, separators=(",", ":")
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# ─── Causal audit fields ────────────────────────────────────────


@dataclass
class CausalIDs:
    """7-layer causal ID model per Codex spec.

    All lineage fields. v0.1 daemon doesn't have these;
    v0.2 introduces them for sealed-tbz arrivals that pass
    verify+fork.
    """
    actor_id: str                         # who handled (JIS DID)
    action_id: str                        # this action UUID
    object_id: str                        # the object UUID
    continuity_id: str                    # story line UUID
    generation: int                        # Lamport-monotone counter
    causal_reason: str                    # why this successor exists
    parent_action_id: Optional[str] = None
    parent_object_id: Optional[str] = None
    surface_hash: Optional[str] = None
    prev_surface_hash: Optional[str] = None
    trust_verdict_id: Optional[str] = None  # v0.2.1 will fill

    def to_dict(self) -> dict:
        return {
            "actor_id": self.actor_id,
            "action_id": self.action_id,
            "object_id": self.object_id,
            "continuity_id": self.continuity_id,
            "generation": self.generation,
            "causal_reason": self.causal_reason,
            "parent_action_id": self.parent_action_id,
            "parent_object_id": self.parent_object_id,
            "surface_hash": self.surface_hash,
            "prev_surface_hash": self.prev_surface_hash,
            "trust_verdict_id": self.trust_verdict_id,
        }


# ─── Verify + Fork ──────────────────────────────────────────────


@dataclass
class VerifyForkResult:
    """Outcome of verify_and_fork() call."""
    valid: bool
    surface_status: str                  # MATCH / MISMATCH / PARTIAL / NONE
    disposition: str                     # trusted-fork / triage-fork /
                                          # reject-invalid
    causal_ids: CausalIDs                # 7-layer fields for new event
    verify_errors: list = field(default_factory=list)
    manifest: dict = field(default_factory=dict)


def verify_and_fork(
    bundle_path: Path,
    *,
    actor_id: str,
    intake_causal_ids: CausalIDs,
) -> VerifyForkResult:
    """
    Verify a sealed-tbz bundle and decide forward-causal
    disposition.

    intake_causal_ids = the IDs from the prior Sniff stage.
    Result.causal_ids = NEW lineage IDs for THIS verify+fork
    event, with parent_* pointing to the intake.

    Forward-only invariant: result is ALWAYS a new action_id.
    Object_id may be inherited (= "same object, new step") or
    minted (= "new object derived from intake") depending on
    disposition.
    """
    # Step 1: cryptographic verify
    valid, manifest, errors = verify_bundle(bundle_path)

    # Step 2: surface consistency check
    fn_surface = parse_filename_surface(bundle_path.name)
    mf_surface = {k: manifest.get(k) for k in (
        "surface_time_fragment", "surface_context",
        "surface_profile", "surface_priority")}
    surface_status = compare_surfaces(fn_surface, mf_surface)

    # Step 3: surface hash (over filename + manifest mirror)
    surface_hash = compute_surface_hash(
        bundle_path.name, manifest if valid else {}
    )

    # Step 4: decide disposition + causal_reason
    if not valid:
        causal_reason = "verify-failed-reject"
        disposition = "reject-invalid"
    elif surface_status == "MISMATCH":
        causal_reason = "surface-mismatch-triage-fork"
        disposition = "triage-fork"
    elif surface_status == "PARTIAL":
        causal_reason = "surface-partial-triage-fork"
        disposition = "triage-fork"
    elif surface_status == "NONE":
        # No surface_* present in manifest — legacy bundle.
        # Trust if verify passed.
        causal_reason = "legacy-bundle-trusted"
        disposition = "trusted-fork"
    else:  # MATCH
        causal_reason = "trusted-materialization"
        disposition = "trusted-fork"

    # Step 5: mint new causal IDs (forward-only fork)
    new_action_id = mint_action_id()

    # Object lineage:
    #  - trusted-fork  → new object derived from intake
    #  - triage-fork   → new object (forked into triage line)
    #  - reject        → no new object, parent ref only
    if disposition == "reject-invalid":
        new_object_id = intake_causal_ids.object_id
    else:
        new_object_id = mint_object_id()

    new_causal_ids = CausalIDs(
        actor_id=actor_id,
        action_id=new_action_id,
        object_id=new_object_id,
        continuity_id=intake_causal_ids.continuity_id,
        generation=intake_causal_ids.generation + 1,
        causal_reason=causal_reason,
        parent_action_id=intake_causal_ids.action_id,
        parent_object_id=intake_causal_ids.object_id,
        surface_hash=surface_hash,
        prev_surface_hash=intake_causal_ids.surface_hash,
        trust_verdict_id=None,  # v0.2.1 trust-kernel hook
    )

    return VerifyForkResult(
        valid=valid,
        surface_status=surface_status,
        disposition=disposition,
        causal_ids=new_causal_ids,
        verify_errors=errors,
        manifest=manifest if valid else {},
    )


# ─── Public API ─────────────────────────────────────────────────


__all__ = [
    "CausalIDs",
    "VerifyForkResult",
    "verify_and_fork",
    "mint_action_id",
    "mint_object_id",
    "mint_continuity_id",
    "compute_surface_hash",
]
