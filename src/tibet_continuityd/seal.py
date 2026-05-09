"""
seal.py — Seal stage (v0.3.0).

After Verify+Fork (v0.2/v0.2.1), the materialized state lives in
the daemon's runtime memory or its work-zone. The Seal stage
**re-packs** that state into a fresh TBZ/ICC bundle and emits
it to the outbox lane atomically (per atomic-transfer convention,
Codex' v02 spec).

Why Seal exists:

  • forward-causal append in the TIBET chain
    (= one more event in the continuity_id story-line, with
       parent_action_id pointing back to the verify-fork event)
  • outbox bundle is signed by the daemon's actor JIS DID
    (= "I, jis:humotica:continuityd@host, attest that this state
        is what I observed and accepted")
  • atomic publish via .part → mv (Codex' atomic-transfer spec)
    so downstream consumers never see a half-sealed bundle
  • complete provenance cycle:
       intake → verify → fork → seal → outbox → next-host-pipeline

Seal does NOT:

  • re-verify upstream signatures (= Verify's job, already done)
  • re-classify the payload (= Sniff's job, already done)
  • re-decide policy (= Trust-Kernel's job, already done)

Seal is purely a forward-causal **commit-and-publish** stage.

Spec: continuityd-v02-atomic-transfer-convention.md (Codex)
Plus: tza-icc-causal-record-embed-and-parse.md (Codex)
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Bridge to tibet_drop for TBZ pack primitives
_TIBET_DROP_SRC = Path("/srv/jtel-stack/sandbox/airdrop-cli/src")
if _TIBET_DROP_SRC.exists() and str(_TIBET_DROP_SRC) not in sys.path:
    sys.path.insert(0, str(_TIBET_DROP_SRC))

try:
    from tibet_drop.bundle import pack_bundle  # type: ignore
    from tibet_drop.crypto import IdentityKey  # type: ignore
    from tibet_drop.handshake import new_tpid  # type: ignore
except ImportError as e:
    raise ImportError(
        "seal requires tibet-drop. Install via PyPI (v0.3+) "
        "or ensure /srv/jtel-stack/sandbox/airdrop-cli/src is on "
        "sys.path."
    ) from e

from tibet_continuityd.verify_fork import CausalIDs, mint_action_id


# ─── Default outbox layout ──────────────────────────────────────


# Per Codex atomic-transfer-convention.md §"Aanbevolen padmodel":
# write to staging with .part suffix, then atomic mv to final
# name in the outbox lane.
DEFAULT_OUTBOX = Path(
    os.environ.get(
        "TIBET_CONTINUITYD_OUTBOX",
        "/var/lib/tibet/outbox",
    )
)
DEFAULT_OUTBOX_STAGING = Path(
    os.environ.get(
        "TIBET_CONTINUITYD_OUTBOX_STAGING",
        "/var/lib/tibet/outbox.staging",
    )
)


# ─── Seal result ────────────────────────────────────────────────


@dataclass
class SealResult:
    """Outcome of SealEngine.reseal() call."""
    sealed_path: Path                # final path in outbox lane
    bytes_written: int
    causal_ids: CausalIDs            # NEW lineage IDs (post-seal)
    seal_action_id: str              # the "seal" causal step
    duration_ms: float

    def to_dict(self) -> dict:
        return {
            "sealed_path": str(self.sealed_path),
            "bytes_written": self.bytes_written,
            "seal_action_id": self.seal_action_id,
            "duration_ms": self.duration_ms,
            **self.causal_ids.to_dict(),
        }


# ─── Seal engine ────────────────────────────────────────────────


class SealEngine:
    """Re-pack runtime state into a TBZ outbox bundle atomically.

    Per Codex' atomic-transfer convention (axe 2 hardening):
      1. compose blocks
      2. pack via tibet_drop into staging/<name>.part
      3. fsync
      4. atomic POSIX mv to outbox/<name>
      5. emit seal-stage audit event with NEW causal_ids
    """

    def __init__(
        self,
        signer: IdentityKey,
        actor_id: str,
        outbox: Path = DEFAULT_OUTBOX,
        staging: Path = DEFAULT_OUTBOX_STAGING,
    ):
        self.signer = signer
        self.actor_id = actor_id
        self.outbox = outbox
        self.staging = staging
        self.outbox.mkdir(parents=True, exist_ok=True)
        self.staging.mkdir(parents=True, exist_ok=True)

    def reseal(
        self,
        *,
        prior_causal_ids: CausalIDs,
        receiver_aint: str,
        receiver_pubkey_hex: str,
        sender_aint: str,
        blocks: list[tuple[str, bytes]],
        surface_time_fragment: Optional[str] = None,
        surface_context: str = "resealed",
        surface_profile: str = "tza",
        surface_priority: str = "normal",
        causal_reason: str = "trusted-resealed",
    ) -> SealResult:
        """
        Re-pack runtime state into an atomic-published TBZ bundle.

        prior_causal_ids = the verify-fork stage's IDs.
        New causal_ids inherit continuity_id, increment generation,
        and chain parent_action_id back to verify-fork's action.

        Returns SealResult with the final outbox path + new IDs.
        """
        t_start = time.perf_counter()

        # Compose surface fields
        time_frag = surface_time_fragment or \
            time.strftime("%Y-%m-%d", time.gmtime())
        bundle_name = (
            f"{time_frag}.{surface_context}."
            f"{surface_profile}.{surface_priority}.tza"
        )

        staging_path = self.staging / f"{bundle_name}.part"
        final_path = self.outbox / bundle_name

        # 1. Pack to staging (.part) — never directly to final
        pack_bundle(
            output_path=staging_path,
            blocks=blocks,
            sender_aint=sender_aint,
            sender_signer=self.signer,
            receiver_aint=receiver_aint,
            receiver_pubkey_hex=receiver_pubkey_hex,
            payload_type="ai_state",
            tpid=new_tpid(),
            surface_time_fragment=time_frag,
            surface_context=surface_context,
            surface_profile=surface_profile,
            surface_priority=surface_priority,
        )

        # 2. fsync the file (= writer is done, durable on disk)
        with open(staging_path, "rb") as f:
            os.fsync(f.fileno())
        bytes_written = staging_path.stat().st_size

        # 3. Atomic POSIX mv (= continuityd consumer sees
        #    MOVED_TO with final name only after fsync)
        os.rename(str(staging_path), str(final_path))

        # 4. Mint NEW causal IDs for the seal step
        new_action_id = mint_action_id()
        seal_causal_ids = CausalIDs(
            actor_id=self.actor_id,
            action_id=new_action_id,
            object_id=prior_causal_ids.object_id,  # same object
            continuity_id=prior_causal_ids.continuity_id,
            generation=prior_causal_ids.generation + 1,
            causal_reason=causal_reason,
            parent_action_id=prior_causal_ids.action_id,
            parent_object_id=prior_causal_ids.object_id,
            surface_hash=prior_causal_ids.surface_hash,
            prev_surface_hash=prior_causal_ids.prev_surface_hash,
            trust_verdict_id=prior_causal_ids.trust_verdict_id,
        )

        duration_ms = (time.perf_counter() - t_start) * 1000.0

        return SealResult(
            sealed_path=final_path,
            bytes_written=bytes_written,
            causal_ids=seal_causal_ids,
            seal_action_id=new_action_id,
            duration_ms=duration_ms,
        )


__all__ = [
    "DEFAULT_OUTBOX",
    "DEFAULT_OUTBOX_STAGING",
    "SealEngine",
    "SealResult",
]
