"""Tests for v0.2 verify+fork stage.

Validates:
  • verify VALID + surface MATCH       → trusted-fork
  • verify VALID + surface MISMATCH    → triage-fork
  • verify VALID + surface NONE         → trusted-fork (legacy)
  • verify INVALID                     → reject-invalid
  • forward-only causal IDs (parent_*)
  • generation monotonically increases
  • surface_hash deterministic
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

# Bridge to airdrop-cli + local package
_TIBET_DROP = Path("/srv/jtel-stack/sandbox/airdrop-cli/src")
if str(_TIBET_DROP) not in sys.path:
    sys.path.insert(0, str(_TIBET_DROP))
_PKG = Path("/srv/jtel-stack/packages/tibet-continuityd/src")
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from tibet_drop.bundle import pack_bundle  # noqa: E402
from tibet_drop.crypto import IdentityKey  # noqa: E402
from tibet_drop.handshake import new_tpid  # noqa: E402

from tibet_continuityd.verify_fork import (  # noqa: E402
    CausalIDs,
    compute_surface_hash,
    mint_action_id,
    mint_continuity_id,
    mint_object_id,
    verify_and_fork,
)


# ─── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def alice_bob():
    return IdentityKey.generate(), IdentityKey.generate()


@pytest.fixture
def intake_ids():
    return CausalIDs(
        actor_id="jis:humotica:continuityd@test",
        action_id=mint_action_id(),
        object_id=mint_object_id(),
        continuity_id=mint_continuity_id(),
        generation=0,
        causal_reason="initial-intake",
    )


def _make_sealed_bundle(
    tmp: Path,
    alice: IdentityKey,
    bob: IdentityKey,
    *,
    surface_time="2026-05-09",
    surface_context="test",
    surface_profile="claude",
    surface_priority="normal",
    filename: str | None = None,
) -> Path:
    """Build a real signed TBZ bundle in tmp/."""
    blocks = [("payload.txt", b"test payload content")]
    name = filename or (
        f"{surface_time}.{surface_context}.{surface_profile}."
        f"{surface_priority}.tza"
    )
    out = tmp / name
    pack_bundle(
        output_path=out,
        blocks=blocks,
        sender_aint="alice.aint",
        sender_signer=alice,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        payload_type="ai_state",
        tpid=new_tpid(),
        surface_time_fragment=surface_time,
        surface_context=surface_context,
        surface_profile=surface_profile,
        surface_priority=surface_priority,
    )
    return out


# ─── Causal ID minting ─────────────────────────────────────────


def test_action_id_format():
    aid = mint_action_id()
    assert aid.startswith("act_")
    assert len(aid) == 20  # "act_" + 16 hex


def test_object_id_format():
    oid = mint_object_id()
    assert oid.startswith("obj_")
    assert len(oid) == 20


def test_continuity_id_format():
    cid = mint_continuity_id()
    assert cid.startswith("cont_")
    assert len(cid) == 21


def test_ids_are_unique():
    seen = {mint_action_id() for _ in range(100)}
    assert len(seen) == 100


# ─── Surface hash determinism ───────────────────────────────────


def test_surface_hash_deterministic():
    h1 = compute_surface_hash("2026-05-09.test.claude.normal.tza", {
        "surface_time_fragment": "2026-05-09",
        "surface_context": "test",
        "surface_profile": "claude",
        "surface_priority": "normal",
    })
    h2 = compute_surface_hash("2026-05-09.test.claude.normal.tza", {
        "surface_time_fragment": "2026-05-09",
        "surface_context": "test",
        "surface_profile": "claude",
        "surface_priority": "normal",
    })
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_surface_hash_changes_on_filename():
    base = {
        "surface_time_fragment": "2026-05-09",
        "surface_context": "test",
        "surface_profile": "claude",
        "surface_priority": "normal",
    }
    h_a = compute_surface_hash("a.tza", base)
    h_b = compute_surface_hash("b.tza", base)
    assert h_a != h_b


def test_surface_hash_changes_on_priority():
    base = {
        "surface_time_fragment": "2026-05-09",
        "surface_context": "test",
        "surface_profile": "claude",
        "surface_priority": "normal",
    }
    swapped = {**base, "surface_priority": "urgent"}
    assert compute_surface_hash("x.tza", base) != \
           compute_surface_hash("x.tza", swapped)


def test_surface_hash_handles_none_manifest():
    h = compute_surface_hash("x.tza", None)
    assert h.startswith("sha256:")


# ─── Verify + Fork: 4 disposition paths ─────────────────────────


def test_verify_valid_surface_match_trusted_fork(alice_bob, intake_ids):
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.valid is True
        assert result.surface_status == "MATCH"
        assert result.disposition == "trusted-fork"
        assert result.causal_ids.causal_reason == \
            "trusted-materialization"


def test_verify_valid_surface_mismatch_triage_fork(
    alice_bob, intake_ids
):
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # Pack with priority=normal
        bundle = _make_sealed_bundle(
            tmp, alice, bob, surface_priority="normal"
        )
        # Rename to claim priority=urgent (= MISMATCH)
        renamed = bundle.parent / bundle.name.replace(
            ".normal.", ".urgent."
        )
        bundle.rename(renamed)

        result = verify_and_fork(
            renamed, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.valid is True  # crypto stays valid
        assert result.surface_status == "MISMATCH"
        assert result.disposition == "triage-fork"
        assert result.causal_ids.causal_reason == \
            "surface-mismatch-triage-fork"


def test_verify_invalid_reject(alice_bob, intake_ids):
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)
        # Corrupt last byte
        raw = bundle.read_bytes()
        bundle.write_bytes(raw[:-1] + b"\xff")

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.valid is False
        assert result.disposition == "reject-invalid"
        assert result.causal_ids.causal_reason == \
            "verify-failed-reject"
        assert len(result.verify_errors) > 0


def test_verify_legacy_no_surface_trusted(alice_bob, intake_ids):
    """Bundle without surface_* fields = NONE compare = trusted."""
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # Pack WITHOUT surface_* fields, with non-conforming
        # filename so parse_filename_surface returns None
        out = tmp / "legacy-bundle.bin"
        from tibet_drop.bundle import pack_bundle
        pack_bundle(
            output_path=out,
            blocks=[("payload.txt", b"legacy content")],
            sender_aint="alice.aint",
            sender_signer=alice,
            receiver_aint="bob.aint",
            receiver_pubkey_hex=bob.pub_bytes().hex(),
            payload_type="ai_state",
            tpid=new_tpid(),
            # no surface_* fields
        )

        result = verify_and_fork(
            out, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.valid is True
        assert result.surface_status == "NONE"
        assert result.disposition == "trusted-fork"
        assert result.causal_ids.causal_reason == \
            "legacy-bundle-trusted"


# ─── Causal lineage invariants ──────────────────────────────────


def test_forward_only_invariant_new_action_id(alice_bob, intake_ids):
    """Verify+fork ALWAYS produces a new action_id."""
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.causal_ids.action_id != intake_ids.action_id
        assert result.causal_ids.parent_action_id == \
            intake_ids.action_id


def test_generation_monotonic(alice_bob, intake_ids):
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.causal_ids.generation == \
            intake_ids.generation + 1


def test_continuity_id_inherited(alice_bob, intake_ids):
    """continuity_id binds the whole intake-cycle together."""
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.causal_ids.continuity_id == \
            intake_ids.continuity_id


def test_object_id_minted_for_fork_disposition(alice_bob, intake_ids):
    """trusted-fork & triage-fork get a NEW object_id."""
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.causal_ids.object_id != intake_ids.object_id
        assert result.causal_ids.parent_object_id == \
            intake_ids.object_id


def test_object_id_inherited_for_reject(alice_bob, intake_ids):
    """reject-invalid keeps intake object_id (no new object created)."""
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)
        bundle.write_bytes(bundle.read_bytes()[:-1] + b"\xff")

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.disposition == "reject-invalid"
        assert result.causal_ids.object_id == intake_ids.object_id


def test_surface_hash_chain_prev_link(alice_bob, intake_ids):
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.causal_ids.prev_surface_hash == \
            intake_ids.surface_hash
        assert result.causal_ids.surface_hash is not None
        assert result.causal_ids.surface_hash != \
            intake_ids.surface_hash


def test_trust_verdict_id_filled_in_v021(alice_bob, intake_ids):
    """v0.2.1: trust_verdict_id is now populated by trust-kernel hook.

    (v0.2 emitted None as placeholder. v0.2.1 fills it with a
     deterministic tv_<16-hex> id from query_trust_kernel.)
    """
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
        )

        assert result.causal_ids.trust_verdict_id is not None
        assert result.causal_ids.trust_verdict_id.startswith("tv_")


def test_trust_verdict_id_null_when_hook_disabled(alice_bob, intake_ids):
    """apply_trust_kernel=False reverts to v0.2 behavior (null)."""
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bundle = _make_sealed_bundle(tmp, alice, bob)

        result = verify_and_fork(
            bundle, actor_id="jis:test:host",
            intake_causal_ids=intake_ids,
            apply_trust_kernel=False,
        )

        assert result.causal_ids.trust_verdict_id is None
