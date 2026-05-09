"""Tests for v0.3.0 Seal stage + atomic-transfer convention."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

_TIBET_DROP = Path("/srv/jtel-stack/sandbox/airdrop-cli/src")
if str(_TIBET_DROP) not in sys.path:
    sys.path.insert(0, str(_TIBET_DROP))
_PKG = Path("/srv/jtel-stack/packages/tibet-continuityd/src")
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from tibet_drop.bundle import inspect_bundle, verify_bundle  # noqa: E402
from tibet_drop.crypto import IdentityKey  # noqa: E402

from tibet_continuityd.seal import SealEngine, SealResult  # noqa: E402
from tibet_continuityd.sniff import (  # noqa: E402
    IntakeClass,
    sniff_payload,
)
from tibet_continuityd.verify_fork import (  # noqa: E402
    CausalIDs,
    mint_action_id,
    mint_continuity_id,
    mint_object_id,
)


# ─── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def alice_bob():
    return IdentityKey.generate(), IdentityKey.generate()


@pytest.fixture
def prior_ids():
    """Mock causal IDs from a prior verify-fork stage."""
    return CausalIDs(
        actor_id="jis:humotica:test",
        action_id=mint_action_id(),
        object_id=mint_object_id(),
        continuity_id=mint_continuity_id(),
        generation=1,
        causal_reason="trusted-materialization",
        parent_action_id=mint_action_id(),
        parent_object_id=mint_object_id(),
        surface_hash="sha256:" + "a" * 64,
        prev_surface_hash=None,
        trust_verdict_id="tv_test_verdict",
    )


# ─── Sniff: staging-suffix recognition ──────────────────────────


@pytest.mark.parametrize("ext", ["part", "tmp", "writing", "inflight"])
def test_staging_suffix_recognized(tmp_path, ext):
    """Files with staging suffix should be classified STAGING
    with disposition 'ignore' so daemon waits for the atomic mv."""
    p = tmp_path / f"in-flight-bundle.{ext}"
    p.write_bytes(b"\x54\x42\x5A" + b"\x00" * 100)  # even with TBZ magic
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.STAGING
    assert r.disposition_hint == "ignore"


def test_normal_extension_unaffected(tmp_path):
    """Sealed-tbz arrival with .tza extension still works."""
    p = tmp_path / "normal.tza"
    p.write_bytes(b"\x54\x42\x5A\x01" + b"\x00" * 100)
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.SEALED_TBZ


# ─── SealEngine basics ─────────────────────────────────────────


def test_seal_writes_to_outbox(alice_bob, prior_ids, tmp_path):
    alice, bob = alice_bob
    outbox = tmp_path / "outbox"
    staging = tmp_path / "staging"

    engine = SealEngine(
        signer=alice,
        actor_id="jis:humotica:test",
        outbox=outbox,
        staging=staging,
    )

    blocks = [("payload.json", b'{"resealed": true}')]
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=blocks,
    )

    assert result.sealed_path.exists()
    assert result.sealed_path.parent == outbox
    assert result.bytes_written > 0


def test_seal_no_part_files_left_in_staging(
    alice_bob, prior_ids, tmp_path
):
    """After successful seal, staging directory has NO .part files."""
    alice, bob = alice_bob
    outbox = tmp_path / "outbox"
    staging = tmp_path / "staging"

    engine = SealEngine(
        signer=alice,
        actor_id="jis:humotica:test",
        outbox=outbox,
        staging=staging,
    )

    engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=[("p.txt", b"data")],
    )

    part_files = list(staging.glob("*.part"))
    assert len(part_files) == 0


def test_seal_creates_valid_tbz(alice_bob, prior_ids, tmp_path):
    """Sealed bundle is verifiable via verify_bundle()."""
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice,
        actor_id="jis:humotica:test",
        outbox=tmp_path / "outbox",
        staging=tmp_path / "staging",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=[("p.txt", b"data")],
    )

    valid, manifest, errors = verify_bundle(result.sealed_path)
    assert valid, f"sealed bundle should verify: {errors}"
    assert manifest["sender_aint"] == "alice.aint"
    assert manifest["receiver_aint"] == "bob.aint"


def test_seal_filename_follows_ssm_convention(
    alice_bob, prior_ids, tmp_path
):
    """Sealed filename = <date>.<context>.<profile>.<priority>.tza"""
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice,
        actor_id="jis:humotica:test",
        outbox=tmp_path / "outbox",
        staging=tmp_path / "staging",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        surface_time_fragment="2026-05-09",
        surface_context="resealed-test",
        surface_profile="claude",
        surface_priority="urgent",
        blocks=[("p.txt", b"data")],
    )

    assert result.sealed_path.name == \
        "2026-05-09.resealed-test.claude.urgent.tza"


def test_seal_manifest_has_surface_fields(
    alice_bob, prior_ids, tmp_path
):
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice,
        actor_id="jis:humotica:test",
        outbox=tmp_path / "outbox",
        staging=tmp_path / "staging",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        surface_time_fragment="2026-05-09",
        surface_context="seal-test",
        surface_profile="claude",
        surface_priority="normal",
        blocks=[("p.txt", b"data")],
    )

    manifest = inspect_bundle(result.sealed_path)
    assert manifest["surface_time_fragment"] == "2026-05-09"
    assert manifest["surface_context"] == "seal-test"
    assert manifest["surface_profile"] == "claude"
    assert manifest["surface_priority"] == "normal"


# ─── Causal lineage chain ──────────────────────────────────────


def test_seal_chains_forward_from_verify_fork(
    alice_bob, prior_ids, tmp_path
):
    """Seal's action_id != prior, generation +1, parent links set."""
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice,
        actor_id="jis:humotica:test",
        outbox=tmp_path / "outbox",
        staging=tmp_path / "staging",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=[("p.txt", b"data")],
    )

    assert result.causal_ids.action_id != prior_ids.action_id
    assert result.causal_ids.parent_action_id == prior_ids.action_id
    assert result.causal_ids.generation == prior_ids.generation + 1


def test_seal_inherits_continuity_id(alice_bob, prior_ids, tmp_path):
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice, actor_id="jis:test",
        outbox=tmp_path / "o", staging=tmp_path / "s",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=[("p.txt", b"data")],
    )
    assert result.causal_ids.continuity_id == prior_ids.continuity_id


def test_seal_keeps_same_object_id(alice_bob, prior_ids, tmp_path):
    """Seal acts on the SAME object — object_id is inherited,
    not minted fresh. (Different from fork, which mints new)."""
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice, actor_id="jis:test",
        outbox=tmp_path / "o", staging=tmp_path / "s",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=[("p.txt", b"data")],
    )
    assert result.causal_ids.object_id == prior_ids.object_id


def test_seal_propagates_trust_verdict_id(
    alice_bob, prior_ids, tmp_path
):
    """trust_verdict_id from verify-fork stage carried forward."""
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice, actor_id="jis:test",
        outbox=tmp_path / "o", staging=tmp_path / "s",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=[("p.txt", b"data")],
    )
    assert result.causal_ids.trust_verdict_id == \
        prior_ids.trust_verdict_id


def test_seal_default_causal_reason(alice_bob, prior_ids, tmp_path):
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice, actor_id="jis:test",
        outbox=tmp_path / "o", staging=tmp_path / "s",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=[("p.txt", b"data")],
    )
    assert result.causal_ids.causal_reason == "trusted-resealed"


def test_seal_custom_causal_reason(alice_bob, prior_ids, tmp_path):
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice, actor_id="jis:test",
        outbox=tmp_path / "o", staging=tmp_path / "s",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=[("p.txt", b"data")],
        causal_reason="triage-quarantine-snapshot",
    )
    assert result.causal_ids.causal_reason == \
        "triage-quarantine-snapshot"


def test_seal_duration_recorded(alice_bob, prior_ids, tmp_path):
    alice, bob = alice_bob
    engine = SealEngine(
        signer=alice, actor_id="jis:test",
        outbox=tmp_path / "o", staging=tmp_path / "s",
    )
    result = engine.reseal(
        prior_causal_ids=prior_ids,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        sender_aint="alice.aint",
        blocks=[("p.txt", b"data")],
    )
    assert result.duration_ms > 0
    assert result.duration_ms < 5000  # sanity: under 5s
