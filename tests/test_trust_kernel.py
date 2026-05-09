"""Tests for trust-kernel zone-policy decision layer (v0.2.1)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PKG = Path("/srv/jtel-stack/packages/tibet-continuityd/src")
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from tibet_continuityd.trust_kernel import (  # noqa: E402
    EMBEDDED_DEFAULT_POLICIES,
    TrustQuery,
    TrustVerdict,
    _reset_cache,
    apply_verdict_to_disposition,
    load_policies,
    query_trust_kernel,
)


@pytest.fixture(autouse=True)
def reset_cache_before_each():
    _reset_cache()


# ─── Embedded policy loads ──────────────────────────────────────


def test_embedded_default_loads():
    pol, src = load_policies(path=Path("/nonexistent/path.toml"))
    assert src == "embedded"
    assert "zone" in pol
    assert "inbox" in pol["zone"]


def test_toml_override_loads(tmp_path):
    custom = tmp_path / "custom.toml"
    custom.write_text("""
[zone."special"]
description = "Custom test zone"
allow = ["sealed-tbz"]
triage = []
reseal = []
deny = ["json-text", "executable"]
""")
    pol, src = load_policies(path=custom)
    assert src == f"toml:{custom}"
    assert "special" in pol["zone"]


# ─── inbox-zone defaults ────────────────────────────────────────


def test_inbox_sealed_tbz_allow():
    v = query_trust_kernel(TrustQuery(
        intake_class="sealed-tbz",
        zone_name="inbox",
        actor_id="jis:test",
        object_id="obj_test",
    ))
    assert v.verdict == "ALLOW"
    assert v.verdict_id.startswith("tv_")


def test_inbox_disguised_triage():
    v = query_trust_kernel(TrustQuery(
        intake_class="disguised",
        zone_name="inbox",
        actor_id="jis:test",
        object_id="obj_test",
    ))
    assert v.verdict == "TRIAGE"


def test_inbox_executable_deny():
    v = query_trust_kernel(TrustQuery(
        intake_class="executable",
        zone_name="inbox",
        actor_id="jis:test",
        object_id="obj_test",
    ))
    assert v.verdict == "DENY"


def test_inbox_json_reseal():
    v = query_trust_kernel(TrustQuery(
        intake_class="json-text",
        zone_name="inbox",
        actor_id="jis:test",
        object_id="obj_test",
    ))
    assert v.verdict == "RESEAL"


# ─── triage-zone is permissive ─────────────────────────────────


def test_triage_zone_allows_disguised():
    v = query_trust_kernel(TrustQuery(
        intake_class="disguised",
        zone_name="triage",
        actor_id="jis:test",
        object_id="obj_test",
    ))
    assert v.verdict == "ALLOW"


# ─── unknown zone fail-safe ─────────────────────────────────────


def test_unknown_zone_defaults_triage():
    v = query_trust_kernel(TrustQuery(
        intake_class="sealed-tbz",
        zone_name="some-random-zone",
        actor_id="jis:test",
        object_id="obj_test",
    ))
    assert v.verdict == "TRIAGE"
    assert "not in policy table" in v.reason


def test_undeclared_intake_class_defaults_triage():
    v = query_trust_kernel(TrustQuery(
        intake_class="some-future-class",
        zone_name="inbox",
        actor_id="jis:test",
        object_id="obj_test",
    ))
    assert v.verdict == "TRIAGE"
    assert "not declared" in v.reason


# ─── verdict_id determinism ─────────────────────────────────────


def test_verdict_id_deterministic():
    q = TrustQuery(
        intake_class="sealed-tbz",
        zone_name="inbox",
        actor_id="jis:test",
        object_id="obj_test",
    )
    v1 = query_trust_kernel(q)
    v2 = query_trust_kernel(q)
    assert v1.verdict_id == v2.verdict_id


def test_verdict_id_changes_on_intake_class():
    base = TrustQuery(
        intake_class="sealed-tbz",
        zone_name="inbox",
        actor_id="jis:test",
        object_id="obj_test",
    )
    other = TrustQuery(
        intake_class="disguised",
        zone_name="inbox",
        actor_id="jis:test",
        object_id="obj_test",
    )
    assert query_trust_kernel(base).verdict_id != \
           query_trust_kernel(other).verdict_id


# ─── apply_verdict_to_disposition merging ───────────────────────


def _verdict(v: str) -> TrustVerdict:
    return TrustVerdict(
        verdict=v,
        verdict_id=f"tv_test_{v.lower()}",
        zone_name="inbox",
        intake_class="sealed-tbz",
        reason="test",
        policy_source="embedded",
    )


def test_allow_keeps_disposition():
    out, _ = apply_verdict_to_disposition("trusted-fork", _verdict("ALLOW"))
    assert out == "trusted-fork"


def test_deny_overrides_to_reject_by_policy():
    out, reason = apply_verdict_to_disposition(
        "trusted-fork", _verdict("DENY")
    )
    assert out == "reject-by-policy"
    assert "DENY" in reason


def test_reseal_overrides_to_reseal_required():
    out, _ = apply_verdict_to_disposition(
        "trusted-fork", _verdict("RESEAL")
    )
    assert out == "reseal-required"


def test_triage_downgrades_trusted_to_triage():
    out, _ = apply_verdict_to_disposition(
        "trusted-fork", _verdict("TRIAGE")
    )
    assert out == "triage-fork"


def test_triage_idempotent_on_already_triage():
    out, _ = apply_verdict_to_disposition(
        "triage-fork", _verdict("TRIAGE")
    )
    assert out == "triage-fork"


def test_reject_invalid_immune_to_policy():
    """Crypto failure is harder signal than policy."""
    for verdict_str in ("ALLOW", "DENY", "RESEAL", "TRIAGE"):
        out, reason = apply_verdict_to_disposition(
            "reject-invalid", _verdict(verdict_str)
        )
        assert out == "reject-invalid", \
            f"reject-invalid was overridden by {verdict_str}"
