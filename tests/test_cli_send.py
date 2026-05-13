"""Regression tests for CLI send/ack delivery routing."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PKG = Path("/srv/jtel-stack/packages/tibet-continuityd/src")
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from tibet_continuityd import cli  # noqa: E402


def test_cmd_send_same_host_jis_target_delivers_locally(
    tmp_path, monkeypatch
):
    """Same-host JIS targets must short-circuit before SCP."""
    src = tmp_path / "payload.json"
    src.write_text('{"hello":"world"}', encoding="utf-8")

    inbox = tmp_path / "inbox"
    identity = tmp_path / "identity"

    def fake_pack_in_process(**kwargs):
        kwargs["bundle_out"].write_bytes(b"fake-sealed-bundle")
        return None

    def fake_resolve_jis_did(_did: str):
        return f"root@JTel-brain:{inbox}", "JTel-brain", str(inbox)

    def fail_if_scp_called(*_args, **_kwargs):
        raise AssertionError("subprocess.run must not be called")

    monkeypatch.setattr(cli, "_pack_in_process", fake_pack_in_process)
    monkeypatch.setattr(cli, "_resolve_jis_did", fake_resolve_jis_did)
    monkeypatch.setattr(cli, "_is_same_host", lambda host: host == "JTel-brain")
    monkeypatch.setattr(cli.subprocess, "run", fail_if_scp_called)

    args = argparse.Namespace(
        file=str(src),
        to="jis:humotica:continuityd@JTel-brain",
        identity=str(identity),
        receiver_aint=None,
        receiver_pubkey=None,
        surface_time="2026-05-13",
        surface_context="ack-of-tpingroundtr",
        surface_profile="claude",
        surface_priority="background",
        transport="scp",
        no_ains=True,
        no_http_auth=False,
        min_trust=0.0,
        dry_run=False,
        verbose=False,
        mux_server=None,
        mux_target=None,
        mux_intent=None,
        mux_agent=None,
        mux_keep_open=False,
    )

    rc = cli._cmd_send(args)
    assert rc == 0

    final = inbox / "2026-05-13.ack-of-tpingroundtr.claude.background.tza"
    assert final.exists()
    assert final.read_bytes() == b"fake-sealed-bundle"
    assert not (inbox / (final.name + ".part")).exists()
