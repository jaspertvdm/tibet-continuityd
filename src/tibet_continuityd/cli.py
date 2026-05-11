"""
CLI entry-point for tibet-continuityd with subcommands.

  tcd run             # daemon mode (default — backwards-compat)
  tcd send FILE --to HOST:PATH
                      # push-mode: pack + scp to peer inbox
  tcd send FILE --to jis:org:service@host
                      # push-mode: identity-bound routing (v0.5.1+)

Without subcommand, defaults to `run` (= existing v0.4.x behavior).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Tuple


_DEFAULT_AINS_API = "https://brein.jaspervandemeent.nl/api/ains/resolve"


def _compute_http_auth_header(
    identity_dir: Path, body_bytes: bytes
) -> Optional[str]:
    """Sign (sha256(body) + timestamp) with identity for HTTP auth.

    Returns Authorization header value, or None if signing fails
    (= tibet-drop unavailable, identity dir invalid, etc.).

    Header format (v1):
        TIBET-SIG-V1 <pubkey-hex>:<iso-timestamp>:<sig-hex>
    """
    try:
        from tibet_drop.crypto import sha256, IdentityKey  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        return None
    try:
        priv_bytes = (identity_dir / "identity.priv").read_bytes()
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signer = IdentityKey(priv=priv, pub=priv.public_key())
    except Exception:
        return None

    timestamp_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    body_hash = sha256(body_bytes)
    msg = body_hash + timestamp_iso.encode("utf-8")
    sig = signer.sign(msg)
    pubkey_hex = signer.pub_bytes().hex()
    sig_hex = sig.hex()
    # Separator '|' to avoid collision with ':' in timestamp_iso.
    return f"TIBET-SIG-V1 {pubkey_hex}|{timestamp_iso}|{sig_hex}"


def _ains_lookup(name: str, timeout: float = 3.0) -> Optional[dict]:
    """Look up a name via the AINS resolve API.

    Returns the AINS record dict (`{"status", "domain", "record", ...}`)
    on success, or None if the API is unavailable / no record exists.

    Configurable via:
        TIBET_AINS_API_URL    (default: brein.jaspervandemeent.nl)
        TIBET_AINS_API_TIMEOUT (default: 3.0 seconds)
    """
    api_url = os.environ.get("TIBET_AINS_API_URL", _DEFAULT_AINS_API)
    try:
        timeout = float(os.environ.get(
            "TIBET_AINS_API_TIMEOUT", str(timeout)))
    except ValueError:
        pass
    url = f"{api_url.rstrip('/')}/{name}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") != "found":
                return None
            return data
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, TimeoutError, OSError):
        return None


def _resolve_jis_did(did: str) -> Tuple[str, str, str]:
    """Resolve `jis:org:service@host` → (ssh_target, host, inbox_path).

    Phase B convention-based parsing (v0.5.1).

    Format: `jis:<org>:<service>@<host>`
    Returns: ("root@<host>:<inbox>", "<host>", "<inbox>")

    Defaults:
        ssh user: from TIBET_AINS_SSH_USER env-var, else "root"
        inbox:   from TIBET_AINS_DEFAULT_INBOX env-var,
                 else "/var/lib/tibet/inbox"

    Phase C (v0.5.2) will add AINS-API lookup for richer resolution
    (= per-DID inbox path, public-key, transport-preference).
    """
    if not did.startswith("jis:"):
        raise ValueError(
            f"Not a JIS DID (must start with 'jis:'): {did}"
        )
    after_jis = did[4:]  # e.g. "humotica:continuityd@p520"
    if "@" not in after_jis:
        raise ValueError(
            f"JIS DID missing '@host' suffix: {did}"
        )
    spec, host = after_jis.rsplit("@", 1)
    if not host:
        raise ValueError(f"Empty host in JIS DID: {did}")

    ssh_user = os.environ.get("TIBET_AINS_SSH_USER", "root")
    inbox = os.environ.get(
        "TIBET_AINS_DEFAULT_INBOX",
        "/var/lib/tibet/inbox",
    )
    ssh_target = f"{ssh_user}@{host}:{inbox}"
    return ssh_target, host, inbox


def _resolve_jis_to_url(did: str, default_port: int = 8443) -> Tuple[str, str]:
    """Resolve `jis:org:service@host` → (url, host) for HTTP transport.

    Phase C step 4 (v0.5.7): identity-bound URL routing.

    Format: `jis:<org>:<service>@<host>` (= same DID format)
    Returns: ("http://<host>:<port>", "<host>")

    Defaults:
        port: from TIBET_HTTP_PORT env-var, else 8443
    """
    if not did.startswith("jis:"):
        raise ValueError(
            f"Not a JIS DID (must start with 'jis:'): {did}"
        )
    after_jis = did[4:]
    if "@" not in after_jis:
        raise ValueError(
            f"JIS DID missing '@host' suffix: {did}"
        )
    _spec, host = after_jis.rsplit("@", 1)
    if not host:
        raise ValueError(f"Empty host in JIS DID: {did}")
    try:
        port = int(os.environ.get("TIBET_HTTP_PORT", str(default_port)))
    except ValueError:
        port = default_port
    url = f"http://{host}:{port}"
    return url, host


def _cmd_run(args: argparse.Namespace) -> int:
    """Subcommand: run daemon (= existing v0.4 behavior)."""
    from tibet_continuityd.daemon import main as daemon_main
    return daemon_main()


def _cmd_mux_consumer(args: argparse.Namespace) -> int:
    """Subcommand: poll tibet-mux server for incoming frames and
    materialize them as files in the local inbox.

    Phase E step 2 (v0.6.1): mux receiver-side bridge.

    Loop:
        1. GET /api/mux/channels?agent=<me>
        2. For each channel where target matches and intent matches,
           GET /api/mux/channel/{id} → recent_frames
        3. For each frame not yet seen (track via channel_id + seq):
           a. Decode payload (expects {bundle_b64, name, size_bytes}).
           b. Write inbox/<name>.part atomically, then rename.
        4. Sleep --interval seconds; repeat until --duration elapsed
           or Ctrl-C.

    The continuityd daemon (running separately, watching this inbox)
    will pick up the new file via inotify and run its
    Watch/Sniff/Verify/Seal pipeline as for any other arrival.
    """
    try:
        from tibet_mux.client import MuxClient  # type: ignore
    except ImportError:
        print(
            "ERROR: tcd mux-consumer requires tibet-mux.\n"
            "  pip install tibet-continuityd[mux]",
            file=sys.stderr,
        )
        return 1

    import base64 as _b64
    import time as _time

    server = args.server or os.environ.get(
        "TIBET_MUX_SERVER", "http://localhost:8000"
    )
    agent = args.agent
    intent_filter = args.intent or "continuityd:inbox"
    inbox = Path(args.inbox).resolve()
    inbox.mkdir(parents=True, exist_ok=True)

    client = MuxClient(server, agent)

    print(
        f"tcd mux-consumer listening on {server} "
        f"as agent={agent} intent={intent_filter}"
    )
    print(f"  inbox:    {inbox}")
    print(f"  interval: {args.interval}s")
    print(f"  duration: {args.duration}s (0 = forever)")
    print(f"  ctrl-c to stop")
    print()

    seen: set = set()  # (channel_id, seq) pairs
    received = 0
    start = _time.monotonic()
    rc = 0
    try:
        while True:
            if args.duration and (
                _time.monotonic() - start >= args.duration
            ):
                break
            try:
                # v0.6.1: use /by-target endpoint (tibet-mux v1.0.1+)
                # because core mux indexes _agent_channels by SENDER,
                # so calling client.channels(agent=us) as the receiver
                # returns nothing. /by-target?target=us iterates all
                # channels in core._channels and filters by ch.target.
                import urllib.request as _ureq
                import urllib.parse as _uparse
                import json as _json
                q = _uparse.urlencode({
                    "target": agent,
                    "intent": intent_filter or "",
                    "include_closed": "true",
                })
                url = (
                    server.rstrip("/")
                    + "/api/mux/by-target?" + q
                )
                with _ureq.urlopen(url, timeout=3.0) as resp:
                    chans_resp = _json.loads(
                        resp.read().decode("utf-8")
                    )
                chans = chans_resp.get("channels", []) or []
            except Exception as e:
                if args.verbose:
                    print(f"  poll error: {e}")
                _time.sleep(args.interval)
                continue

            for c in chans:
                ch_id = c.get("id") or c.get("channel_id")
                if not ch_id:
                    continue
                if intent_filter and c.get("intent") != intent_filter:
                    continue
                # /by-target already filters by target — extra guard
                if c.get("target") and c.get("target") != agent.lower():
                    continue
                try:
                    detail = client.channel(ch_id)
                except Exception as e:
                    if args.verbose:
                        print(f"  channel-fetch error {ch_id}: {e}")
                    continue
                frames = detail.get("recent_frames", []) or []
                for frame in frames:
                    seq = frame.get("seq")
                    key = (ch_id, seq)
                    if key in seen:
                        continue
                    seen.add(key)
                    payload = frame.get("payload") or {}
                    if not isinstance(payload, dict):
                        continue
                    name = payload.get("name")
                    body_b64 = payload.get("bundle_b64")
                    if not name or not body_b64:
                        continue
                    try:
                        body = _b64.b64decode(body_b64)
                    except Exception:
                        continue
                    # Path safety
                    if "/" in name or "\\" in name or ".." in name:
                        if args.verbose:
                            print(f"  reject unsafe name: {name}")
                        continue
                    part = inbox / (name + ".part")
                    final = inbox / name
                    part.write_bytes(body)
                    part.rename(final)
                    received += 1
                    print(
                        f"✓ materialized: name={name} "
                        f"size={len(body)} channel={ch_id} seq={seq}"
                    )
                    # Close channel after successful materialize.
                    try:
                        client.close(
                            ch_id, reason="consumer_received"
                        )
                    except Exception as e:
                        if args.verbose:
                            print(
                                f"  warn: close({ch_id}) failed: {e}"
                            )
                    if args.count and received >= args.count:
                        break
                if args.count and received >= args.count:
                    break
            if args.count and received >= args.count:
                break
            _time.sleep(args.interval)
    except KeyboardInterrupt:
        print("(aborted by user)")
        rc = 130

    print(f"tcd mux-consumer done. received={received}")
    return rc


def _cmd_recv(args: argparse.Namespace) -> int:
    """Subcommand: ephemeral HTTP listener for one or more arrivals.

    Phase D step 2 (v0.5.9): bidirectional roundtrip primitive.

    Spawns an InboxHTTPServer in the foreground for N seconds (or
    until --count arrivals received). Prints a JSON summary line
    per arrival. Useful from a laptop/smartphone-grade host that
    wants to receive ONE ACK without running a permanent daemon.

    Note: auth verification follows the same rules as the daemon
    (TIBET_HTTP_REQUIRE_AUTH, TIBET_HTTP_REQUIRE_AINS_PIN env-vars
    apply).
    """
    import json as _json
    import time as _time
    from tibet_continuityd import __version__ as _ver
    from tibet_continuityd.inbox_http import InboxHTTPServer

    if args.inbox:
        inbox_dir = Path(args.inbox).resolve()
        inbox_dir.mkdir(parents=True, exist_ok=True)
        ephemeral_dir = False
    else:
        inbox_dir = Path(tempfile.mkdtemp(prefix="tcd-recv-"))
        ephemeral_dir = True

    print(
        f"tcd recv v{_ver} listening on "
        f"http://{args.host}:{args.port}/inbox/"
    )
    print(f"  inbox:   {inbox_dir}")
    print(f"  wait:    {args.wait}s")
    print(f"  count:   {args.count}")
    print(f"  ctrl-c to abort")
    print()

    server = InboxHTTPServer(
        inbox_dir=inbox_dir,
        port=args.port,
        host=args.host,
        version=_ver,
    )
    server.start()

    deadline = _time.monotonic() + args.wait
    seen: set = set()
    received_count = 0
    rc = 0
    try:
        while _time.monotonic() < deadline:
            files = sorted(inbox_dir.glob("*.tza"))
            for f in files:
                if f.name in seen:
                    continue
                seen.add(f.name)
                received_count += 1
                summary = {
                    "name": f.name,
                    "size_bytes": f.stat().st_size,
                    "received_at": _time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", _time.gmtime()
                    ),
                }
                print(f"✓ received: {_json.dumps(summary)}")
                if received_count >= args.count:
                    break
            if received_count >= args.count:
                break
            _time.sleep(0.5)
        if received_count == 0:
            print(f"(no arrivals in {args.wait}s window)")
            rc = 2
    except KeyboardInterrupt:
        print("(aborted by user)")
        rc = 130
    finally:
        server.stop()
        if ephemeral_dir and not args.keep_inbox:
            shutil.rmtree(inbox_dir, ignore_errors=True)

    return rc


def _cmd_ack(args: argparse.Namespace) -> int:
    """Subcommand: send a signed ACK bundle referencing a prior event.

    Phase D step 1 (v0.5.8): reply-loop primitive.

    Flow:
        1. Build a tiny ACK payload referencing the prior bundle's
           name / object_id and the acking actor's identity.
        2. Pack as a sealed TBZ via tibet-drop (= same as send).
        3. Filename follows SSM convention:
              <date>.ack-of-<shortid>.<profile>.<priority>.tza
        4. Delivery reuses tcd send (= scp or http transport).

    The ACK is a normal sealed envelope; the receiver's sniff
    stage will pick it up like any other arrival. The
    parent-reference lives in the payload JSON for now;
    future v0.6+ will write a real `parent_action_id` into
    the manifest itself.
    """
    src_name = args.ref  # name of the bundle being acked
    short_id = "".join(c for c in src_name if c.isalnum())[:12]
    if not short_id:
        short_id = "unknown"

    surface_time = args.surface_time or time.strftime("%Y-%m-%d")
    surface_profile = args.surface_profile or "claude"
    # ACK is low-priority by SSM-convention; "background" is the
    # sandbox tibet-drop enum value for "non-urgent ambient signal".
    surface_priority = args.surface_priority or "background"
    surface_context = f"ack-of-{short_id}"

    payload = {
        "kind": "ack",
        "version": "v0.5.8",
        "referenced": src_name,
        "ack_timestamp_iso": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        ),
        "ack_note": args.note or "",
    }
    with tempfile.NamedTemporaryFile(
        prefix="tcd-ack-", suffix=".json",
        mode="w", delete=False
    ) as f:
        import json as _json
        _json.dump(payload, f)
        ack_payload_path = f.name

    # Reuse _cmd_send with the ack payload + custom surface fields
    class _Synth:
        pass
    inner = _Synth()
    inner.file = ack_payload_path
    inner.to = args.to
    inner.identity = args.identity
    inner.receiver_aint = args.receiver_aint
    inner.receiver_pubkey = args.receiver_pubkey
    inner.surface_time = surface_time
    inner.surface_context = surface_context
    inner.surface_profile = surface_profile
    inner.surface_priority = surface_priority
    inner.transport = args.transport
    inner.no_ains = args.no_ains
    inner.no_http_auth = args.no_http_auth
    inner.min_trust = args.min_trust
    inner.dry_run = args.dry_run
    inner.verbose = args.verbose

    print(f"✓ ACK: {short_id} → {args.to}")
    return _cmd_send(inner)


def _cmd_send(args: argparse.Namespace) -> int:
    """Subcommand: pack a file as TBZ envelope and push to peer inbox.

    Phase A — host-to-host sealed handoff via SCP.

    Flow:
        1. Resolve identity (= --identity dir, or temp ad-hoc).
        2. Pack input via `python -m tibet_drop pack`.
        3. SCP the .tza bundle to <user>@<host>:<inbox-path>.
        4. Peer continuityd watcher picks it up + audit-emits.

    Identity-bound routing (Phase B) and tibet-mux:443 transport
    (Phase C) will follow as v0.5.1 / v0.5.2.
    """
    src = Path(args.file).resolve()
    if not src.exists():
        print(f"ERROR: source not found: {src}", file=sys.stderr)
        return 1

    # Resolve target: JIS DID (v0.5.1+) or direct host:path (v0.5.0)
    target = args.to
    resolved_host = None
    # v0.5.7: JIS DID with HTTP transport → URL form
    if target.startswith("jis:") and args.transport == "http":
        try:
            target, resolved_host = _resolve_jis_to_url(target)
            print(f"✓ resolved {args.to} → {target} (HTTP transport)")
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    elif target.startswith("jis:"):
        try:
            target, resolved_host, _inbox = _resolve_jis_did(target)
            print(f"✓ resolved {args.to} → {target}")
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

        # v0.5.2: optional AINS API identity verification.
        # Lookup the @<host> part as AINS name (e.g. "root_idd").
        # On hit: print trust_score + capabilities for transparency.
        # On miss or API down: continue silently (= graceful fallback).
        if not args.no_ains and resolved_host:
            ains = _ains_lookup(resolved_host)
            if ains:
                rec = ains.get("record", {})
                trust = rec.get("trust_score")
                caps = rec.get("capabilities") or []
                domain = ains.get("domain", resolved_host)
                print(
                    f"✓ AINS verified: domain={domain} "
                    f"trust={trust} caps={','.join(caps[:4])}"
                    + ("..." if len(caps) > 4 else "")
                )
                if trust is not None and trust < args.min_trust:
                    print(
                        f"ERROR: AINS trust_score {trust} below "
                        f"--min-trust {args.min_trust}",
                        file=sys.stderr,
                    )
                    return 1
            elif args.verbose:
                print(
                    f"  (AINS lookup for {resolved_host}: no record / "
                    f"API unavailable — continuing via convention)"
                )
    elif ":" not in target:
        print(
            "ERROR: --to must be one of:\n"
            "  <user@host>:<inbox-path>   (direct SCP)\n"
            "  <host>:<inbox-path>        (root user assumed)\n"
            "  jis:<org>:<service>@<host>  (identity-bound, v0.5.1+)",
            file=sys.stderr,
        )
        return 1

    # Default identity dir if not supplied (= ad-hoc per-send)
    identity_dir = args.identity
    if identity_dir is None:
        identity_dir = tempfile.mkdtemp(prefix="tcd-send-id-")

    # Default receiver pubkey (= dummy when not yet AINS-resolved)
    receiver_pubkey = args.receiver_pubkey or ("0" * 64)
    receiver_aint = args.receiver_aint or "self.aint"

    # Surface fields (= visible routing hints per SSM)
    surface_time = args.surface_time or time.strftime("%Y-%m-%d")
    surface_context = args.surface_context or "tcd-send"
    surface_profile = args.surface_profile or "claude"
    surface_priority = args.surface_priority or "normal"

    # Build the output bundle name following SSM convention:
    # <date>.<context>.<profile>.<priority>.tza
    bundle_name = (
        f"{surface_time}.{surface_context}.{surface_profile}"
        f".{surface_priority}.tza"
    )

    with tempfile.TemporaryDirectory(prefix="tcd-send-pack-") as tmp:
        bundle_out = Path(tmp) / bundle_name

        # Init identity if needed (idempotent)
        init_cmd = [
            sys.executable, "-m", "tibet_drop", "init",
            "--out", str(identity_dir),
            "--aint", "tcd.sender",
        ]
        rc = subprocess.run(init_cmd, capture_output=True)
        # init may fail if already exists; that's OK

        # Pack the source into a sealed .tza bundle.
        # Surface-args are sandbox-version-only; PyPI 0.1.0 doesn't
        # know them. Try with surface-args first; on
        # "unrecognized arguments" retry without. SSM-name on the
        # output path is preserved either way.
        pack_cmd_base = [
            sys.executable, "-m", "tibet_drop", "pack",
            "--identity", str(identity_dir),
            "--receiver-aint", receiver_aint,
            "--receiver-pubkey", receiver_pubkey,
            "--input", str(src),
            "--output", str(bundle_out),
        ]
        pack_cmd_with_surface = pack_cmd_base + [
            "--surface-time", surface_time,
            "--surface-context", surface_context,
            "--surface-profile", surface_profile,
            "--surface-priority", surface_priority,
        ]
        result = subprocess.run(
            pack_cmd_with_surface, capture_output=True, text=True
        )
        if result.returncode != 0 and "unrecognized arguments" in result.stderr:
            # Older tibet-drop on PyPI lacks surface-* flags.
            # Retry without; the SSM filename on --output is enough
            # for the receiver's sniff/SSM-routing stage.
            result = subprocess.run(
                pack_cmd_base, capture_output=True, text=True
            )
        if result.returncode != 0:
            print(
                f"ERROR: tibet_drop pack failed:\n{result.stderr}",
                file=sys.stderr,
            )
            return result.returncode

        print(f"✓ packed sealed envelope: {bundle_name}")

        if args.dry_run:
            print(
                f"[dry-run] would deliver {bundle_out} → {target}"
                f" via {args.transport}"
            )
            return 0

        # Choose transport
        if args.transport == "mux":
            # v0.6.0: route bundle via tibet-mux multiplexer.
            # Single port (= 443 in prod) carrying many intents.
            try:
                from tibet_mux.client import MuxClient  # type: ignore
            except ImportError:
                print(
                    "ERROR: --transport mux requires tibet-mux.\n"
                    "  pip install tibet-continuityd[mux]\n"
                    "  or:  pip install tibet-mux",
                    file=sys.stderr,
                )
                return 1
            mux_server = args.mux_server or os.environ.get(
                "TIBET_MUX_SERVER", "http://localhost:8000"
            )
            target_agent = args.mux_target or (
                resolved_host or "self"
            )
            intent = args.mux_intent or "continuityd:inbox"
            sender_agent = args.mux_agent or os.environ.get(
                "TIBET_MUX_AGENT", "tcd-sender"
            )
            with open(bundle_out, "rb") as f:
                body = f.read()
            import base64 as _b64
            payload = {
                "bundle_b64": _b64.b64encode(body).decode("ascii"),
                "name": bundle_name,
                "size_bytes": len(body),
            }
            try:
                client = MuxClient(mux_server, sender_agent)
                ch = client.open(
                    target=target_agent,
                    intent=intent,
                    metadata={"continuityd_version": "0.6.0"},
                )
                ch_id = ch.get("channel_id") or ch.get("id")
                if not ch_id:
                    print(
                        f"ERROR: mux.open returned no channel_id: {ch}",
                        file=sys.stderr,
                    )
                    return 1
                client.send(ch_id, payload)
                if args.mux_keep_open:
                    # v0.6.1: leave channel open so consumer can
                    # poll, fetch recent_frames, materialize, then
                    # close it themselves. Mux core.channels(agent)
                    # filters to state=='open' so a closed channel
                    # is invisible to the consumer.
                    print(
                        f"  (channel {ch_id} left OPEN for "
                        f"consumer to close on receipt)"
                    )
                else:
                    client.close(
                        ch_id, reason="continuityd_send_done"
                    )
            except Exception as e:
                print(
                    f"ERROR: mux transport failed: {e}",
                    file=sys.stderr,
                )
                return 1
            print(
                f"✓ delivered via mux to {mux_server} "
                f"intent={intent} target={target_agent} "
                f"channel={ch_id}"
            )
        elif args.transport == "http":
            # v0.5.3: HTTP POST to peer /inbox/<filename>.
            # Target format: http://host:port  (port 8443 typical)
            url_base = target.rstrip("/")
            if not (url_base.startswith("http://")
                    or url_base.startswith("https://")):
                # Convert <host>:<port> to http:// default
                url_base = f"http://{url_base}"
            url = f"{url_base}/inbox/{bundle_name}"
            try:
                with open(bundle_out, "rb") as f:
                    body = f.read()
                http_headers = {
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(len(body)),
                }
                # v0.5.4: sign request with same identity that signed
                # the TBZ bundle. Header proves "same actor that
                # packed this is delivering it RIGHT NOW".
                if not args.no_http_auth:
                    auth = _compute_http_auth_header(
                        Path(identity_dir), body
                    )
                    if auth:
                        http_headers["Authorization"] = auth
                        if args.verbose:
                            print(f"  signed HTTP request: {auth[:60]}...")
                # v0.5.5: send identity claim if --to was a JIS DID.
                # Daemon can AINS-lookup this claim and pin the
                # Authorization pubkey against record.public_key.
                if args.to.startswith("jis:"):
                    http_headers["X-TIBET-Sender-DID"] = args.to
                req = urllib.request.Request(
                    url,
                    data=body,
                    method="POST",
                    headers=http_headers,
                )
                timeout = float(os.environ.get(
                    "TIBET_HTTP_TIMEOUT", "10.0"
                ))
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = resp.status
                    resp_body = resp.read().decode("utf-8", errors="replace")
                if status not in (200, 201):
                    print(
                        f"ERROR: HTTP {status}: {resp_body}",
                        file=sys.stderr,
                    )
                    return 1
                if args.verbose:
                    print(f"  HTTP {status}: {resp_body.strip()}")
            except (urllib.error.URLError, urllib.error.HTTPError,
                    OSError) as e:
                print(f"ERROR: HTTP delivery failed: {e}", file=sys.stderr)
                return 1
            print(f"✓ delivered via HTTP to {url}")
        else:
            # Default: SCP transport (= v0.5.0/0.5.1/0.5.2 path)
            scp_cmd = ["scp", str(bundle_out), f"{target}/"]
            if args.verbose:
                scp_cmd.insert(1, "-v")
            result = subprocess.run(
                scp_cmd, capture_output=True, text=True
            )
            if result.returncode != 0:
                print(
                    f"ERROR: scp failed:\n{result.stderr}",
                    file=sys.stderr,
                )
                return result.returncode
            print(f"✓ delivered to {target}/{bundle_name}")

        print(
            f"  peer continuityd will sniff + verify + seal "
            f"on arrival"
        )

    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Top-level CLI dispatcher."""
    parser = argparse.ArgumentParser(
        prog="tcd",
        description=(
            "tibet-continuityd — Distributed Continuity OS daemon. "
            "Without subcommand, runs in daemon mode."
        ),
    )
    sub = parser.add_subparsers(dest="cmd")

    # `tcd run` — explicit daemon mode
    p_run = sub.add_parser(
        "run",
        help="Run the continuity guardian daemon (default)",
    )
    p_run.set_defaults(func=_cmd_run)

    # `tcd send FILE --to HOST:PATH`
    p_send = sub.add_parser(
        "send",
        help="Pack a file as TBZ envelope and push to peer inbox",
    )
    p_send.add_argument(
        "file",
        help="Path to file or directory to pack and send",
    )
    p_send.add_argument(
        "--to",
        required=True,
        help=(
            "Target: <user@host>:<inbox-path> "
            "(SCP-style). For example: "
            "root@192.168.4.85:/var/lib/tibet/inbox"
        ),
    )
    p_send.add_argument(
        "--identity",
        default=None,
        help="JIS identity directory (default: ad-hoc temp)",
    )
    p_send.add_argument(
        "--receiver-aint",
        default=None,
        help="Receiver AINS handle (default: self.aint)",
    )
    p_send.add_argument(
        "--receiver-pubkey",
        default=None,
        help="Receiver Ed25519 pubkey hex (default: 64 zeros)",
    )
    p_send.add_argument(
        "--surface-time",
        default=None,
        help="Visible surface time (default: today YYYY-MM-DD)",
    )
    p_send.add_argument(
        "--surface-context",
        default=None,
        help="Visible surface context (default: tcd-send)",
    )
    p_send.add_argument(
        "--surface-profile",
        default=None,
        help="Visible surface profile (default: claude)",
    )
    p_send.add_argument(
        "--surface-priority",
        default=None,
        help="Visible surface priority (default: normal)",
    )
    p_send.add_argument(
        "--transport",
        choices=("scp", "http", "mux"),
        default="scp",
        help=(
            "Transport: 'scp' (SSH/22), 'http' (POST to peer /inbox), "
            "or 'mux' (tibet-mux multiplexer, single-port). v0.6+"
        ),
    )
    p_send.add_argument(
        "--mux-server",
        default=None,
        help="tibet-mux base URL (default: TIBET_MUX_SERVER env or "
             "http://localhost:8000)",
    )
    p_send.add_argument(
        "--mux-target",
        default=None,
        help="Target agent name for mux channel (default: host from "
             "JIS DID, else 'self')",
    )
    p_send.add_argument(
        "--mux-intent",
        default=None,
        help="Mux intent (default: continuityd:inbox)",
    )
    p_send.add_argument(
        "--mux-agent",
        default=None,
        help="Sender agent name (default: TIBET_MUX_AGENT env or "
             "'tcd-sender')",
    )
    p_send.add_argument(
        "--mux-keep-open",
        action="store_true",
        help=(
            "v0.6.1+ leave mux channel open after send so a "
            "polling consumer (= tcd mux-consumer) can see + "
            "materialize the frame, then close it themselves. "
            "Required for end-to-end mux delivery."
        ),
    )
    p_send.add_argument(
        "--no-ains",
        action="store_true",
        help="Skip AINS API identity lookup (v0.5.2+)",
    )
    p_send.add_argument(
        "--no-http-auth",
        action="store_true",
        help="Skip JIS-DID auth header on HTTP transport (v0.5.4+)",
    )
    p_send.add_argument(
        "--min-trust",
        type=float,
        default=0.5,
        help=(
            "Minimum AINS trust_score to allow send "
            "(default: 0.5; only enforced when AINS-record found)"
        ),
    )
    p_send.add_argument(
        "--dry-run",
        action="store_true",
        help="Pack but skip SCP step",
    )
    p_send.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose SCP output",
    )
    p_send.set_defaults(func=_cmd_send)

    # `tcd ack REF --to TARGET` — send signed ACK back
    p_ack = sub.add_parser(
        "ack",
        help=(
            "Send a signed ACK bundle referencing a prior arrival "
            "(v0.5.8+)"
        ),
    )
    p_ack.add_argument(
        "ref",
        help="Name of the bundle being acked (= filename or ID)",
    )
    p_ack.add_argument(
        "--to",
        required=True,
        help="Target where the ACK should be delivered",
    )
    p_ack.add_argument(
        "--note",
        default=None,
        help="Optional human-readable ACK note",
    )
    # Mirror the send-side flags so we reuse the same transport
    for opt in [
        "identity", "receiver-aint", "receiver-pubkey",
        "surface-time", "surface-profile", "surface-priority",
    ]:
        flag = f"--{opt}"
        p_ack.add_argument(flag, default=None)
    p_ack.add_argument(
        "--transport", choices=("scp", "http"), default="scp"
    )
    p_ack.add_argument("--no-ains", action="store_true")
    p_ack.add_argument("--no-http-auth", action="store_true")
    p_ack.add_argument("--min-trust", type=float, default=0.5)
    p_ack.add_argument("--dry-run", action="store_true")
    p_ack.add_argument("-v", "--verbose", action="store_true")
    p_ack.set_defaults(func=_cmd_ack)

    # `tcd recv --port 8443 --wait 60` — ephemeral HTTP listener
    p_recv = sub.add_parser(
        "recv",
        help=(
            "Ephemeral HTTP listener — receive 1 or more arrivals "
            "then exit (v0.5.9+)"
        ),
    )
    p_recv.add_argument(
        "--port", type=int, default=8443,
        help="HTTP port to listen on (default 8443)",
    )
    p_recv.add_argument(
        "--host", default="0.0.0.0",
        help="Bind address (default 0.0.0.0)",
    )
    p_recv.add_argument(
        "--wait", type=int, default=60,
        help="Maximum seconds to wait for arrival(s) (default 60)",
    )
    p_recv.add_argument(
        "--count", type=int, default=1,
        help="Number of arrivals to wait for (default 1)",
    )
    p_recv.add_argument(
        "--inbox", default=None,
        help="Inbox directory (default: ephemeral temp dir)",
    )
    p_recv.add_argument(
        "--keep-inbox", action="store_true",
        help="Keep inbox dir after exit (default: clean up ephemeral)",
    )
    p_recv.set_defaults(func=_cmd_recv)

    # `tcd mux-consumer` — polling receiver for mux frames
    p_muxc = sub.add_parser(
        "mux-consumer",
        help=(
            "Poll a tibet-mux server and materialize incoming frames "
            "as inbox files (v0.6.1+)"
        ),
    )
    p_muxc.add_argument(
        "--server", default=None,
        help="tibet-mux base URL (default: TIBET_MUX_SERVER env or "
             "http://localhost:8000)",
    )
    p_muxc.add_argument(
        "--agent", required=True,
        help="My agent name (= mux target identity)",
    )
    p_muxc.add_argument(
        "--intent", default=None,
        help="Intent filter (default: continuityd:inbox)",
    )
    p_muxc.add_argument(
        "--inbox", required=True,
        help="Inbox directory to write incoming bundles into",
    )
    p_muxc.add_argument(
        "--interval", type=float, default=1.0,
        help="Poll interval in seconds (default 1.0)",
    )
    p_muxc.add_argument(
        "--duration", type=int, default=0,
        help="Max seconds to run (0 = forever, default 0)",
    )
    p_muxc.add_argument(
        "--count", type=int, default=0,
        help="Stop after N materializations (0 = unlimited)",
    )
    p_muxc.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose polling output",
    )
    p_muxc.set_defaults(func=_cmd_mux_consumer)

    args = parser.parse_args(argv)

    # Default subcommand: run (backwards-compat with v0.4.x).
    if args.cmd is None:
        return _cmd_run(args)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
