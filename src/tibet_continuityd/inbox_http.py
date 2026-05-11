"""
HTTP inbox endpoint for tibet-continuityd (v0.5.3).

Phase C step 2 — single-port transport unification.

Provides an optional HTTP listener that writes incoming POST
payloads to the daemon's inbox directory, where the regular
Watch/Sniff/Verify/Seal pipeline picks them up. This means
sealed-tbz arrival can happen over HTTPS-friendly ports
(8088 / 443 via reverse-proxy) instead of SSH/22 — useful
when corporate firewalls block 22 but allow 443.

Endpoints:
    GET  /                  → health check (= text response)
    POST /inbox/<filename>  → write request body to inbox/<filename>

SECURITY NOTE (= explicit, v0.5.3 demo level):
    This endpoint does NOT authenticate. It is intended for:
      • lab + dev cross-host testing
      • behind a reverse-proxy (nginx/Caddy) that enforces TLS
        and adds auth headers
      • internal trusted networks only
    Identity-binding still happens at the TBZ layer (= Ed25519
    signatures verified by continuityd downstream). But the
    HTTP layer itself is unauthenticated in this release.

    Future v0.6+ will add JIS-DID-based auth headers and
    bearer-token enforcement.

Usage:
    Start daemon with HTTP listener enabled:
        TIBET_CONTINUITYD_HTTP_PORT=8088 tcd run

    Send from a peer:
        tcd send hello.txt --transport http \\
            --to http://target-host:8088
"""
from __future__ import annotations

import calendar
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional


_log = logging.getLogger("tibet_continuityd.inbox_http")


def _ains_lookup_pubkey(
    sender_did: str, timeout: float = 3.0
) -> Optional[str]:
    """Look up the AINS record for a JIS DID's host segment,
    returning the registered public_key hex if available.

    sender_did format: jis:<org>:<service>@<host>
    AINS lookup is performed on <host>.

    Returns None on any failure (= API down, no record, no pubkey).
    """
    if not sender_did.startswith("jis:"):
        return None
    after = sender_did[4:]
    if "@" not in after:
        return None
    _, host = after.rsplit("@", 1)
    if not host:
        return None
    api_url = os.environ.get(
        "TIBET_AINS_API_URL",
        "https://brein.jaspervandemeent.nl/api/ains/resolve",
    )
    import json as _json
    import urllib.error as _err
    import urllib.request as _req
    try:
        timeout = float(os.environ.get(
            "TIBET_AINS_API_TIMEOUT", str(timeout)))
    except ValueError:
        pass
    url = f"{api_url.rstrip('/')}/{host}"
    try:
        with _req.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            data = _json.loads(resp.read().decode("utf-8"))
            if data.get("status") != "found":
                return None
            rec = data.get("record") or {}
            pk = rec.get("public_key")
            return pk if isinstance(pk, str) else None
    except (_err.URLError, _err.HTTPError, _json.JSONDecodeError,
            TimeoutError, OSError):
        return None


def _verify_auth_header(
    auth_value: str, body: bytes
) -> Optional[tuple[str, bool]]:
    """Verify TIBET-SIG-V1 Authorization header.

    Returns (pubkey_hex, in_allowlist) on success, None on failure.
    Replay-window via TIBET_HTTP_MAX_SIG_AGE_SEC (default 300).
    Optional allowlist via TIBET_HTTP_TRUSTED_PUBKEYS (comma-sep hex).
    """
    if not auth_value.startswith("TIBET-SIG-V1 "):
        return None
    payload = auth_value[len("TIBET-SIG-V1 "):]
    # v0.5.4: separator is '|' (not ':') to avoid collision
    # with ':' inside timestamp_iso. Older messages used ':'.
    if "|" in payload:
        parts = payload.split("|", 2)
    else:
        # Backwards-compat: split timestamp recombined
        raw = payload.split(":")
        if len(raw) >= 5:
            parts = [raw[0], ":".join(raw[1:-1]), raw[-1]]
        else:
            parts = raw
    if len(parts) != 3:
        return None
    pubkey_hex, ts_iso, sig_hex = parts

    # Replay window check
    try:
        max_age = int(os.environ.get(
            "TIBET_HTTP_MAX_SIG_AGE_SEC", "300"
        ))
    except ValueError:
        max_age = 300
    try:
        ts = calendar.timegm(time.strptime(ts_iso, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return None
    now = time.time()
    if abs(now - ts) > max_age:
        _log.warning(
            f"http-auth: timestamp out of window ({abs(now-ts):.0f}s "
            f"> {max_age}s)"
        )
        return None

    # Signature verification — requires tibet-drop crypto
    try:
        from tibet_drop.crypto import sha256, verify_signature  # type: ignore
    except ImportError:
        _log.warning(
            "http-auth: tibet-drop unavailable, skipping verification"
        )
        return None
    try:
        pubkey = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return None
    body_hash = sha256(body)
    msg = body_hash + ts_iso.encode("utf-8")
    if not verify_signature(pubkey, msg, sig):
        return None

    # Optional allowlist
    allowlist_env = os.environ.get("TIBET_HTTP_TRUSTED_PUBKEYS", "")
    allowlist = {
        k.strip().lower()
        for k in allowlist_env.split(",")
        if k.strip()
    }
    in_allow = pubkey_hex.lower() in allowlist if allowlist else True
    return pubkey_hex, in_allow


def _make_handler(inbox_dir: Path, version: str = "?"):
    """Factory: returns a request-handler class bound to inbox_dir."""

    class _InboxHTTPHandler(BaseHTTPRequestHandler):
        # Suppress default log to stderr; we use our own logger.
        def log_message(self, fmt, *args):  # noqa: D401, ARG002
            _log.debug(f"{self.address_string()} {fmt % args}")

        def do_GET(self):  # noqa: N802
            if self.path in ("/", "/health"):
                body = (
                    f"tibet-continuityd v{version} HTTP inbox\n"
                    f"inbox={inbox_dir}\n"
                    f"POST /inbox/<filename> to deliver.\n"
                )
                payload = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):  # noqa: N802
            if not self.path.startswith("/inbox/"):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            filename = self.path[len("/inbox/"):]
            # Basic safety: reject path traversal
            if "/" in filename or "\\" in filename or ".." in filename:
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0:
                self.send_response(411)  # Length Required
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = self.rfile.read(length)

            # v0.5.4 Optional JIS-DID auth verification.
            _log.debug(
                f"http-inbox headers received: "
                f"{dict(self.headers).keys()}"
            )
            # If TIBET_HTTP_REQUIRE_AUTH=1: reject 401 on fail.
            # If not required: log success/failure, accept either way.
            auth_value = self.headers.get("Authorization", "")
            require_auth = os.environ.get(
                "TIBET_HTTP_REQUIRE_AUTH", "0"
            ) in ("1", "true", "yes")
            auth_result = None
            if auth_value:
                auth_result = _verify_auth_header(auth_value, body)

            # v0.5.5 Optional AINS pubkey-pinning.
            # If sender claims a JIS DID via X-TIBET-Sender-DID and
            # AINS has a record with public_key, the Authorization
            # pubkey MUST match. Behavior controlled by
            # TIBET_HTTP_REQUIRE_AINS_PIN (=1 strict, else warn+accept).
            sender_claim = self.headers.get("X-TIBET-Sender-DID", "")
            pin_status = "no-claim"
            pin_ok = True
            if sender_claim and auth_result:
                ains_pk = _ains_lookup_pubkey(sender_claim)
                if ains_pk:
                    if ains_pk.lower() == auth_result[0].lower():
                        pin_status = f"pinned-by-AINS({sender_claim})"
                    else:
                        pin_status = (
                            f"AINS-PIN-MISMATCH "
                            f"claim={sender_claim} "
                            f"got={auth_result[0][:16]}... "
                            f"want={ains_pk[:16]}..."
                        )
                        pin_ok = False
                else:
                    pin_status = (
                        f"claim={sender_claim} (no AINS record)"
                    )

            require_pin = os.environ.get(
                "TIBET_HTTP_REQUIRE_AINS_PIN", "0"
            ) in ("1", "true", "yes")
            if require_pin and not pin_ok:
                _log.warning(
                    f"http-inbox: 401 AINS-pin failed for {filename}: "
                    f"{pin_status}"
                )
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if require_auth and (auth_result is None
                                  or not auth_result[1]):
                _log.warning(
                    f"http-inbox: 401 unauthorized for {filename} "
                    f"(auth_result={auth_result})"
                )
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            auth_status = "no-auth"
            if auth_result:
                pk_short = auth_result[0][:16] + "..."
                in_allow = auth_result[1]
                auth_status = (
                    f"signed-by={pk_short} allowed={in_allow} "
                    f"{pin_status}"
                )

            # Write atomically: <name>.part → rename
            part = inbox_dir / (filename + ".part")
            final = inbox_dir / filename
            inbox_dir.mkdir(parents=True, exist_ok=True)
            part.write_bytes(body)
            part.rename(final)
            _log.info(
                f"http-inbox: received {filename} "
                f"({length} bytes) from {self.address_string()} "
                f"[{auth_status}]"
            )
            self.send_response(201)
            resp = (
                f"created {filename} ({length} bytes) "
                f"[{auth_status}]\n"
            ).encode()
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

    return _InboxHTTPHandler


class InboxHTTPServer:
    """Threaded HTTP server bound to a continuityd inbox directory."""

    def __init__(
        self,
        inbox_dir: Path,
        port: int,
        host: str = "0.0.0.0",
        version: str = "?",
    ):
        self.inbox_dir = inbox_dir
        self.port = port
        self.host = host
        self.version = version
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler_cls = _make_handler(self.inbox_dir, version=self.version)
        self._httpd = ThreadingHTTPServer(
            (self.host, self.port), handler_cls
        )
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="continuityd-http-inbox",
            daemon=True,
        )
        self._thread.start()
        _log.info(
            f"http-inbox listening on http://{self.host}:{self.port}"
            f"/inbox → {self.inbox_dir}"
        )

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
