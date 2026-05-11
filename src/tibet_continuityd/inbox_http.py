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

import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional


_log = logging.getLogger("tibet_continuityd.inbox_http")


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
            # Write atomically: <name>.part → rename
            part = inbox_dir / (filename + ".part")
            final = inbox_dir / filename
            inbox_dir.mkdir(parents=True, exist_ok=True)
            part.write_bytes(body)
            part.rename(final)
            _log.info(
                f"http-inbox: received {filename} "
                f"({length} bytes) from {self.address_string()}"
            )
            self.send_response(201)
            resp = f"created {filename} ({length} bytes)\n".encode()
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
