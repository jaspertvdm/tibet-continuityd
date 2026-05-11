"""
CLI entry-point for tibet-continuityd with subcommands.

  tcd run             # daemon mode (default — backwards-compat)
  tcd send FILE --to HOST:PATH
                      # push-mode: pack + scp to peer inbox

Without subcommand, defaults to `run` (= existing v0.4.x behavior).
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional


def _cmd_run(args: argparse.Namespace) -> int:
    """Subcommand: run daemon (= existing v0.4 behavior)."""
    from tibet_continuityd.daemon import main as daemon_main
    return daemon_main()


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

    target = args.to
    if ":" not in target:
        print(
            "ERROR: --to must be <user@host>:<inbox-path> or "
            "<host>:<inbox-path>",
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

        # Pack the source into a sealed .tza bundle
        pack_cmd = [
            sys.executable, "-m", "tibet_drop", "pack",
            "--identity", str(identity_dir),
            "--receiver-aint", receiver_aint,
            "--receiver-pubkey", receiver_pubkey,
            "--input", str(src),
            "--output", str(bundle_out),
            "--surface-time", surface_time,
            "--surface-context", surface_context,
            "--surface-profile", surface_profile,
            "--surface-priority", surface_priority,
        ]
        result = subprocess.run(pack_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(
                f"ERROR: tibet_drop pack failed:\n{result.stderr}",
                file=sys.stderr,
            )
            return result.returncode

        print(f"✓ packed sealed envelope: {bundle_name}")

        if args.dry_run:
            print(f"[dry-run] would scp {bundle_out} → {target}")
            return 0

        # SCP to target host inbox
        scp_cmd = ["scp", str(bundle_out), f"{target}/"]
        if args.verbose:
            scp_cmd.insert(1, "-v")
        result = subprocess.run(scp_cmd, capture_output=True, text=True)
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

    args = parser.parse_args(argv)

    # Default subcommand: run (backwards-compat with v0.4.x).
    if args.cmd is None:
        return _cmd_run(args)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
