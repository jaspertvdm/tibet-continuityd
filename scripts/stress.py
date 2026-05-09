#!/usr/bin/env python3
"""
stress.py — Synthetic stress generator for tibet-continuityd v0.1.

Implements Codex' maturing-plan scenarios A-E
(/srv/jtel-stack/hersenspinsels/tibet-continuityd-maturing-plan.md):

  A. Clean happy path        10 valid TBZ arrivals, mixed extensions
  B. Rename/disguise path    valid filename, wrong magic, rename churn
  C. Wrong object family     ELF, PE, PDF, shell, plain text
  D. Unpacked leakage        plain JSON, pseudo-state blobs
  E. Burst + churn           100+ files, renames, deletes, partial writes

Usage:
  python3 stress.py --inbox /tmp/inbox --scenario all
  python3 stress.py --inbox /tmp/inbox --scenario E --burst 1000

Designed to run AGAINST a live daemon. Drops files into the
watched inbox lane and reports timing.
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import sys
import time
from pathlib import Path

TBZ_MAGIC = b"\x54\x42\x5A"
ELF_MAGIC = b"\x7fELF\x02\x01\x01\x00"
PE_MAGIC = b"MZ\x90\x00"
PDF_MAGIC = b"%PDF-1.7\n"

SEALED_EXTS = ["claude", "gemini", "gpt", "kit", "iddrop",
               "parentattest", "capsule", "tza"]


def _make_tbz(path: Path, payload_size: int = 256) -> None:
    body = TBZ_MAGIC + b"\x01\x00\x00\x00" + os.urandom(payload_size)
    path.write_bytes(body)


def _stamp() -> str:
    return f"{int(time.time() * 1000) % 1_000_000_000:09d}"


# ─── Scenario A — Clean happy path ──────────────────────────────


def scenario_a(inbox: Path, count: int = 10) -> dict:
    """10 valid TBZ arrivals, mixed extensions."""
    print(f"[A] Clean happy path — {count} valid TBZ arrivals")
    t0 = time.time()
    for i in range(count):
        ext = random.choice(SEALED_EXTS + [""])  # one in N has no ext
        suffix = f".{ext}" if ext else ""
        name = f"clean-{_stamp()}-{i}{suffix}"
        _make_tbz(inbox / name)
        time.sleep(0.01)
    elapsed = time.time() - t0
    return {"scenario": "A", "files": count, "elapsed_sec": round(elapsed, 3)}


# ─── Scenario B — Rename/disguise ───────────────────────────────


def scenario_b(inbox: Path, count: int = 10) -> dict:
    """Disguised: valid extension, wrong magic. Plus rename churn."""
    print(f"[B] Disguise + rename — {count} disguised arrivals")
    t0 = time.time()
    for i in range(count):
        ext = random.choice(SEALED_EXTS)
        # plain text body, NO TBZ magic
        body = f"This is plain text but pretends to be sealed (run {i})\n" \
               f"random: {os.urandom(32).hex()}\n"
        path = inbox / f"impostor-{_stamp()}-{i}.{ext}"
        path.write_bytes(body.encode())
        time.sleep(0.01)

        # Half also get renamed quickly
        if i % 2 == 0:
            new_ext = random.choice(SEALED_EXTS)
            new_path = inbox / f"renamed-{_stamp()}-{i}.{new_ext}"
            try:
                path.rename(new_path)
            except OSError:
                pass
        time.sleep(0.01)

    elapsed = time.time() - t0
    return {"scenario": "B", "files": count, "elapsed_sec": round(elapsed, 3)}


# ─── Scenario C — Wrong object family ───────────────────────────


def scenario_c(inbox: Path) -> dict:
    """ELF, PE, PDF, shell, plain text."""
    print("[C] Wrong object family — exe / pdf / shell / text")
    t0 = time.time()

    (inbox / f"binary-elf-{_stamp()}").write_bytes(
        ELF_MAGIC + os.urandom(128))
    (inbox / f"binary-pe-{_stamp()}.exe").write_bytes(
        PE_MAGIC + os.urandom(128))
    (inbox / f"document-{_stamp()}.pdf").write_bytes(
        PDF_MAGIC + os.urandom(128))
    (inbox / f"script-{_stamp()}.sh").write_bytes(
        b"#!/bin/bash\necho hello\n")
    (inbox / f"plain-{_stamp()}.txt").write_bytes(
        b"just plain text, nothing fancy\n")
    time.sleep(0.05)

    elapsed = time.time() - t0
    return {"scenario": "C", "files": 5, "elapsed_sec": round(elapsed, 3)}


# ─── Scenario D — Unpacked continuity leakage ───────────────────


def scenario_d(inbox: Path, count: int = 5) -> dict:
    """Plain JSON / pseudo-state blobs."""
    print(f"[D] Unpacked continuity leakage — {count} JSON blobs")
    import json
    t0 = time.time()

    for i in range(count):
        state = {
            "session_id": f"phantom-leaked-{_stamp()}-{i}",
            "owner_did": "jis:pixel:test",
            "transcript": [
                {"role": "user", "content": "leaked content"},
                {"role": "assistant", "content": "leaked response"},
            ],
            "context_data": {"leak_test": True, "i": i},
        }
        (inbox / f"orphan-state-{_stamp()}-{i}.json").write_bytes(
            json.dumps(state).encode()
        )
        time.sleep(0.01)

    # Also: pseudo-state without .json extension
    (inbox / f"pseudo-{_stamp()}").write_bytes(
        b'{"looks-like-json": "but has no ext"}'
    )
    time.sleep(0.01)

    elapsed = time.time() - t0
    return {"scenario": "D", "files": count + 1, "elapsed_sec": round(elapsed, 3)}


# ─── Scenario E — Burst + churn ─────────────────────────────────


def scenario_e(inbox: Path, burst: int = 100) -> dict:
    """Burst arrivals + renames + deletes + partial writes."""
    print(f"[E] Burst + churn — {burst} files with rename/delete/partial")
    t0 = time.time()
    written = []

    for i in range(burst):
        # Mix of valid and invalid
        if i % 3 == 0:
            # valid TBZ
            p = inbox / f"burst-tbz-{_stamp()}-{i}.tza"
            _make_tbz(p, payload_size=128)
        elif i % 3 == 1:
            # disguised
            p = inbox / f"burst-disguise-{_stamp()}-{i}.claude"
            p.write_bytes(b"plain text " + os.urandom(64))
        else:
            # plain
            p = inbox / f"burst-plain-{_stamp()}-{i}.json"
            p.write_bytes(b'{"i":' + str(i).encode() + b'}')
        written.append(p)

        # Mild churn: every 10th, rename or delete an earlier file
        if i % 10 == 9 and len(written) > 5:
            target = random.choice(written[:-3])
            if target.exists():
                if random.random() < 0.5:
                    new = target.parent / f"churn-{_stamp()}{target.suffix}"
                    try:
                        target.rename(new)
                        written.append(new)
                    except OSError:
                        pass
                else:
                    try:
                        target.unlink()
                    except OSError:
                        pass

    # Partial-write tail: open + write incomplete + close
    for i in range(3):
        with open(inbox / f"partial-{_stamp()}-{i}.tza", "wb") as f:
            f.write(b"TB")  # only 2 bytes — not full magic

    elapsed = time.time() - t0
    return {
        "scenario": "E",
        "files": burst + 3,
        "elapsed_sec": round(elapsed, 3),
        "rate_per_sec": round(burst / elapsed, 1) if elapsed > 0 else 0,
    }


# ─── Runner ─────────────────────────────────────────────────────


SCENARIOS = {
    "A": scenario_a,
    "B": scenario_b,
    "C": scenario_c,
    "D": scenario_d,
    "E": scenario_e,
}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inbox", required=True, type=Path,
                   help="Watched inbox directory")
    p.add_argument("--scenario", default="all",
                   choices=["A", "B", "C", "D", "E", "all"])
    p.add_argument("--burst", type=int, default=100,
                   help="Burst size for scenario E")
    p.add_argument("--clean", action="store_true",
                   help="Wipe inbox before starting")
    args = p.parse_args()

    if not args.inbox.exists():
        print(f"inbox not found: {args.inbox}", file=sys.stderr)
        return 1

    if args.clean:
        for child in args.inbox.iterdir():
            if child.is_file():
                child.unlink()
            elif child.is_dir():
                shutil.rmtree(child)

    scenarios_to_run = (list("ABCDE") if args.scenario == "all"
                        else [args.scenario])
    results = []

    print(f"\nstress: inbox={args.inbox} scenarios={scenarios_to_run}\n")
    for s in scenarios_to_run:
        if s == "E":
            r = SCENARIOS[s](args.inbox, burst=args.burst)
        else:
            r = SCENARIOS[s](args.inbox)
        results.append(r)
        time.sleep(0.5)  # let daemon settle between scenarios

    print("\nResults:")
    for r in results:
        print(f"  {r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
