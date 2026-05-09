"""
sniff.py — Magic-byte recognition for incoming payloads.

Implements the Sniff stage of the continuity pipeline:
- magic-byte intrinsic recognition (libmagic-style, but we use
  a small in-package table for our known classes; we do not
  rely on python-magic to keep the daemon dependency-light)
- intake disposition per Codex' policy table
  (tibet-continuity-guardian.md §"Intake policy table")

Key axiom (Codex 9 mei 2026):

    Name is hint. Content is truth. Arrival is event.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


# ─── Magic-byte registry ────────────────────────────────────────


# TBZ format magic — first 3 bytes "TBZ" (0x54 0x42 0x5A)
TBZ_MAGIC = b"\x54\x42\x5A"

# Common executable / archive magics (for disposition-table)
ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
PDF_MAGIC = b"%PDF"
JSON_HINT_OPEN = b"{"
JSON_HINT_LIST = b"["

# Recognized vendor extensions for sealed bundles per
# SSM draft §8.1 Surface Profile Registry
SEALED_EXTENSIONS = frozenset({
    "tza", "claude", "gemini", "gpt", "kit", "iddrop",
    "parentattest", "capsule",
})


class IntakeClass(Enum):
    """Sniffed intake classification.

    Per Codex' policy table (tibet-continuity-guardian.md):
    each class maps to a canonical disposition decision in
    Mode 2/3.
    """
    SEALED_TBZ = "sealed-tbz"               # TBZ magic + recognized
    SEALED_TBZ_NO_EXT = "sealed-tbz-no-ext" # TBZ magic, no/unknown ext
    DISGUISED = "disguised"                 # ext suggests sealed, no magic
    EXECUTABLE = "executable"               # ELF / PE binary
    PDF = "pdf"
    JSON_TEXT = "json-text"                 # plain JSON state
    UNKNOWN = "unknown"                     # everything else
    EMPTY = "empty"                         # zero-byte file


@dataclass
class SniffResult:
    """Output of sniff_payload()."""
    intake_class: IntakeClass
    extension: str                  # without leading dot, lowercased
    surface_extension_implies_sealed: bool
    magic_prefix_hex: str           # first 8 bytes hex (for logging)
    size_bytes: int
    disposition_hint: str           # one of: trusted-candidate /
                                    # quarantine / triage-disguised /
                                    # reseal-candidate / reject

    def to_dict(self) -> dict:
        return {
            "intake_class": self.intake_class.value,
            "extension": self.extension,
            "surface_extension_implies_sealed":
                self.surface_extension_implies_sealed,
            "magic_prefix_hex": self.magic_prefix_hex,
            "size_bytes": self.size_bytes,
            "disposition_hint": self.disposition_hint,
        }


def _read_prefix(path: Path, n: int = 16) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return b""


def _classify_disposition(
    intake: IntakeClass,
    surface_implies_sealed: bool,
) -> str:
    """Map intake class to disposition hint per Codex §"Intake policy"."""
    if intake == IntakeClass.SEALED_TBZ:
        return "trusted-candidate"
    if intake == IntakeClass.SEALED_TBZ_NO_EXT:
        return "trusted-candidate"
    if intake == IntakeClass.DISGUISED:
        return "triage-disguised"
    if intake == IntakeClass.EXECUTABLE:
        return "quarantine"
    if intake == IntakeClass.PDF:
        return "reject"
    if intake == IntakeClass.JSON_TEXT:
        # plain unpacked continuity state in sealed-only zone
        return "reseal-candidate"
    if intake == IntakeClass.EMPTY:
        return "reject"
    return "quarantine"


def sniff_payload(path: Path) -> SniffResult:
    """
    Inspect a single arrived payload at `path`.

    Returns a SniffResult with intake classification + disposition
    hint. Does NOT verify cryptographic integrity — that is the
    Verify stage (v0.2). Sniff is content-recognition only.
    """
    if not path.exists() or not path.is_file():
        return SniffResult(
            intake_class=IntakeClass.UNKNOWN,
            extension="",
            surface_extension_implies_sealed=False,
            magic_prefix_hex="",
            size_bytes=0,
            disposition_hint="quarantine",
        )

    size_bytes = path.stat().st_size
    if size_bytes == 0:
        return SniffResult(
            intake_class=IntakeClass.EMPTY,
            extension=path.suffix.lstrip(".").lower(),
            surface_extension_implies_sealed=False,
            magic_prefix_hex="",
            size_bytes=0,
            disposition_hint="reject",
        )

    prefix = _read_prefix(path, 16)
    extension = path.suffix.lstrip(".").lower()
    surface_implies_sealed = extension in SEALED_EXTENSIONS
    magic_hex = prefix[:8].hex()

    # Magic-byte recognition (content-truth)
    if prefix.startswith(TBZ_MAGIC):
        # Sealed TBZ. Disposition depends on whether extension
        # also suggests sealed (cosmetic alignment).
        intake = (IntakeClass.SEALED_TBZ if surface_implies_sealed
                  else IntakeClass.SEALED_TBZ_NO_EXT)
        return SniffResult(
            intake_class=intake,
            extension=extension,
            surface_extension_implies_sealed=surface_implies_sealed,
            magic_prefix_hex=magic_hex,
            size_bytes=size_bytes,
            disposition_hint=_classify_disposition(
                intake, surface_implies_sealed),
        )

    # Surface CLAIMS sealed but content does NOT — disguised
    if surface_implies_sealed:
        return SniffResult(
            intake_class=IntakeClass.DISGUISED,
            extension=extension,
            surface_extension_implies_sealed=True,
            magic_prefix_hex=magic_hex,
            size_bytes=size_bytes,
            disposition_hint="triage-disguised",
        )

    # Other content classes
    if prefix.startswith(ELF_MAGIC) or prefix.startswith(PE_MAGIC):
        return SniffResult(
            intake_class=IntakeClass.EXECUTABLE,
            extension=extension,
            surface_extension_implies_sealed=False,
            magic_prefix_hex=magic_hex,
            size_bytes=size_bytes,
            disposition_hint="quarantine",
        )
    if prefix.startswith(PDF_MAGIC):
        return SniffResult(
            intake_class=IntakeClass.PDF,
            extension=extension,
            surface_extension_implies_sealed=False,
            magic_prefix_hex=magic_hex,
            size_bytes=size_bytes,
            disposition_hint="reject",
        )
    stripped = prefix.lstrip(b" \t\n\r")
    if stripped.startswith(JSON_HINT_OPEN) or \
            stripped.startswith(JSON_HINT_LIST):
        return SniffResult(
            intake_class=IntakeClass.JSON_TEXT,
            extension=extension,
            surface_extension_implies_sealed=False,
            magic_prefix_hex=magic_hex,
            size_bytes=size_bytes,
            disposition_hint="reseal-candidate",
        )

    return SniffResult(
        intake_class=IntakeClass.UNKNOWN,
        extension=extension,
        surface_extension_implies_sealed=False,
        magic_prefix_hex=magic_hex,
        size_bytes=size_bytes,
        disposition_hint="quarantine",
    )
