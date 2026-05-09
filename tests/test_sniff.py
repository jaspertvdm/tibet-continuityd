"""Tests for sniff stage — magic-byte recognition + intake disposition."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PKG = Path("/srv/jtel-stack/packages/tibet-continuityd/src")
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from tibet_continuityd.sniff import (  # noqa: E402
    IntakeClass,
    SEALED_EXTENSIONS,
    TBZ_MAGIC,
    sniff_payload,
)


# ─── Helper to build a fake TBZ-prefixed bundle ─────────────────


def _make_tbz_bundle(path: Path, payload: bytes = b"\x00" * 100) -> Path:
    path.write_bytes(TBZ_MAGIC + b"\x01\x00\x00\x00" + payload)
    return path


# ─── Sealed (TBZ magic + recognized extension) ──────────────────


@pytest.mark.parametrize("ext", sorted(SEALED_EXTENSIONS))
def test_sealed_tbz_with_known_extension(tmp_path, ext):
    p = _make_tbz_bundle(tmp_path / f"sample.{ext}")
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.SEALED_TBZ
    assert r.extension == ext
    assert r.surface_extension_implies_sealed
    assert r.disposition_hint == "trusted-candidate"


def test_sealed_tbz_no_extension(tmp_path):
    p = _make_tbz_bundle(tmp_path / "no-ext-bundle")
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.SEALED_TBZ_NO_EXT
    assert r.extension == ""
    assert not r.surface_extension_implies_sealed
    assert r.disposition_hint == "trusted-candidate"


def test_sealed_tbz_unknown_extension(tmp_path):
    p = _make_tbz_bundle(tmp_path / "weird.xyz")
    r = sniff_payload(p)
    # Magic wins; unknown extension still trusted-candidate
    assert r.intake_class == IntakeClass.SEALED_TBZ_NO_EXT
    assert r.disposition_hint == "trusted-candidate"


# ─── Disguised (extension claims sealed, no TBZ magic) ──────────


@pytest.mark.parametrize("ext", ["claude", "tza", "iddrop", "capsule"])
def test_disguised_payload_extension_claims_sealed(tmp_path, ext):
    p = tmp_path / f"impostor.{ext}"
    p.write_bytes(b"This is not a TBZ bundle, just text.")
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.DISGUISED
    assert r.surface_extension_implies_sealed
    assert r.disposition_hint == "triage-disguised"


# ─── Executable / PDF / JSON / unknown ──────────────────────────


def test_elf_executable_quarantined(tmp_path):
    p = tmp_path / "binary"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.EXECUTABLE
    assert r.disposition_hint == "quarantine"


def test_pe_executable_quarantined(tmp_path):
    p = tmp_path / "windows.exe"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 60)
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.EXECUTABLE
    assert r.disposition_hint == "quarantine"


def test_pdf_rejected(tmp_path):
    p = tmp_path / "document.pdf"
    p.write_bytes(b"%PDF-1.7\n")
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.PDF
    assert r.disposition_hint == "reject"


def test_plain_json_reseal_candidate(tmp_path):
    p = tmp_path / "session.json"
    p.write_bytes(b'  {"key": "value"}\n')
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.JSON_TEXT
    assert r.disposition_hint == "reseal-candidate"


def test_empty_file_rejected(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.EMPTY
    assert r.disposition_hint == "reject"


def test_unknown_text_quarantined(tmp_path):
    p = tmp_path / "random"
    p.write_bytes(b"some random text payload")
    r = sniff_payload(p)
    assert r.intake_class == IntakeClass.UNKNOWN
    assert r.disposition_hint == "quarantine"


# ─── Library invariants ─────────────────────────────────────────


def test_sniff_result_serializable(tmp_path):
    p = _make_tbz_bundle(tmp_path / "x.tza")
    r = sniff_payload(p)
    d = r.to_dict()
    assert d["intake_class"] == "sealed-tbz"
    assert d["disposition_hint"] == "trusted-candidate"
    assert d["size_bytes"] > 0


def test_axiom_codex_name_hint_content_truth(tmp_path):
    """Codex' axiom: filename does not determine trust.

    A file named hello.tza without TBZ magic is DISGUISED.
    A file named random with TBZ magic is SEALED_TBZ_NO_EXT.
    """
    fake = tmp_path / "hello.tza"
    fake.write_bytes(b"plain text content")
    r1 = sniff_payload(fake)
    assert r1.intake_class == IntakeClass.DISGUISED

    real = tmp_path / "no-extension"
    _make_tbz_bundle(real)
    r2 = sniff_payload(real)
    assert r2.intake_class == IntakeClass.SEALED_TBZ_NO_EXT
    assert r2.disposition_hint == "trusted-candidate"
