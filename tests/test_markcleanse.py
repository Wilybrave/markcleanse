"""Test suite.

Two halves that matter equally:

* **detection** — every fixture must land on the right verdict and tier;
* **restraint** — the false-positive corpus must stay clean. Every entry in
  ``test_no_false_positives`` is a real pattern that fooled an earlier build of
  this tool on a real machine. They are regression tests for over-eagerness,
  which is the failure mode that destroys trust in a forensics tool.

    python3 -m pytest tests/ -q
"""

from __future__ import annotations

import io
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pytest
except ImportError:                       # no pip on this box — see _minipytest
    from _minipytest import pytest        # type: ignore[assignment]

from markcleanse import ScanOptions, Tier, Verdict, scan_bytes, scan_file  # noqa: E402
from markcleanse.cbor_min import loads as cbor_loads                       # noqa: E402
from markcleanse.detectors import unicode_wm                               # noqa: E402
from markcleanse.detectors.stylometry import analyse                       # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _ensure_fixtures() -> None:
    if not os.path.isdir(FIXTURES) or not os.listdir(FIXTURES):
        subprocess.run([sys.executable,
                        os.path.join(os.path.dirname(FIXTURES), "make_fixtures.py")],
                       check=True, capture_output=True)


_ensure_fixtures()

NO_EXIF = ScanOptions(use_exiftool=False)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

EXPECTED = [
    # fixture,                    verdict,                    tier,   source contains
    ("sd_a1111.png",              Verdict.CONFIRMED_AI,       Tier.A, "Stable Diffusion"),
    ("comfyui.png",               Verdict.CONFIRMED_AI,       Tier.A, "ComfyUI"),
    ("novelai.png",               Verdict.CONFIRMED_AI,       Tier.A, "NovelAI"),
    ("dalle3_c2pa.jpg",           Verdict.CONFIRMED_AI,       Tier.A, "DALL"),
    ("hidden_tags.txt",           Verdict.CONFIRMED_AI,       Tier.A, None),
    ("hidden_zerowidth.txt",      Verdict.CONFIRMED_AI,       Tier.A, None),
    ("hidden_varsel.txt",         Verdict.CONFIRMED_AI,       Tier.A, None),
    ("hidden_interword.txt",      Verdict.CONFIRMED_AI,       Tier.A, None),
    ("hidden_trailing.txt",       Verdict.CONFIRMED_AI,       Tier.A, None),
    ("habit_twospace.txt",        Verdict.NO_EVIDENCE,        None,   None),
    ("ai_doc.docx",               Verdict.CONFIRMED_AI,       Tier.A, None),
    ("midjourney_xmp.png",        Verdict.DECLARED_AI,        Tier.B, "Midjourney"),
    ("google_synthid_hint.png",   Verdict.DECLARED_AI,        Tier.B, "Google"),
    ("gamma_export.pdf",          Verdict.DECLARED_AI,        Tier.B, "Gamma"),
    ("leakage.txt",               Verdict.DECLARED_AI,        Tier.B, None),
    ("llm_prose.md",              Verdict.SUSPECT,            Tier.C, None),
    ("homoglyph.txt",             Verdict.SUSPECT,            Tier.C, None),
    ("camera_c2pa.jpg",           Verdict.SIGNED_CAPTURE,     None,   None),
    ("stealth_novelai.png",       Verdict.CONFIRMED_AI,       Tier.A, "NovelAI"),
    ("clean_rgba.png",            Verdict.NO_EVIDENCE,        None,   None),
    ("clean.png",                 Verdict.NO_EVIDENCE,        None,   None),
    ("human_prose.md",            Verdict.NO_EVIDENCE,        None,   None),
]


#: Fixtures whose expected verdict comes from prose stylometry, which is
#: opt-in — see `ScanOptions.include_heuristics`.
NEEDS_STYLOMETRY = {"llm_prose.md"}

WITH_STYLOMETRY = ScanOptions(use_exiftool=False, include_heuristics=True)


@pytest.mark.parametrize("name,verdict,tier,source", EXPECTED,
                         ids=[e[0] for e in EXPECTED])
def test_fixture_verdicts(name, verdict, tier, source):
    opts = WITH_STYLOMETRY if name in NEEDS_STYLOMETRY else NO_EXIF
    report = scan_file(os.path.join(FIXTURES, name), opts)
    assert report.verdict is verdict, f"{name}: {report.basis}"
    if tier is not None:
        assert report.best_tier is tier
    if source is not None:
        assert source.lower() in (report.source or "").lower()


def test_c2pa_generator_and_source_type():
    report = scan_file(os.path.join(FIXTURES, "dalle3_c2pa.jpg"), NO_EXIF)
    f = next(f for f in report.findings if f.signal.startswith("c2pa."))
    assert "trainedAlgorithmicMedia" in str(f.evidence["digital_source_type"])
    assert any("DALL" in g for g in f.evidence["claim_generator"])
    # This fixture carries no signature box, so verification must say so
    # rather than quietly treating an unsigned manifest as verified.
    v = f.evidence["verification"]
    assert v["signature"] == "unchecked", v
    assert not any(g.signal == "c2pa.verified" for g in report.findings)
    assert any(g.signal == "info.c2pa.unverified" for g in report.findings)


def test_camera_c2pa_is_not_called_ai():
    """A signed capture must never be reported as generated."""
    report = scan_file(os.path.join(FIXTURES, "camera_c2pa.jpg"), NO_EXIF)
    assert report.verdict is Verdict.SIGNED_CAPTURE
    assert report.source is None


def test_synthid_is_reported_as_unverifiable():
    report = scan_file(os.path.join(FIXTURES, "google_synthid_hint.png"), NO_EXIF)
    wm = next(f for f in report.findings if f.tier is Tier.U)
    assert "SynthID" in wm.evidence["scheme"]
    assert "ONLY by Google" in wm.evidence["note"]


def test_hidden_payloads_are_recovered():
    cases = {
        "hidden_tags.txt": "wm:openai:2026-08-01:u91234",
        "hidden_zerowidth.txt": "TRACE-8842",
        "hidden_varsel.txt": "leak-id-7731",
    }
    for name, payload in cases.items():
        report = scan_file(os.path.join(FIXTURES, name), NO_EXIF)
        dumped = str([f.evidence for f in report.findings])
        assert payload in dumped, f"{name} did not recover {payload!r}"


# ---------------------------------------------------------------------------
# Restraint — every case here once produced a false positive
# ---------------------------------------------------------------------------

CLEAN_TEXT = {
    "emoji_zwj": "Team update 👨‍🍳 cooking, 👩‍🏫 teaching, 👨‍👩‍👧 family plan. "
                 "Shipping Friday.",
    "ui_bidi_marks": 'combobox "‎Name Box‎" [ref=f10] and '
                     '⁦isolated label⁩ in a snapshot.',
    "persian_zwnj": "نمی‌خواهم این کار را انجام دهم و می‌توانم بروم.",
    "leading_bom": "﻿id,name,total\n1,widget,42\n2,gadget,17\n",
    "plain_prose": "The lawnmower carburettor was gummed up so I soaked it "
                   "overnight. It started on the third pull the next morning.",
    "code_like": "const x = [1,2,3].map(n => n * 2); // doubles every entry\n",
    "emoji_varsel": "Status: ✅️ done, ⚠️ pending, ❌️ blocked, "
                    "▶️ running, ☑️ queued.",
    # A gazetteer: genuine Cyrillic/Greek words, not Latin words salted with
    # lookalikes. Caught a 1992-hit false positive on a countries geojson.
    "mixed_script_names": '{"names": ["Россия", "Ελλάδα", "Україна", "Србија", '
                          '"Ελληνική Δημοκρατία", "Норвегия", "Κύπρος"], '
                          '"iso": ["RU", "GR", "UA", "RS", "CY"]}',
    # Office and LaTeX exports are full of NBSP and em/en spaces.
    "office_spaces": "Q3 results were strong across all "
                     "regions. Revenue rose 12% year on "
                     "year and margin held flat.",
}


@pytest.mark.parametrize("name,text", sorted(CLEAN_TEXT.items()))
def test_no_false_positives(name, text):
    # Deliberately run with stylometry ON even though it is opt-in: restraint
    # has to hold in the configuration most likely to cry wolf, not the safe one.
    report = scan_bytes(f"{name}.txt", text.encode("utf-8"), WITH_STYLOMETRY)
    assert report.verdict is Verdict.NO_EVIDENCE, \
        f"{name} falsely flagged: {report.basis}"


def test_filename_is_never_evidence():
    """A file called CLAUDE.md is not evidence that Claude wrote it."""
    report = scan_bytes("CLAUDE.md", b"# Project notes\n\nBuild with make.\n",
                        WITH_STYLOMETRY)
    assert report.verdict is Verdict.NO_EVIDENCE


def test_homoglyph_needs_a_latin_neighbour():
    """Salting inside Latin words fires; genuine Cyrillic words do not."""
    salted = scan_bytes("a.txt", "The rаte of return on the аccount was high "
                                 "and the аnalyst noted it.".encode(), NO_EXIF)
    assert any(f.signal == "unicode.homoglyphs" for f in salted.findings)
    native = scan_bytes("b.txt", "Москва и Санкт-Петербург — Ελλάδα.".encode(), NO_EXIF)
    assert not any(f.signal == "unicode.homoglyphs" for f in native.findings)


def test_unreadable_pdf_is_not_suspect():
    """'I could not read this' is a coverage note, not evidence."""
    report = scan_bytes("scan.pdf", b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF\n",
                        NO_EXIF)
    assert report.verdict is Verdict.NO_EVIDENCE
    assert any(f.signal.startswith("info.") for f in report.findings)


def test_empty_path_argument_scans_nothing():
    """An empty shell argument must not expand into scanning the whole tree."""
    from markcleanse import scan_paths
    assert scan_paths(["", "   "], NO_EXIF).scanned == 0


def test_google_c2pa_generator_gets_synthid_note():
    """Google signs with 'Google C2PA Core Generator Library', never a model name."""
    from markcleanse.signatures import identify, watermark_for
    named = identify("Google C2PA Core Generator Library")
    assert named == "Google AI"
    assert watermark_for(named) == "SynthID"
    assert watermark_for("Google Some Unreleased Product") == "SynthID"
    assert watermark_for("Adobe Firefly") is None


# ---------------------------------------------------------------------------
# C2PA verification
# ---------------------------------------------------------------------------

SIGNED = os.path.join(FIXTURES, "c2pa_signed.png")
HAVE_SIGNED = os.path.exists(SIGNED)


def _verification(name: str):
    report = scan_file(os.path.join(FIXTURES, name), NO_EXIF)
    for f in report.findings:
        if f.evidence.get("verification"):
            return report, f.evidence["verification"]
    return report, {}


def test_signed_manifest_verifies_end_to_end():
    if not HAVE_SIGNED:
        return
    report, v = _verification("c2pa_signed.png")
    assert v["signature"] == "valid", v
    assert v["binding"] == "matched", v
    assert v["assertions"] == "matched", v
    assert v["chain"] == "verified", v
    assert v["expired"] is False
    assert report.verdict is Verdict.CONFIRMED_AI


def test_boxhash_binding_verifies():
    """`c2pa.hash.boxes` — the third hard binding C2PA 2.4 requires."""
    if not os.path.exists(os.path.join(FIXTURES, "c2pa_boxhash.png")):
        return
    report, v = _verification("c2pa_boxhash.png")
    assert v["binding"] == "matched", v
    assert v["signature"] == "valid", v
    assert report.verdict is Verdict.CONFIRMED_AI, report.basis


def test_boxhash_catches_edited_image_data():
    if not os.path.exists(os.path.join(FIXTURES, "c2pa_boxhash_edited.png")):
        return
    report, v = _verification("c2pa_boxhash_edited.png")
    assert v["binding"] == "mismatched", v
    assert "IDAT" in v["binding_detail"]
    assert report.verdict is Verdict.PROVENANCE_INVALID


def test_box_map_matches_the_reference_naming():
    """Names and order must match c2pa-rs, or the assertion cannot be read."""
    from markcleanse import boxmap
    png = open(os.path.join(FIXTURES, "c2pa_boxhash.png"), "rb").read()
    names = [b.name for b in boxmap.box_map(png, "png")]
    assert names[0] == "PNGh", names
    assert names[1] == "IHDR", names
    assert "C2PA" in names, "the caBX chunk must be named C2PA"
    assert names[-1] == "IEND", names

    jpg = open(os.path.join(FIXTURES, "dalle3_c2pa.jpg"), "rb").read()
    jnames = [b.name for b in boxmap.box_map(jpg, "jpeg")]
    assert jnames[0] == "SOI", jnames
    # A run of APP11 JUMBF segments collapses into a single C2PA entry.
    assert jnames.count("C2PA") == 1, jnames


def test_boxhash_detects_an_inserted_box():
    """Order matters: names are consumed sequentially, so an inserted chunk
    breaks verification even though every original byte is untouched."""
    import struct
    import zlib
    if not os.path.exists(os.path.join(FIXTURES, "c2pa_boxhash.png")):
        return
    from markcleanse import boxmap
    png = open(os.path.join(FIXTURES, "c2pa_boxhash.png"), "rb").read()
    payload = b"Comment\x00harmless"
    extra = (struct.pack(">I", len(payload)) + b"tEXt" + payload
             + struct.pack(">I", zlib.crc32(b"tEXt" + payload) & 0xFFFFFFFF))
    idat = next(b for b in boxmap.box_map(png, "png") if b.name == "IDAT")
    spliced = png[:idat.start] + extra + png[idat.start:]

    report = scan_bytes("x.png", spliced, NO_EXIF)
    v = next(f.evidence["verification"] for f in report.findings
             if f.evidence.get("verification"))
    assert v["binding"] == "mismatched", v
    assert "order" in v["binding_detail"] or "tEXt" in v["binding_detail"], v


def test_transplanted_manifest_is_caught():
    """The same signed manifest pasted onto a different image."""
    if not HAVE_SIGNED:
        return
    report, v = _verification("c2pa_transplant.png")
    assert v["binding"] == "mismatched", v
    assert v["signature"] == "valid", "the manifest itself is intact — only the binding fails"
    assert report.verdict is Verdict.PROVENANCE_INVALID
    assert any(f.signal == "integrity.c2pa.binding_mismatch" for f in report.findings)


def test_image_edited_after_signing_is_caught():
    if not HAVE_SIGNED:
        return
    report, v = _verification("c2pa_edited.png")
    assert v["binding"] == "mismatched", v
    assert report.verdict is Verdict.PROVENANCE_INVALID


def test_forged_assertion_is_caught():
    """Rewriting the generator name inside a signed manifest must not pass."""
    if not os.path.exists(os.path.join(FIXTURES, "c2pa_forged.png")):
        return
    report, v = _verification("c2pa_forged.png")
    assert v["signature"] == "invalid" or v["assertions"] == "mismatched", v
    assert report.verdict is Verdict.PROVENANCE_INVALID


def test_stapled_ocsp_good_is_verified():
    """Revocation is answerable from the file alone — no network."""
    if not os.path.exists(os.path.join(FIXTURES, "c2pa_ocsp_good.png")):
        return
    _r, v = _verification("c2pa_ocsp_good.png")
    rev = v["revocation"]
    assert rev and rev["state"] == "good", rev
    assert rev["signature_verified"], "the responder signature must be checked"


def test_revoked_credential_blocks_verified_but_is_not_tampering():
    if not os.path.exists(os.path.join(FIXTURES, "c2pa_ocsp_revoked.png")):
        return
    report, v = _verification("c2pa_ocsp_revoked.png")
    rev = v["revocation"]
    assert rev["state"] == "revoked", rev
    assert "key compromise" in rev["detail"], rev
    assert any(f.signal == "c2pa.credential_revoked" for f in report.findings)
    assert not any(f.signal == "c2pa.verified" for f in report.findings)
    # A revoked credential says the signer is compromised, not that the file
    # was altered — it must not be reported as forged provenance.
    assert report.verdict is not Verdict.PROVENANCE_INVALID


def test_revocation_can_be_disabled():
    if not os.path.exists(os.path.join(FIXTURES, "c2pa_ocsp_revoked.png")):
        return
    opts = ScanOptions(use_exiftool=False, revocation="off")
    report = scan_file(os.path.join(FIXTURES, "c2pa_ocsp_revoked.png"), opts)
    v = next(f.evidence["verification"] for f in report.findings
             if f.evidence.get("verification"))
    assert v["revocation"] is None


def test_online_revocation_is_never_used_unless_asked():
    """The default must not touch the network — that would disclose the scan."""
    import markcleanse.ocsp as ocsp_mod
    called = []
    original = ocsp_mod.check_online
    ocsp_mod.check_online = lambda *a, **k: called.append(1)
    try:
        scan_file(os.path.join(FIXTURES, "c2pa_signed.png"),
                  ScanOptions(use_exiftool=False))
    finally:
        ocsp_mod.check_online = original
    assert not called, "default scan must not perform a live OCSP query"


def test_certificate_profile_accepts_real_signing_certs():
    """The profile check must not fire on genuine production credentials."""
    if not HAVE_SIGNED:
        return
    from markcleanse import cert_profile
    _r, v = _verification("c2pa_signed.png")
    assert v["profile_problems"] == [], v["profile_problems"]
    assert cert_profile.ALLOWED_CURVES == {"P-256", "P-384", "P-521"}


def test_certificate_profile_rejects_a_non_conforming_cert():
    """Missing EKU / AKI, or a self-signed CA, must be caught."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timedelta, timezone
    except ImportError:
        return
    from markcleanse import asn1, cert_profile

    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sloppy Signer")])
    bare = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256()))
    problems = cert_profile.check(asn1.parse_certificate(
        bare.public_bytes(__import__("cryptography").hazmat.primitives
                          .serialization.Encoding.DER)))
    joined = " ".join(problems).lower()
    assert "self-signed" in joined, problems
    assert "keyusage" in joined, problems


def test_profile_violation_is_not_reported_as_tampering():
    """An out-of-policy credential is not evidence the file was altered."""
    from markcleanse.c2pa_verify import Verification
    v = Verification(signature_state="valid", binding_state="matched",
                     assertion_state="matched", chain_state="verified")
    v.profile_problems = ["no authorityKeyIdentifier"]
    assert not v.tampered
    assert not v.cryptographically_valid


def test_trust_anchors_change_the_trust_state():
    if not HAVE_SIGNED:
        return
    from markcleanse.c2pa_verify import TrustStore
    anchors = os.path.join(FIXTURES, "trust_anchors.txt")
    _r, v = _verification("c2pa_signed.png")
    assert v["trust"] == "no-trust-list", "default must not claim trust"

    opts = ScanOptions(use_exiftool=False, trust_store=TrustStore.from_file(anchors))
    report = scan_file(SIGNED, opts)
    trusted = next(f.evidence["verification"] for f in report.findings
                   if f.evidence.get("verification"))
    assert trusted["trust"] == "trusted"

    opts = ScanOptions(use_exiftool=False, trust_store=TrustStore({"00" * 32}))
    report = scan_file(SIGNED, opts)
    other = next(f.evidence["verification"] for f in report.findings
                 if f.evidence.get("verification"))
    assert other["trust"] == "untrusted-root"


def test_no_verify_flag_disables_verification():
    if not HAVE_SIGNED:
        return
    report = scan_file(SIGNED, ScanOptions(use_exiftool=False, verify_c2pa=False))
    assert not any(f.signal.startswith(("c2pa.verified", "integrity.c2pa"))
                   for f in report.findings)


def test_both_crypto_backends_agree():
    """The pure-Python fallback must accept exactly what the library accepts.

    This test is the reason the fallback exists twice over: it once caught the
    library path silently failing every ECDSA verification.
    """
    if not HAVE_SIGNED:
        return
    from markcleanse import crypto_min
    original = crypto_min.HAVE_CRYPTOGRAPHY
    try:
        results = {}
        for use_lib in (True, False):
            if use_lib and not original:
                continue
            crypto_min.HAVE_CRYPTOGRAPHY = use_lib
            _r, v = _verification("c2pa_signed.png")
            results[use_lib] = (v["signature"], v["chain"])
        assert len(set(results.values())) == 1, results
        assert all(r[0] == "valid" for r in results.values()), results
    finally:
        crypto_min.HAVE_CRYPTOGRAPHY = original


def test_pure_python_ecdsa_rejects_a_bad_signature():
    from markcleanse import asn1, crypto_min
    from markcleanse.cbor_min import dumps
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError:
        return
    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pub = asn1._parse_spki(asn1.read_tlv(spki), spki)
    msg = dumps(["Signature1", b"\xa1\x01\x26", b"", b"payload" * 20])
    r, s = utils.decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
    good = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    bad = bytes(good[0] ^ 0x01) + good[1:] if False else bytes([good[0] ^ 1]) + good[1:]

    original = crypto_min.HAVE_CRYPTOGRAPHY
    try:
        for use_lib in ({True, False} if original else {False}):
            crypto_min.HAVE_CRYPTOGRAPHY = use_lib
            assert crypto_min.verify(pub, "ecdsa", "sha256", msg, good, raw_ecdsa=True)
            assert not crypto_min.verify(pub, "ecdsa", "sha256", msg, bad, raw_ecdsa=True)
            assert not crypto_min.verify(pub, "ecdsa", "sha256", msg + b"x", good,
                                         raw_ecdsa=True)
    finally:
        crypto_min.HAVE_CRYPTOGRAPHY = original


def test_der_parser_reads_a_real_certificate():
    if not HAVE_SIGNED:
        return
    _r, v = _verification("c2pa_signed.png")
    assert v["chain_subjects"] == ["markcleanse Test Signer", "markcleanse Test Root CA"], v


# ---------------------------------------------------------------------------
# BMFF: AVIF / HEIC / MP4
#
# Base containers are encoded by ffmpeg, so these exercise real box structures
# rather than hand-rolled approximations. They skip when ffmpeg is absent.
# ---------------------------------------------------------------------------

HAVE_BMFF = os.path.exists(os.path.join(FIXTURES, "c2pa_bmff.avif"))


@pytest.mark.parametrize("name", ["c2pa_bmff.avif", "c2pa_bmff.heic",
                                  "c2pa_bmff.mp4", "c2pa_bmff_early.avif"])
def test_bmff_manifests_verify(name):
    if not HAVE_BMFF or not os.path.exists(os.path.join(FIXTURES, name)):
        return
    report, v = _verification(name)
    assert v["signature"] == "valid", v
    assert v["binding"] == "matched", v
    assert v["assertions"] == "matched", v
    assert report.verdict is Verdict.CONFIRMED_AI, report.basis


def test_bmff_transplant_is_caught():
    """The gap this closes: without a BMFF binding, this passed silently."""
    if not HAVE_BMFF:
        return
    report, v = _verification("c2pa_bmff_transplant.avif")
    assert v["signature"] == "valid", "the manifest itself is intact"
    assert v["binding"] == "mismatched", v
    assert "BMFF" in v["binding_detail"]
    assert report.verdict is Verdict.PROVENANCE_INVALID


def test_clean_avif_has_no_findings():
    if not HAVE_BMFF:
        return
    report = scan_file(os.path.join(FIXTURES, "clean.avif"), NO_EXIF)
    assert report.verdict is Verdict.NO_EVIDENCE, report.basis


def test_bmff_walker_paths_and_nesting():
    if not HAVE_BMFF:
        return
    from markcleanse import bmff
    data = open(os.path.join(FIXTURES, "c2pa_bmff.avif"), "rb").read()
    paths = [b.path for b in bmff.flatten(bmff.walk(data))]
    assert "/ftyp" in paths and "/meta" in paths and "/mdat" in paths
    assert "/meta/iloc" in paths, "nested boxes must be walked"
    assert "/uuid" in paths
    assert bmff.brand(data) == "avif"


def test_bmff_exclusion_predicate_pins_the_right_uuid_box():
    """`/uuid` alone would match any uuid box; the data predicate anchors it."""
    if not HAVE_BMFF:
        return
    from markcleanse import bmff
    from markcleanse.c2pa_verify import _bmff_rule_matches
    from markcleanse.detectors.c2pa import C2PA_UUID
    data = open(os.path.join(FIXTURES, "c2pa_bmff.avif"), "rb").read()
    box = bmff.find_uuid_box(data, C2PA_UUID)
    assert box is not None
    good = {"xpath": "/uuid", "data": [{"offset": 8, "value": C2PA_UUID}]}
    bad = {"xpath": "/uuid", "data": [{"offset": 8, "value": b"\x00" * 16}]}
    assert _bmff_rule_matches(good, box, data)
    assert not _bmff_rule_matches(bad, box, data)


def test_bmff_sanitize_is_lossless_and_offset_safe():
    if not HAVE_BMFF:
        return
    from markcleanse import bmff
    from markcleanse.sanitize import sanitize_bytes
    all_cats = {"hidden", "privacy", "generator", "provenance"}

    data = open(os.path.join(FIXTURES, "c2pa_bmff.avif"), "rb").read()
    result = sanitize_bytes("x.avif", data, all_cats)
    assert result.changed
    # The manifest was appended after mdat, so the remainder is byte-identical.
    assert data.startswith(result.data)
    assert scan_bytes("x.avif", result.data, NO_EXIF).verdict is Verdict.NO_EVIDENCE
    assert bmff.walk(result.data), "output must still parse as BMFF"

    # ...but a manifest placed before the media data must be left alone.
    early = open(os.path.join(FIXTURES, "c2pa_bmff_early.avif"), "rb").read()
    blocked = sanitize_bytes("y.avif", early, all_cats)
    assert not blocked.changed
    assert any("offset tables" in w for w in blocked.warnings)


def test_unsupported_kind_does_not_bury_a_real_finding():
    """MP4 is not fully supported, but a manifest in one is still a finding."""
    if not HAVE_BMFF or not os.path.exists(os.path.join(FIXTURES, "c2pa_bmff.mp4")):
        return
    report = scan_file(os.path.join(FIXTURES, "c2pa_bmff.mp4"), NO_EXIF)
    assert report.verdict is not Verdict.UNSUPPORTED
    assert report.best_tier is Tier.A


# ---------------------------------------------------------------------------
# Whitespace steganography
# ---------------------------------------------------------------------------

def test_whitespace_payloads_are_recovered():
    for name, payload in {"hidden_interword.txt": "WM-4417",
                          "hidden_trailing.txt": "COPY-9"}.items():
        report = scan_file(os.path.join(FIXTURES, name), NO_EXIF)
        dumped = str([f.evidence for f in report.findings])
        assert payload in dumped, f"{name} did not recover {payload!r}"


def test_uniform_spacing_habit_is_never_flagged():
    """Two spaces after every period is a style. Zero entropy, zero findings."""
    report = scan_file(os.path.join(FIXTURES, "habit_twospace.txt"), NO_EXIF)
    assert not any(f.detector == "whitespace_wm" for f in report.findings)


def test_whitespace_only_runs_on_raw_bytes():
    """Extracted PDF/OOXML text has fabricated spacing — it must be skipped."""
    from markcleanse.context import FileCtx
    from markcleanse.detectors import whitespace_wm
    # Letters only: the extractor requires letters on both sides of a gap, so
    # numbers and punctuation (i.e. code and tables) never contribute bits.
    words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]
    spaced = "".join(words[i % 6] + ("  " if i % 3 else " ") for i in range(300))
    for source in ("raw-stream", "pypdf", "ooxml", "html"):
        ctx = FileCtx(path="x.pdf", data=b"", size=0, kind="document", fmt="pdf",
                      text=spaced, text_source=source)
        assert whitespace_wm.detect(ctx) == [], f"{source} should be skipped"
    ctx = FileCtx(path="x.txt", data=b"", size=0, kind="text", fmt="txt",
                  text=spaced, text_source="plain")
    assert whitespace_wm.detect(ctx), "plain text should still be examined"


def test_entropy_separates_habit_from_payload():
    from markcleanse.detectors.whitespace_wm import entropy
    assert entropy("1" * 64) == 0.0
    assert entropy("01" * 32) == 1.0
    assert entropy("0" * 60 + "1" * 4) < 0.4


# ---------------------------------------------------------------------------
# Punctuation and prose gating
# ---------------------------------------------------------------------------

def test_source_code_is_not_scored_for_style():
    """Type annotations and object literals are not a punctuation profile."""
    from markcleanse.detectors.stylometry import looks_like_code
    code = "\n".join([
        "import { useState } from 'react';",
        "export const Panel = ({ title, items, onSelect }: Props) => {",
        "  const [open, setOpen] = useState<boolean>(false);",
        "  return <div className={styles.panel}>{title}</div>;",
        "};",
    ] * 12)
    assert looks_like_code(code, ".tsx")
    assert looks_like_code(code, ".txt"), "content sniff should catch it too"
    report = scan_bytes("Panel.tsx", code.encode(), NO_EXIF)
    assert not any(f.detector == "stylometry" for f in report.findings)


def test_punctuation_alone_cannot_create_a_finding():
    """A semicolon habit is a writing style, not evidence of generation."""
    sentence = ("The committee reviewed the proposal; the members agreed on the "
                "timeline, the budget, and the scope: all three were approved "
                "(unanimously), which surprised nobody. ")
    report = scan_bytes("minutes.txt", (sentence * 12).encode(), NO_EXIF)
    assert not any(f.signal == "text.stylometry" for f in report.findings), \
        f"punctuation alone produced: {report.basis}"


def test_markdown_scaffolding_excluded_from_punctuation_rates():
    """Colons in '**Label:** value' bullets are structural, not authorial."""
    from markcleanse.detectors.stylometry import punctuation_profile, prose_lines
    doc = ("Some ordinary running prose that carries the document forward "
           "without unusual punctuation at all, repeated for length. " * 8
           + "\n" + "\n".join(f"- **Item {i}:** a value, another value" for i in range(40)))
    assert "Item 3" not in prose_lines(doc)
    assert punctuation_profile(doc, len(doc.split()))["colon_per_1000"] < 5


def test_only_flag_keeps_the_text_extraction_stage():
    """--only stylometry must not silently disable text extraction."""
    from markcleanse import scan_paths
    opts = ScanOptions(use_exiftool=False, only={"stylometry"})
    result = scan_paths([os.path.join(FIXTURES, "llm_prose.md")], opts)
    assert any(f.signal == "text.stylometry"
               for r in result.reports for f in r.findings)


def test_human_prose_scores_below_llm_prose():
    human = analyse(open(os.path.join(FIXTURES, "human_prose.md"), encoding="utf-8").read())
    llm = analyse(open(os.path.join(FIXTURES, "llm_prose.md"), encoding="utf-8").read())
    assert llm["score"] > human["score"] + 20
    assert llm["family"] == "Anthropic Claude-family"


def test_short_text_is_not_scored():
    """Stylometry on two sentences is noise; it must abstain."""
    report = scan_bytes("tiny.txt", b"It's not just fast, but cheap. That said, "
                                    b"it's worth noting the tradeoff.\n", NO_EXIF)
    assert not any(f.signal == "text.stylometry" for f in report.findings)


# ---------------------------------------------------------------------------
# Sanitizing
# ---------------------------------------------------------------------------

def _sanitize(name: str, cats=None):
    from markcleanse.sanitize import sanitize_bytes
    with open(os.path.join(FIXTURES, name), "rb") as fh:
        data = fh.read()
    return data, sanitize_bytes(name, data, cats)


def _idat(png: bytes) -> bytes:
    from markcleanse.detectors.c2pa import iter_png_chunks
    return b"".join(p for t, p in iter_png_chunks(png) if t == b"IDAT")


def test_sanitize_removes_hidden_payload_but_not_visible_text():
    data, result = _sanitize("hidden_tags.txt")
    assert result.changed
    before = data.decode("utf-8")
    after = result.data.decode("utf-8")
    assert after == "".join(c for c in before if not 0xE0000 <= ord(c) <= 0xE007F)
    assert "Quarterly summary follows." in after


def test_sanitize_output_is_clean_on_rescan():
    for name in ("hidden_tags.txt", "hidden_zerowidth.txt", "hidden_varsel.txt",
                 "hidden_interword.txt", "hidden_trailing.txt"):
        _data, result = _sanitize(name)
        assert result.changed, name
        after = scan_bytes(name, result.data, NO_EXIF)
        assert not any(f.detector in ("unicode_wm", "whitespace_wm")
                       for f in after.findings), f"{name}: {after.basis}"


def test_sanitize_png_is_lossless():
    """Chunks are dropped; the image data must be byte-identical."""
    data, result = _sanitize("sd_a1111.png")
    assert result.changed
    assert _idat(result.data) == _idat(data)
    assert result.data.startswith(b"\x89PNG\r\n\x1a\n")
    assert result.data.rstrip().endswith(b"IEND\xae\x42\x60\x82")
    after = scan_bytes("x.png", result.data, NO_EXIF)
    assert after.verdict is Verdict.NO_EVIDENCE, after.basis


def test_provenance_needs_an_explicit_opt_in():
    if not HAVE_SIGNED:
        return
    _data, default = _sanitize("c2pa_signed.png")
    assert not default.changed, "C2PA must survive the default categories"
    assert any("C2PA manifest is present and was kept" in w
               for w in default.warnings)

    _data, opted = _sanitize("c2pa_signed.png",
                             {"hidden", "privacy", "generator", "provenance"})
    assert opted.changed
    assert any(a.category == "provenance" for a in opted.actions)
    after = scan_bytes("x.png", opted.data, NO_EXIF)
    assert not any(f.detector == "c2pa" for f in after.findings)


def test_sanitize_warns_that_pixel_watermarks_survive():
    _data, result = _sanitize("google_synthid_hint.png")
    assert result.changed
    joined = " ".join(result.warnings)
    assert "SynthID" in joined
    assert "NOT removed" in joined


def test_whitespace_normalisation_only_runs_when_a_payload_exists():
    """A metadata scrub must not silently reflow someone's prose."""
    from markcleanse.sanitize import sanitize_text
    _data, habit = _sanitize("habit_twospace.txt")
    assert not habit.changed, "consistent two-space habit must be left alone"

    payload = open(os.path.join(FIXTURES, "hidden_trailing.txt"),
                   encoding="utf-8").read()
    cleaned, actions = sanitize_text(payload, {"hidden"})
    assert any("trailing whitespace" in a.detail for a in actions)


def test_sanitize_preserves_emoji_and_script_joiners():
    from markcleanse.sanitize import sanitize_text
    text = "Team 👨‍🍳 and 👨‍👩‍👧 plus نمی‌خواهم here."
    cleaned, actions = sanitize_text(text, {"hidden"})
    assert cleaned == text, f"removed something it should not have: {actions}"


def test_sanitize_refuses_formats_it_cannot_rewrite_safely():
    from markcleanse.sanitize import sanitize_bytes
    result = sanitize_bytes("x.tiff", b"II*\x00" + b"\x00" * 64)
    assert not result.changed
    assert "not implemented" in result.unsupported
    assert "exiftool" in result.unsupported


def test_sanitize_pdf_blanks_in_place_without_restructuring():
    """PDF metadata is erased byte-for-byte, never by rebuilding the file.

    Rewriting a PDF re-renders it and drops signatures and forms; ghostscript
    was measured turning a 596 KB document into a 2 KB stub that still passed a
    header check. Blanking a literal string with spaces of the same length
    leaves every xref offset valid, which is why the length must not move.
    """
    from markcleanse.sanitize import sanitize_bytes

    data = open(os.path.join(FIXTURES, "gamma_export.pdf"), "rb").read()
    result = sanitize_bytes("x.pdf", data, {"privacy", "generator"})
    assert result.changed
    assert len(result.data) == len(data), "byte offsets must not shift"
    assert b"Gamma" not in result.data and b"ChatGPT" not in result.data
    assert scan_bytes("x.pdf", result.data, NO_EXIF).verdict is Verdict.NO_EVIDENCE

    # Metadata inside a compressed object stream cannot be reached this way,
    # and that has to be said rather than reported as a clean file.
    packed = b"%PDF-1.7\n1 0 obj\n<< /Type /ObjStm >>\nendobj\n%%EOF\n"
    note = sanitize_bytes("y.pdf", packed, {"privacy", "generator"})
    assert not note.changed
    assert any("compressed object stream" in w for w in note.warnings), note.warnings


def test_sanitize_docx_keeps_a_valid_zip():
    import re
    import zipfile
    data, result = _sanitize("ai_doc.docx")
    assert result.changed
    src = zipfile.ZipFile(io.BytesIO(data))
    out = zipfile.ZipFile(io.BytesIO(result.data))
    assert out.testzip() is None
    before = src.read("word/document.xml").decode()
    after = out.read("word/document.xml").decode()
    stripped = "".join(c for c in before if not 0xE0000 <= ord(c) <= 0xE007F)
    assert after == stripped, "only the hidden payload may change"
    assert "docProps/core.xml" not in out.namelist()


def test_sanitize_never_touches_a_clean_file():
    for name in ("clean.png", "human_prose.md"):
        _data, result = _sanitize(name)
        assert not result.changed, name


# ---------------------------------------------------------------------------
# Holes found by adversarial probing. Each of these once got through.
# ---------------------------------------------------------------------------

def test_stealth_pnginfo_is_read_from_the_pixels():
    """Alpha-LSB payloads survive every metadata strip, so they must be read."""
    report = scan_file(os.path.join(FIXTURES, "stealth_novelai.png"), NO_EXIF)
    assert report.verdict is Verdict.CONFIRMED_AI, report.basis
    dumped = str([f.evidence for f in report.findings])
    assert "volumetric fog" in dumped
    assert any(f.signal == "pixels.stealth_pnginfo" for f in report.findings)


def test_stealth_payload_is_scrubbed_from_the_pixels():
    """The pixel channel is reachable, but only by altering pixels.

    Metadata stripping alone must never appear to have removed it, so the LSB
    scrub is what does the work, and it has to leave a valid image behind:
    same dimensions, and no sample moved by more than one step out of 256.
    """
    from markcleanse.detectors.stealth_png import decode_png
    from markcleanse.sanitize import sanitize_bytes

    data = open(os.path.join(FIXTURES, "stealth_novelai.png"), "rb").read()
    result = sanitize_bytes("x.png", data,
                            {"hidden", "privacy", "generator", "provenance"})
    assert result.changed
    after = scan_bytes("x.png", result.data, NO_EXIF)
    assert not any(f.signal.startswith("pixels.") for f in after.findings), \
        "the pixel payload should be gone once the low bits are cleared"

    before_px, after_px = decode_png(data), decode_png(result.data)
    assert before_px[:3] == after_px[:3], "dimensions must not change"
    assert max(abs(a - b) for a, b in zip(before_px[3], after_px[3])) <= 1

    # Metadata categories alone must not touch the pixels: without `hidden`
    # the payload has to survive, or the report would be a lie.
    only_meta = sanitize_bytes("x.png", data, {"privacy", "generator"})
    still = scan_bytes("x.png", only_meta.data or data, NO_EXIF)
    assert any(f.signal == "pixels.stealth_pnginfo" for f in still.findings)


def test_random_alpha_low_bits_are_not_a_payload():
    report = scan_file(os.path.join(FIXTURES, "clean_rgba.png"), NO_EXIF)
    assert report.verdict is Verdict.NO_EVIDENCE, report.basis


def test_ai_image_embedded_in_a_document_is_found():
    """A generated image pasted into a .docx used to be completely invisible."""
    import zipfile
    sd = open(os.path.join(FIXTURES, "sd_a1111.png"), "rb").read()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml",
                   "<w:document><w:body><w:p>Quarterly report</w:p></w:body></w:document>")
        z.writestr("word/media/image1.png", sd)
    report = scan_bytes("nested.docx", buf.getvalue(), NO_EXIF)
    assert report.verdict is Verdict.CONFIRMED_AI, report.basis
    assert any("embedded: word/media/image1.png" in f.summary
               for f in report.findings)


def test_ai_image_embedded_in_a_pdf_is_found():
    jpg = open(os.path.join(FIXTURES, "dalle3_c2pa.jpg"), "rb").read()
    pdf = (b"%PDF-1.7\n2 0 obj\n<< /Subtype /Image /Filter /DCTDecode /Length "
           + str(len(jpg)).encode() + b" >>\nstream\n" + jpg
           + b"\nendstream\nendobj\n%%EOF\n")
    report = scan_bytes("withimage.pdf", pdf, NO_EXIF)
    assert report.verdict is Verdict.CONFIRMED_AI, report.basis
    assert "DALL" in (report.source or "")


def test_pdf_metadata_inside_a_compressed_object_stream():
    """PDF 1.5+ compresses the /Info dict; a raw regex finds nothing."""
    import zlib
    inner = b"<< /Producer (Gamma AI presentation export) /Creator (ChatGPT) >>"
    comp = zlib.compress(inner)
    pdf = (b"%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /Filter /FlateDecode /Length "
           + str(len(comp)).encode() + b" >>\nstream\n" + comp
           + b"\nendstream\nendobj\ntrailer\n<< >>\n%%EOF\n")
    report = scan_bytes("modern.pdf", pdf, NO_EXIF)
    assert report.verdict is Verdict.DECLARED_AI, report.basis
    assert "Gamma" in (report.source or "")


@pytest.mark.parametrize("codepoint", [0x3164, 0x115F, 0xFFA0, 0x1160, 0x2800])
def test_blank_rendering_characters_outside_the_zero_width_block(codepoint):
    """Hangul fillers and the Braille blank hide text just as well as ZWSP."""
    text = "Contract clause" + chr(codepoint) * 40 + " end of clause."
    report = scan_bytes("x.txt", text.encode("utf-8"), NO_EXIF)
    assert report.verdict is not Verdict.NO_EVIDENCE, f"U+{codepoint:04X} missed"


def test_data_appended_after_jpeg_eoi_is_removed():
    from markcleanse.sanitize import sanitize_bytes
    jpg = open(os.path.join(FIXTURES, "dalle3_c2pa.jpg"), "rb").read()
    tampered = jpg + b"HIDDEN-PAYLOAD-AFTER-EOI" * 4
    result = sanitize_bytes("x.jpg", tampered,
                            {"hidden", "privacy", "generator", "provenance"})
    assert result.changed
    assert b"HIDDEN-PAYLOAD-AFTER-EOI" not in result.data


def test_signed_camera_capture_is_not_called_ai():
    """A *verified* manifest is not evidence of AI — it is equally true of a photo.

    Letting `c2pa.verified` count as AI evidence labelled every signed
    photograph AI-GENERATED.
    """
    if not HAVE_SIGNED:
        return
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import make_signed_fixtures as mk
    if not mk.AVAILABLE:
        return
    from cryptography.hazmat.primitives import serialization
    key, leaf, root = mk.make_chain()
    chain = [leaf.public_bytes(serialization.Encoding.DER),
             root.public_bytes(serialization.Encoding.DER)]
    head, tail = mk.base_png(32, 32, b"\x10\x20\x30")
    png = mk.assemble(key, chain, head, tail,
                      generator="Leica Camera AG M11 Firmware 3.0",
                      source_type="digitalCapture")
    report = scan_bytes("cam.png", png, NO_EXIF)
    assert report.verdict is Verdict.SIGNED_CAPTURE, report.basis
    # ...and a self-signed chain must not read as an endorsement.
    verified = next(f for f in report.findings if f.signal == "c2pa.verified")
    assert "UNVERIFIED" in verified.summary or "NOT in your trust list" in verified.summary


def test_redacted_assertion_is_not_reported_as_tampering():
    """C2PA 2.x permits redaction; absence is not evidence of alteration."""
    from markcleanse.c2pa_verify import Verification
    v = Verification(signature_state="valid", binding_state="matched",
                     assertion_state="matched", chain_state="verified")
    v.assertions_absent = ["c2pa.training-mining"]
    assert not v.tampered, "an absent assertion must not read as tampering"
    assert v.cryptographically_valid


def test_absent_hard_binding_does_not_force_a_forged_verdict():
    """Update manifests legitimately carry no hard binding."""
    from markcleanse.c2pa_verify import Verification
    v = Verification(signature_state="valid", binding_state="absent",
                     assertion_state="matched", chain_state="verified")
    assert not v.tampered
    assert v.signature_only
    assert not v.cryptographically_valid


def test_official_c2pa_trust_list_loads_from_pem():
    """--trust must accept the published PEM bundle without conversion."""
    import glob
    from markcleanse.c2pa_verify import TrustStore
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pems = glob.glob(os.path.join(root, "trust", "*.pem"))
    if not pems:
        return                      # trust list not fetched in this checkout
    store = TrustStore.from_file(pems[0])
    assert len(store.fingerprints) > 5
    assert all(len(f) == 64 for f in store.fingerprints)


def test_manifest_without_a_hard_binding_is_not_called_verified():
    """A signature over a claim that binds to nothing proves nothing about the file."""
    from markcleanse.c2pa_verify import Verification
    v = Verification(signature_state="valid", binding_state="absent",
                     assertion_state="matched", chain_state="verified")
    assert not v.cryptographically_valid
    assert v.signature_only


def test_documented_samples_still_behave_as_documented():
    """DETECTION.md is generated from these files; keep them honest.

    Guards against the documentation and the code drifting apart — the failure
    mode where a published catalogue promises behaviour the tool no longer has.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples = os.path.join(root, "samples")
    if not os.path.isdir(samples):
        return

    expected = {
        "c2pa-verified.png": Verdict.CONFIRMED_AI,
        "c2pa-transplanted.png": Verdict.PROVENANCE_INVALID,
        "c2pa-edited-after-signing.png": Verdict.PROVENANCE_INVALID,
        "c2pa-forged-assertion.png": Verdict.PROVENANCE_INVALID,
        "c2pa-boxhash-edited.png": Verdict.PROVENANCE_INVALID,
        "c2pa-avif-transplanted.avif": Verdict.PROVENANCE_INVALID,
        "c2pa-camera-capture.jpg": Verdict.SIGNED_CAPTURE,
        "sd-generation-parameters.png": Verdict.CONFIRMED_AI,
        "stealth-pnginfo.png": Verdict.CONFIRMED_AI,
        "hidden-unicode-tags.txt": Verdict.CONFIRMED_AI,
        "whitespace-interword.txt": Verdict.CONFIRMED_AI,
        "midjourney-xmp.png": Verdict.DECLARED_AI,
        "clean-image.png": Verdict.NO_EVIDENCE,
        "clean-human-prose.md": Verdict.NO_EVIDENCE,
        "clean-two-space-habit.txt": Verdict.NO_EVIDENCE,
        "clean-rgba-random-lsb.png": Verdict.NO_EVIDENCE,
    }
    for name, verdict in expected.items():
        path = os.path.join(samples, name)
        if not os.path.exists(path):
            continue
        # DETECTION.md is generated with heuristics enabled, so it is compared
        # against the same configuration.
        report = scan_file(path, WITH_STYLOMETRY)
        assert report.verdict is verdict, \
            f"samples/{name}: DETECTION.md says {verdict.value}, got " \
            f"{report.verdict.value} — regenerate with tools/build_samples.py"


def test_capture_assertion_suppresses_the_dimension_heuristic():
    """A signed camera assertion outranks 'that size is also a generator size'."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "samples", "c2pa-camera-capture.jpg")
    if not os.path.exists(path):
        return
    report = scan_file(path, NO_EXIF)
    assert not any(f.signal == "heuristic.native_dimensions"
                   for f in report.findings), \
        "the tool must not argue with itself inside one report"


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------

def test_cbor_roundtrip():
    # {"a": 1, "b": [true, null, "x"], "c": -7}
    blob = bytes.fromhex("a3616101616283f5f66178616326")
    assert cbor_loads(blob) == {"a": 1, "b": [True, None, "x"], "c": -7}


def test_cbor_rejects_truncated():
    from markcleanse.cbor_min import CborError
    with pytest.raises((CborError, ValueError)):
        cbor_loads(bytes.fromhex("a3616101"))


def test_tags_decoder():
    encoded = "".join(chr(0xE0000 + ord(c)) for c in "hello")
    assert unicode_wm.decode_tags("x" + encoded + "y") == "hello"


def test_variation_selector_decoder():
    payload = b"\x00\x0f\x10\xff"
    encoded = "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16)
                      for b in payload)
    assert unicode_wm.decode_variation_selectors(encoded) == payload


def test_unsupported_binary_is_not_flagged():
    report = scan_bytes("blob.bin", bytes(range(256)) * 8, NO_EXIF)
    assert report.verdict in (Verdict.UNSUPPORTED, Verdict.NO_EVIDENCE)


def test_scan_survives_garbage():
    """Malformed containers must degrade, never crash a scan."""
    for name, blob in [("bad.png", b"\x89PNG\r\n\x1a\n" + b"\xff" * 200),
                       ("bad.jpg", b"\xff\xd8\xff\xeb\x00\x04JP" + b"\x00" * 50),
                       ("bad.pdf", b"%PDF-1.4\nstream\n\x78\x9c garbage endstream"),
                       ("bad.docx", b"PK\x03\x04" + b"\x00" * 100)]:
        report = scan_bytes(name, blob, NO_EXIF)
        assert report.verdict is not Verdict.ERROR or report.errors


def test_report_is_standalone_and_leads_with_evidence():
    """The report is the thing handed to someone who does not have the tool.

    So it has to survive on its own: no network, the caveats printed inside the
    document, the worst finding first, and the tier letters readable rather than
    the enum's repr.
    """
    import re

    from markcleanse.report import render
    from markcleanse.scan import ScanOptions, scan_paths

    samples = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "samples")
    if not os.path.isdir(samples):
        pytest.skip("samples/ not built")

    result = scan_paths([samples], ScanOptions(use_exiftool=False))
    page = render(result.to_dict(), target="samples")

    # Self-contained: nothing to fetch, so it still renders years from now.
    for external in ("src=", 'href="http', "@import", "<script"):
        assert external not in page, external

    assert "Absence of evidence" in page          # caveats travel with it
    assert "Tier." not in page                    # enum repr, not a label
    assert page.count('class="file"') == result.scanned

    # Most serious first: a forged credential must not sit below clean files.
    order = re.findall(r'class="vd v-[a-z]+">([A-Z?-]+)<', page)
    assert order, order
    assert order[0] in ("PROVENANCE-FORGED", "AI-GENERATED"), order[:3]
    assert order.index("NO-EVIDENCE") > order.index("AI-GENERATED")

    # A verdict nobody can interpret is not a report.
    assert "does not match the file it is attached to" in page


def test_backups_are_not_rescanned():
    """Clean → rescan → clean must converge.

    A backup holds the pre-clean bytes. If a directory walk picks it up, the
    rescan re-reports the markers that were just removed and cleaning it writes
    a backup of the backup — an endless loop that looks like the tool failing
    to remove anything.
    """
    import tempfile

    from markcleanse.scan import ScanOptions, is_markcleanse_artifact, iter_files

    assert is_markcleanse_artifact("notes.txt.markcleanse-backup")
    assert is_markcleanse_artifact("notes.markcleanse-tmp.txt")
    assert not is_markcleanse_artifact("notes.txt")
    assert not is_markcleanse_artifact("backup-plan.md")     # not ours, still scanned

    with tempfile.TemporaryDirectory() as tmp:
        for name in ("a.txt", "a.txt.markcleanse-backup", "a.markcleanse-tmp.txt", "b.txt"):
            with open(os.path.join(tmp, name), "wb") as fh:
                fh.write(b"x")
        found = {os.path.basename(p) for p in iter_files([tmp], ScanOptions())}
        assert found == {"a.txt", "b.txt"}

    # Named explicitly, a backup is still scanned — this filters walks only.
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "a.txt.markcleanse-backup")
        with open(target, "wb") as fh:
            fh.write(b"x")
        assert list(iter_files([target], ScanOptions())) == [target]


def test_web_write_clean_never_clobbers():
    """Cleaning a path-scanned file twice must not overwrite the first copy."""
    import tempfile

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(root, "web"))
    from serve import _write_clean

    with tempfile.TemporaryDirectory() as tmp:
        original = os.path.join(tmp, "note.txt")
        with open(original, "wb") as fh:
            fh.write(b"original")

        first = _write_clean(original, b"one", replace=False)
        second = _write_clean(original, b"two", replace=False)
        assert os.path.basename(first) == "note.clean.txt"
        assert os.path.basename(second) == "note.clean-2.txt"
        with open(first, "rb") as fh:
            assert fh.read() == b"one"          # not clobbered by the second run
        with open(original, "rb") as fh:
            assert fh.read() == b"original"     # untouched without replace=True

        assert _write_clean(original, b"three", replace=True) == original
        with open(original, "rb") as fh:
            assert fh.read() == b"three"
        with open(original + ".markcleanse-backup", "rb") as fh:
            assert fh.read() == b"original"     # in-place keeps an undo
        _write_clean(original, b"four", replace=True)
        with open(original + ".markcleanse-backup-2", "rb") as fh:
            assert fh.read() == b"three"        # and never overwrites the undo
        # The atomic temp file must never survive either path.
        assert not any(n.startswith("note.markcleanse-tmp") for n in os.listdir(tmp))


# ---------------------------------------------------------------------------
# Command line
#
# These exist because the terminal renderer was once replaced wholesale by the
# HTML one and nothing noticed: `markcleanse <path>` and `markcleanse sanitize` both died
# on an AttributeError at the first line of output, while every detection test
# above still passed. Detection logic is not the product on its own — the four
# entry points below have to actually run.
# ---------------------------------------------------------------------------

import contextlib                                                     # noqa: E402
import json as _json                                                  # noqa: E402
import tempfile                                                       # noqa: E402

from markcleanse.cli import main as cli_main                               # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(PROJECT_ROOT, "samples")

#: exiftool is optional and slow; the CLI tests are about the CLI, not about
#: metadata coverage, so they never depend on whether it is installed.
BASE_ARGS = ["--no-exiftool", "-q"]


def _run_cli(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli_main(argv)
    return code, out.getvalue()


def test_cli_scan_prints_a_table():
    code, out = _run_cli([SAMPLES] + BASE_ARGS)
    assert code == 0
    assert "VERDICT" in out and "EVIDENCE" in out
    assert "AI-GENERATED" in out
    assert "PROVENANCE-FORGED" in out
    assert "scanned" in out.splitlines()[-1] or "scanned" in out
    # The table is one line per flagged file, not a wall of evidence.
    assert "sd-generation-parameters.png" in out


def test_cli_scan_reports_clean_honestly():
    """A clean scan must never read as 'a human made this'."""
    code, out = _run_cli([os.path.join(SAMPLES, "clean-image.png")] + BASE_ARGS)
    assert code == 0
    assert "1 clean" in out
    assert "no markers survived" in out


def test_cli_verbose_prints_the_evidence():
    target = os.path.join(SAMPLES, "c2pa-transplanted.png")
    code, out = _run_cli([target, "-v"] + BASE_ARGS)
    assert code == 0
    assert "integrity.c2pa.binding_mismatch" in out
    # The C2PA check block, not a raw dict dump.
    assert "signature:" in out and "binding:" in out and "chain:" in out
    assert "mismatched" in out
    assert "{'" not in out, "evidence printed as a repr instead of fields"


def test_cli_exports_json_csv_and_markdown():
    import csv as _csv

    with tempfile.TemporaryDirectory() as tmp:
        js = os.path.join(tmp, "r.json")
        cs = os.path.join(tmp, "r.csv")
        md = os.path.join(tmp, "r.md")
        code, _ = _run_cli([SAMPLES, "--json", js, "--csv", cs, "--md", md]
                           + BASE_ARGS)
        assert code == 0

        with open(js, encoding="utf-8") as fh:
            data = _json.load(fh)
        assert data["summary"]["scanned"] > 0
        assert data["files"] and data["files"][0]["verdict"]

        with open(cs, newline="", encoding="utf-8") as fh:
            rows = list(_csv.reader(fh))
        assert rows[0][:4] == ["path", "verdict", "tier", "attributed_to"]
        assert len(rows) == data["summary"]["scanned"] + 1

        with open(md, encoding="utf-8") as fh:
            text = fh.read()
        assert "| File | Verdict |" in text
        assert "never proof" in text          # the tier legend travels with it


def test_cli_fail_on_gates_a_pipeline():
    clean = os.path.join(SAMPLES, "clean-image.png")
    dirty = os.path.join(SAMPLES, "hidden-zero-width.txt")
    assert _run_cli([clean, "--fail-on", "any"] + BASE_ARGS)[0] == 0
    assert _run_cli([dirty, "--fail-on", "any"] + BASE_ARGS)[0] == 1
    assert _run_cli([dirty, "--fail-on", "confirmed"] + BASE_ARGS)[0] == 1
    assert _run_cli([dirty] + BASE_ARGS)[0] == 0        # default never fails


def test_cli_sanitize_dry_run_writes_nothing():
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "note.txt")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("hello​world " + "and some more prose. " * 5)
        before = sorted(os.listdir(tmp))
        code, out = _run_cli(["sanitize", target, "--dry-run"])
        assert code == 0
        assert "dry run" in out
        assert sorted(os.listdir(tmp)) == before


def test_cli_report_writes_html():
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "report.html")
        code, out = _run_cli(["report", os.path.join(SAMPLES, "c2pa-verified.png"),
                              "-o", dest])
        assert code == 0
        with open(dest, encoding="utf-8") as fh:
            html_text = fh.read()
        assert "<html" in html_text.lower()
        assert "AI-GENERATED" in html_text


def test_cli_rejects_unknown_detector():
    code, _ = _run_cli([SAMPLES, "--only", "nope"] + BASE_ARGS)
    assert code == 2


# ---------------------------------------------------------------------------
# Stylometry is opt-in
# ---------------------------------------------------------------------------

def test_stylometry_is_off_by_default():
    """A default scan reports evidence, not an opinion about someone's prose."""
    path = os.path.join(FIXTURES, "llm_prose.md")
    assert scan_file(path, NO_EXIF).verdict is Verdict.NO_EVIDENCE
    assert scan_file(path, WITH_STYLOMETRY).verdict is Verdict.SUSPECT


def test_assistant_leakage_survives_stylometry_being_off():
    """Tier B leakage is verbatim chat output, not a guess — it is not opt-in.

    It ships in the same detector as the prose score, so turning the opinion
    off must not take the evidence beside it.
    """
    report = scan_file(os.path.join(FIXTURES, "leakage.txt"), NO_EXIF)
    assert report.verdict is Verdict.DECLARED_AI
    assert report.best_tier is Tier.B
    assert not any(f.tier is Tier.C for f in report.findings)


def test_only_stylometry_implies_the_opt_in():
    """Naming it explicitly is consent; making the user pass two flags is a trap."""
    opts = ScanOptions(use_exiftool=False, only={"stylometry"})
    report = scan_file(os.path.join(FIXTURES, "llm_prose.md"), opts)
    assert report.verdict is Verdict.SUSPECT


def test_cli_stylometry_flag():
    path = os.path.join(FIXTURES, "llm_prose.md")
    code, out = _run_cli([path] + BASE_ARGS)
    assert code == 0 and "SUSPECT" not in out
    code, out = _run_cli([path, "--stylometry"] + BASE_ARGS)
    assert code == 0 and "SUSPECT" in out
    # The retired flag stays accepted so old scripts do not start exiting 2.
    assert _run_cli([path, "--no-heuristics"] + BASE_ARGS)[0] == 0


if __name__ == "__main__":
    import _minipytest
    raise SystemExit(_minipytest.run(sys.modules[__name__]))
