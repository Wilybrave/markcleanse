"""Build signed AVIF/HEIC fixtures, and tampered copies.

The base images are encoded by ffmpeg (libaom-av1), so these are *real*
containers with real coded image data — not hand-rolled approximations. The
C2PA manifest is then appended as a top-level `uuid` box and bound with a
`c2pa.hash.bmff` assertion.

The manifest box is appended after `mdat` on purpose: `iloc` extents are
absolute file offsets, so inserting anything before the media data would
invalidate every item in the file.

Fixtures:
  c2pa_bmff.avif         valid — signature, assertions and BMFF binding all pass
  c2pa_bmff_transplant.avif  the same manifest appended to a different image
  c2pa_bmff.heic         same manifest shape in an HEIC-branded container

Needs ffmpeg with libaom-av1, plus `cryptography` for signing. Skips cleanly
when either is missing.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from markcleanse import bmff                                    # noqa: E402
from markcleanse.cbor_min import dumps as cbor_dumps            # noqa: E402
from markcleanse.detectors.c2pa import C2PA_UUID                # noqa: E402

import make_signed_fixtures as mk                          # noqa: E402


def ffmpeg_available() -> bool:
    if not shutil.which("ffmpeg"):
        return False
    probe = subprocess.run(["ffmpeg", "-hide_banner", "-encoders"],
                           capture_output=True, text=True)
    return "libaom-av1" in probe.stdout


def make_avif(pattern: str, size: int = 64) -> bytes | None:
    """Encode a real AVIF still with ffmpeg."""
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "x.avif")
        cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error",
               "-f", "lavfi", "-i", f"{pattern}=size={size}x{size}:duration=1:rate=1",
               "-frames:v", "1", "-c:v", "libaom-av1", "-still-picture", "1",
               "-f", "avif", out, "-y"]
        if subprocess.run(cmd, capture_output=True).returncode != 0:
            return None
        try:
            with open(out, "rb") as fh:
                return fh.read()
        except OSError:
            return None


def make_mp4() -> bytes | None:
    """A real HEVC-in-MP4 clip — ISOBMFF with a full moov/trak/mdia tree."""
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "x.mp4")
        cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error",
               "-f", "lavfi", "-i", "testsrc=size=64x64:duration=1:rate=5",
               "-c:v", "libx265", "-tag:v", "hvc1", out, "-y"]
        if subprocess.run(cmd, capture_output=True).returncode != 0:
            return None
        try:
            with open(out, "rb") as fh:
                return fh.read()
        except OSError:
            return None


def rebrand_heic(avif: bytes) -> bytes:
    """Swap the ftyp brands so the file presents as HEIC.

    The coded payload stays AV1, which no part of markcleanse decodes — this
    exercises the HEIC sniffing and box-walking path, nothing more.
    """
    boxes = bmff.walk(avif)
    ftyp = next((b for b in boxes if b.type == b"ftyp"), None)
    if ftyp is None:
        return avif
    body = bytearray(avif[ftyp.offset:ftyp.end])
    body[8:12] = b"heic"                       # major_brand
    for i in range(16, len(body) - 3, 4):      # compatible_brands
        if body[i:i + 4] == b"avif":
            body[i:i + 4] = b"heic"
    return avif[:ftyp.offset] + bytes(body) + avif[ftyp.end:]


def uuid_box(store: bytes) -> bytes:
    """The C2PA BMFF box: UUID, a purpose string, a merkle offset, then the store.

    Writing UUID+store directly (which markcleanse's tolerant parser happily read)
    is not the spec shape, and the reference implementation reports "No claim
    found" for it.
    """
    payload = C2PA_UUID + b"manifest\x00" + struct.pack(">Q", 0) + store
    return struct.pack(">I", len(payload) + 8) + b"uuid" + payload


def build_manifest(key, chain_der, asset_hash: bytes, exclusions: list[dict],
                   generator: str) -> bytes:
    """A manifest whose hard binding is `c2pa.hash.bmff`."""
    actions = cbor_dumps({"actions": [{
        "action": "c2pa.created",
        "softwareAgent": generator,
        "digitalSourceType":
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
    }]})
    bmff_hash = cbor_dumps({
        "exclusions": exclusions, "alg": "sha256",
        "hash": asset_hash, "pad": b"\x00" * 8, "name": "bmff hash",
    })

    actions_box = mk.superbox("c2pa.actions", mk.box(b"cbor", actions), mk.UUID_CBOR)
    hash_box = mk.superbox("c2pa.hash.bmff.v3", mk.box(b"cbor", bmff_hash), mk.UUID_CBOR)
    assertions_box = mk.superbox("c2pa.assertions", actions_box + hash_box,
                                 mk.UUID_ASSERTIONS)

    claim = cbor_dumps({
        "dc:title": "markcleanse bmff fixture",
        "dc:format": "image/avif",
        "instanceID": "xmp:iid:markcleanse-0000-0000-0000-000000000002",
        "claim_generator": generator,
        "claim_generator_info": [{"name": "markcleanse fixtures", "version": "1.0"}],
        "alg": "sha256",
        "signature": "self#jumbf=c2pa.signature",
        "assertions": [
            mk.hashed_uri("self#jumbf=c2pa.assertions/c2pa.actions", actions_box),
            mk.hashed_uri("self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3", hash_box),
        ],
    })
    claim_box = mk.superbox("c2pa.claim", mk.box(b"cbor", claim), mk.UUID_CLAIM)
    sig_box = mk.superbox("c2pa.signature",
                          mk.box(b"cbor", mk.cose_sign1(key, chain_der, claim)),
                          mk.UUID_SIGNATURE)
    manifest = mk.superbox("urn:uuid:markcleanse-bmff",
                           assertions_box + claim_box + sig_box, mk.UUID_MANIFEST)
    return mk.superbox("c2pa", manifest, mk.UUID_STORE)


def exclusions_for(base_len: int) -> list[dict]:
    """Exclude the manifest's own uuid box, pinned by its UUID bytes.

    `/uuid` alone would also match any other uuid box in the file, so the
    `data` predicate anchors it to the C2PA UUID at offset 8 — which is what
    real producers do.
    """
    return [{"xpath": "/uuid", "data": [{"offset": 8, "value": C2PA_UUID}]}]


def bmff_v2_digest(data: bytes, excluded_offsets: set[int]) -> bytes:
    """The BMFF hash v2/v3 digest: each retained top-level box is preceded by
    its own 8-byte big-endian offset.

    Recovered from c2pa-rs and confirmed byte-for-byte against a file signed by
    c2patool itself. A plain hash of the remaining bytes — the obvious reading
    of the spec — produces a different digest and would mark valid files as
    forged.
    """
    digest = hashlib.sha256()
    for box in bmff.walk(data):
        if box.offset in excluded_offsets:
            continue
        digest.update(struct.pack(">Q", box.offset))
        digest.update(data[box.offset:box.end])
    return digest.digest()


def assemble(key, chain_der, base: bytes, generator: str) -> bytes:
    """Append a manifest bound to `base` with a v3 BMFF hash.

    The manifest box goes last, so the excluded region is exactly the tail and
    the digest over the retained boxes is stable — no iteration needed, unlike
    the PNG case where the chunk sits in the middle of the file.
    """
    exclusions = exclusions_for(len(base))
    asset_hash = bmff_v2_digest(base, excluded_offsets=set())
    store = build_manifest(key, chain_der, asset_hash, exclusions, generator)
    return base + uuid_box(store)


def main(outdir: str) -> None:
    if not mk.AVAILABLE:
        print("  (skipping BMFF fixtures — `cryptography` not installed)")
        return
    if not ffmpeg_available():
        print("  (skipping BMFF fixtures — ffmpeg with libaom-av1 not available)")
        return

    base = make_avif("testsrc")
    other = make_avif("smptebars")
    if not base or not other:
        print("  (skipping BMFF fixtures — ffmpeg could not encode AVIF)")
        return

    from cryptography.hazmat.primitives import serialization
    key, leaf, root = mk.make_chain()
    chain = [leaf.public_bytes(serialization.Encoding.DER),
             root.public_bytes(serialization.Encoding.DER)]

    signed = assemble(key, chain, base, "markcleanse BMFF Fixture Generator 1.0")
    _write(outdir, "c2pa_bmff.avif", signed)

    # The identical manifest box appended to a different image.
    manifest_box = signed[len(base):]
    _write(outdir, "c2pa_bmff_transplant.avif", other + manifest_box)

    heic_base = rebrand_heic(base)
    _write(outdir, "c2pa_bmff.heic",
           assemble(key, chain, heic_base, "markcleanse BMFF Fixture Generator 1.0"))

    _write(outdir, "clean.avif", base)

    # A real MP4: genuine BMFF with moov/trak/mdia nesting that the AVIF
    # layout never exercises.
    mp4 = make_mp4()
    if mp4:
        _write(outdir, "c2pa_bmff.mp4",
               assemble(key, chain, mp4, "markcleanse BMFF Fixture Generator 1.0"))

    # A manifest placed BEFORE the media data. Detection must still work;
    # sanitising must refuse to remove it, because dropping it would shift
    # every absolute offset in the file.
    boxes = bmff.walk(base)
    ftyp_end = next(b.end for b in boxes if b.type == b"ftyp")
    exclusions = exclusions_for(0)
    placeholder = build_manifest(key, chain, b"\x00" * 32, exclusions,
                                 "markcleanse BMFF Fixture Generator 1.0")
    box_len = len(uuid_box(placeholder))
    # Inserting mid-file shifts every later box, and the v2/v3 digest folds in
    # those offsets — so the hash must be computed over the shifted layout, not
    # over `base`.
    shifted = base[:ftyp_end] + uuid_box(placeholder) + base[ftyp_end:]
    excluded = {b.offset for b in bmff.walk(shifted) if b.type == b"uuid"}
    digest = bmff_v2_digest(shifted, excluded)
    store = build_manifest(key, chain, digest, exclusions,
                           "markcleanse BMFF Fixture Generator 1.0")
    early = uuid_box(store)
    if len(early) == box_len:
        _write(outdir, "c2pa_bmff_early.avif",
               base[:ftyp_end] + early + base[ftyp_end:])


def _write(outdir: str, name: str, data: bytes) -> None:
    with open(os.path.join(outdir, name), "wb") as fh:
        fh.write(data)
    print(f"  {name}  ({len(data):,} bytes)")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixtures")
    os.makedirs(target, exist_ok=True)
    main(target)
