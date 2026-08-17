"""Build genuinely signed C2PA fixtures, and tampered copies of them.

Everything here is synthetic — its own key, its own self-signed CA — so the
test suite exercises the full verification path without shipping anybody's real
photographs or borrowing a vendor's certificate.

Four fixtures:

* ``c2pa_signed.png``      valid: signature, assertion hashes and asset binding all check out
* ``c2pa_transplant.png``  that manifest pasted onto a different image (binding must fail)
* ``c2pa_edited.png``      valid manifest, image bytes altered afterwards (binding must fail)
* ``c2pa_forged.png``      assertion rewritten to claim a different generator (hashes must fail)

Requires `cryptography` to *generate*. Verifying them needs nothing.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from markcleanse.cbor_min import dumps as cbor_dumps           # noqa: E402

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as ecutils
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    AVAILABLE = True
except ImportError:                                        # pragma: no cover
    AVAILABLE = False


# ---------------------------------------------------------------------------
# JUMBF construction
# ---------------------------------------------------------------------------

def box(btype: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + btype + payload


#: JUMBF type UUIDs. A C2PA box is identified by this 16-byte UUID in its
#: description box, not by its label — markcleanse keys off labels and so tolerates
#: zeros here, but the reference implementation does not, and fixtures that the
#: reference rejects are worth much less as tests.
def _juuid(tag: bytes) -> bytes:
    return tag + bytes.fromhex("00110010800000aa00389b71")


UUID_STORE      = _juuid(b"c2pa")   # manifest store
UUID_MANIFEST   = _juuid(b"c2ma")   # a manifest
UUID_ASSERTIONS = _juuid(b"c2as")   # assertion store
UUID_CLAIM      = _juuid(b"c2cl")   # claim
UUID_SIGNATURE  = _juuid(b"c2cs")   # claim signature
UUID_CBOR       = _juuid(b"cbor")   # CBOR content box


def jumd(label: str, uuid: bytes = UUID_CBOR) -> bytes:
    return box(b"jumd", uuid + b"\x03" + label.encode() + b"\x00")


def superbox(label: str, children: bytes, uuid: bytes = UUID_CBOR) -> bytes:
    return box(b"jumb", jumd(label, uuid) + children)


def hashed_uri(url: str, payload_box: bytes) -> dict:
    """A C2PA hashed-uri. The digest covers the JUMBF payload, header excluded."""
    return {"url": url, "alg": "sha256",
            "hash": hashlib.sha256(payload_box[8:]).digest()}


# ---------------------------------------------------------------------------
# PNG plumbing
# ---------------------------------------------------------------------------

def png_chunk(ctype: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + ctype + payload
            + struct.pack(">I", hashlib.crc32 if False else _crc(ctype + payload)))


def _crc(data: bytes) -> int:
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF


def base_png(width: int, height: int, colour: bytes) -> tuple[bytes, bytes]:
    """Return (head, tail) so a caBX chunk can be spliced between them."""
    import zlib
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + colour * width for _ in range(height))
    head = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr)
    tail = png_chunk(b"IDAT", zlib.compress(raw)) + png_chunk(b"IEND", b"")
    return head, tail


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

#: `make_chain` returns the leaf key, but OCSP responses are signed by the
#: *root*, so it is stashed here rather than widening the public signature.
_ROOT_KEYS: dict[int, object] = {}


def make_chain():
    """A self-signed root and a leaf signed by it."""
    now = datetime.now(timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "markcleanse Test Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "markcleanse fixtures"),
    ])
    root_ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    root = (x509.CertificateBuilder()
            .subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(root_ski, critical=False)
            .sign(root_key, hashes.SHA256()))

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "markcleanse Test Signer"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "markcleanse fixtures")]))
            .issuer_name(root_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            # The C2PA certificate profile requires an end-entity signing cert
            # to carry emailProtection or documentSigning EKU, plus an
            # authorityKeyIdentifier; without them both this tool and the
            # reference report signingCredential.invalid.
            .add_extension(x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier
                           .from_issuer_subject_key_identifier(root_ski),
                           critical=False)
            .sign(root_key, hashes.SHA256()))
    _ROOT_KEYS[id(root)] = root_key
    return leaf_key, leaf, root


def make_ocsp(leaf, root, root_key, revoked: bool = False) -> bytes:
    """A signed OCSP response for `leaf`, as C2PA staples into `rVals`."""
    from cryptography.x509 import ocsp as _ocsp
    now = datetime.now(timezone.utc)
    builder = _ocsp.OCSPResponseBuilder().add_response(
        cert=leaf, issuer=root, algorithm=hashes.SHA1(),
        cert_status=(_ocsp.OCSPCertStatus.REVOKED if revoked
                     else _ocsp.OCSPCertStatus.GOOD),
        this_update=now - timedelta(hours=1),
        next_update=now + timedelta(days=7),
        revocation_time=(now - timedelta(days=2)) if revoked else None,
        revocation_reason=(x509.ReasonFlags.key_compromise if revoked else None),
    ).responder_id(_ocsp.OCSPResponderEncoding.NAME, root)
    return builder.sign(root_key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER)


def cose_sign1(key, chain_der: list[bytes], payload: bytes,
               unprotected: dict | None = None) -> bytes:
    """A detached-payload COSE_Sign1, the shape C2PA uses."""
    protected = cbor_dumps({1: -7, 33: chain_der})
    sig_structure = cbor_dumps(["Signature1", protected, b"", payload])
    der = key.sign(sig_structure, ec.ECDSA(hashes.SHA256()))
    r, s = ecutils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    # CBOR tag 18 (COSE_Sign1). Real producers emit it and the reference
    # implementation requires it; markcleanse's decoder discards tags and so
    # accepted the untagged form, which is how this went unnoticed.
    return b"\xd2" + cbor_dumps([protected, unprotected or {}, None, raw])


# ---------------------------------------------------------------------------
# Manifest assembly
# ---------------------------------------------------------------------------

def build_manifest(key, chain_der, asset_hash: bytes, exclusions: list[dict],
                   generator: str = "markcleanse Fixture Generator 1.0",
                   source_type: str = "trainedAlgorithmicMedia",
                   ocsp_der: bytes | None = None) -> bytes:
    actions = cbor_dumps({"actions": [{
        "action": "c2pa.created",
        "softwareAgent": generator,
        "digitalSourceType":
            f"http://cv.iptc.org/newscodes/digitalsourcetype/{source_type}",
    }]})
    # `pad` is required by the DataHash schema — the reference rejects the
    # assertion without it, even though the field carries no information.
    hash_data = cbor_dumps({
        "exclusions": exclusions, "alg": "sha256",
        "hash": asset_hash, "pad": b"\x00" * 8, "name": "jumbf manifest",
    })

    actions_box = superbox("c2pa.actions", box(b"cbor", actions), UUID_CBOR)
    hash_box = superbox("c2pa.hash.data", box(b"cbor", hash_data), UUID_CBOR)
    assertions_box = superbox("c2pa.assertions", actions_box + hash_box,
                              UUID_ASSERTIONS)

    # C2PA v1 requires dc:format, instanceID, claim_generator, signature,
    # assertions and alg. Omitting any of them makes the reference
    # implementation reject the claim outright.
    claim = cbor_dumps({
        "dc:title": "markcleanse fixture",
        "dc:format": "image/png",
        "instanceID": "xmp:iid:markcleanse-0000-0000-0000-000000000001",
        "claim_generator": generator,
        "claim_generator_info": [{"name": "markcleanse fixtures", "version": "1.0"}],
        "alg": "sha256",
        "signature": "self#jumbf=c2pa.signature",
        "assertions": [
            hashed_uri("self#jumbf=c2pa.assertions/c2pa.actions", actions_box),
            hashed_uri("self#jumbf=c2pa.assertions/c2pa.hash.data", hash_box),
        ],
    })
    claim_box = superbox("c2pa.claim", box(b"cbor", claim), UUID_CLAIM)
    unprotected = {"rVals": {"ocspVals": [ocsp_der]}} if ocsp_der else None
    sig_box = superbox("c2pa.signature",
                       box(b"cbor", cose_sign1(key, chain_der, claim,
                                               unprotected)),
                       UUID_SIGNATURE)

    manifest = superbox("urn:uuid:markcleanse-fixture",
                        assertions_box + claim_box + sig_box, UUID_MANIFEST)
    return superbox("c2pa", manifest, UUID_STORE)


def build_boxhash_manifest(key, chain_der, runs: list[dict],
                           generator: str) -> bytes:
    """A manifest whose hard binding is `c2pa.hash.boxes`."""
    boxes = cbor_dumps({"boxes": runs, "alg": "sha256"})
    actions = cbor_dumps({"actions": [{
        "action": "c2pa.created",
        "softwareAgent": generator,
        "digitalSourceType":
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
    }]})
    actions_box = superbox("c2pa.actions", box(b"cbor", actions), UUID_CBOR)
    boxes_box = superbox("c2pa.hash.boxes", box(b"cbor", boxes), UUID_CBOR)
    assertions_box = superbox("c2pa.assertions", actions_box + boxes_box,
                              UUID_ASSERTIONS)
    claim = cbor_dumps({
        "dc:title": "markcleanse boxhash fixture",
        "dc:format": "image/png",
        "instanceID": "xmp:iid:markcleanse-0000-0000-0000-000000000003",
        "claim_generator": generator,
        "claim_generator_info": [{"name": "markcleanse fixtures", "version": "1.0"}],
        "alg": "sha256",
        "signature": "self#jumbf=c2pa.signature",
        "assertions": [
            hashed_uri("self#jumbf=c2pa.assertions/c2pa.actions", actions_box),
            hashed_uri("self#jumbf=c2pa.assertions/c2pa.hash.boxes", boxes_box),
        ],
    })
    claim_box = superbox("c2pa.claim", box(b"cbor", claim), UUID_CLAIM)
    sig_box = superbox("c2pa.signature",
                       box(b"cbor", cose_sign1(key, chain_der, claim)),
                       UUID_SIGNATURE)
    manifest = superbox("urn:uuid:markcleanse-boxhash",
                        assertions_box + claim_box + sig_box, UUID_MANIFEST)
    return superbox("c2pa", manifest, UUID_STORE)


def assemble_boxhash(key, chain_der, head: bytes, tail: bytes) -> bytes:
    """A PNG bound by BoxHash, in the reference's minimal three-run form.

    The runs are: everything before the manifest chunk, the manifest chunk
    itself (never hashed — it cannot hash its own bytes), and everything after.
    """
    import hashlib as _h
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from markcleanse import boxmap

    # `hash` and `pad` are required on every BoxMap, including the C2PA run
    # whose hash is never used — the reference refuses to decode without them.
    empty = {"names": ["C2PA"], "hash": b"", "pad": b""}
    runs = [{"names": ["PNGh"], "hash": b"\x00" * 32, "pad": b""},
            dict(empty),
            {"names": ["IDAT"], "hash": b"\x00" * 32, "pad": b""}]
    png = b""
    for _ in range(6):
        store = build_boxhash_manifest(key, chain_der, runs,
                                       "markcleanse Fixture Generator 1.0")
        png = head + png_chunk(b"caBX", store) + tail
        boxes = boxmap.box_map(png, "png")
        names = [b.name for b in boxes]
        cut = names.index("C2PA")
        before, after = boxes[:cut], boxes[cut + 1:]
        new_runs = [
            {"names": [b.name for b in before],
             "hash": _h.sha256(png[before[0].start:before[-1].end]).digest(),
             "pad": b""},
            dict(empty),
            {"names": [b.name for b in after],
             "hash": _h.sha256(png[after[0].start:after[-1].end]).digest(),
             "pad": b""},
        ]
        if new_runs == runs:
            return png
        runs = new_runs
    return png


def assemble(key, chain_der, head: bytes, tail: bytes, **kwargs) -> bytes:
    """Build a PNG whose manifest correctly binds to its own final bytes.

    The binding hash covers the file with the caBX chunk excluded, but the
    chunk's offset and length depend on the manifest that contains the hash.
    Every field that varies has a fixed width, so iterating converges on the
    second pass; the loop just proves it rather than assuming it.
    """
    asset_hash = b"\x00" * 32
    exclusions = [{"start": 0, "length": 0}]
    previous = None
    for _ in range(6):
        store = build_manifest(key, chain_der, asset_hash, exclusions, **kwargs)
        chunk = png_chunk(b"caBX", store)
        start, length = len(head), len(chunk)
        png = head + chunk + tail
        digest = hashlib.sha256()
        digest.update(png[:start])
        digest.update(png[start + length:])
        new_hash, new_excl = digest.digest(), [{"start": start, "length": length}]
        if (new_hash, new_excl) == (asset_hash, exclusions) and previous == png:
            return png
        asset_hash, exclusions, previous = new_hash, new_excl, png
    return previous


# ---------------------------------------------------------------------------

def main(outdir: str) -> None:
    if not AVAILABLE:
        print("  (skipping signed C2PA fixtures — `cryptography` not installed)")
        return

    key, leaf, root = make_chain()
    chain_der = [leaf.public_bytes(serialization.Encoding.DER),
                 root.public_bytes(serialization.Encoding.DER)]

    head, tail = base_png(48, 48, b"\x40\x80\xc0")
    signed = assemble(key, chain_der, head, tail)
    _write(outdir, "c2pa_signed.png", signed)

    # Transplant: the same manifest chunk moved onto a different image.
    other_head, other_tail = base_png(48, 48, b"\xc0\x40\x40")
    start = len(head)
    end = len(signed) - len(tail)
    manifest_chunk = signed[start:end]
    _write(outdir, "c2pa_transplant.png",
           other_head + manifest_chunk + other_tail)

    # Edited after signing: one pixel byte of the image data changed.
    edited = bytearray(signed)
    idat = edited.find(b"IDAT")
    edited[idat + 8] ^= 0xFF
    _write(outdir, "c2pa_edited.png", bytes(edited))

    # Forged: rewrite the generator name inside the signed assertion.
    for name, revoked in (("c2pa_ocsp_good.png", False),
                          ("c2pa_ocsp_revoked.png", True)):
        der = make_ocsp(leaf, root, _ROOT_KEYS[id(root)], revoked)
        _write(outdir, name, assemble(key, chain_der, head, tail, ocsp_der=der))

    boxhash = assemble_boxhash(key, chain_der, head, tail)
    _write(outdir, "c2pa_boxhash.png", boxhash)
    # Flip a byte inside the real IDAT chunk. `find(b"IDAT")` would hit the
    # box name inside the manifest's own CBOR and corrupt the assertion rather
    # than the image, which tests nothing.
    from markcleanse import boxmap as _bm
    idat = next(b for b in _bm.box_map(boxhash, "png") if b.name == "IDAT")
    edited_box = bytearray(boxhash)
    edited_box[idat.start + 9] ^= 0xFF
    _write(outdir, "c2pa_boxhash_edited.png", bytes(edited_box))

    # The substitute must be byte-for-byte the same length as the original.
    # This string lives inside length-prefixed CBOR, so a shorter one shifts
    # every following field and the manifest stops parsing at all — which
    # would test the parser, not the hash. The point of this fixture is a
    # manifest that still parses perfectly and fails *only* on the assertion
    # hash, so the length is asserted rather than assumed. (A project rename
    # silently broke this once.)
    real_name = b"markcleanse Fixture Generator 1.0"
    forged_name = b"Totally Legitimate Camera Co Ltd."
    assert len(forged_name) == len(real_name), (
        f"forged generator name must be exactly {len(real_name)} bytes to keep "
        f"the CBOR lengths valid, got {len(forged_name)}")

    forged = signed.replace(real_name, forged_name)
    if forged != signed:
        _write(outdir, "c2pa_forged.png", forged)

    with open(os.path.join(outdir, "trust_anchors.txt"), "w") as fh:
        fh.write("# SHA-256 fingerprints trusted by the fixture tests\n")
        fh.write(hashlib.sha256(chain_der[1]).hexdigest() + "  # markcleanse Test Root CA\n")
    print("  trust_anchors.txt")


def _write(outdir: str, name: str, data: bytes) -> None:
    with open(os.path.join(outdir, name), "wb") as fh:
        fh.write(data)
    print(f"  {name}  ({len(data):,} bytes)")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixtures")
    os.makedirs(target, exist_ok=True)
    main(target)
