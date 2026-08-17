"""C2PA manifest verification.

Four independent checks, ordered by how much they are worth in an argument:

1. **Asset hash binding** (`c2pa.hash.data`) — the claim contains a SHA-256 over
   the file's own bytes with the manifest region excluded. This is what proves
   the manifest belongs to *this* file. It is what catches a manifest lifted
   from a real AI image and pasted onto a photograph, or vice versa. Pure
   hashlib, so it always runs.

2. **Assertion hashes** — the claim lists every assertion with its hash. This
   catches edits to the manifest's contents (changing the generator name,
   deleting the "AI-generated" action) after signing.

3. **COSE signature** — the claim was signed by the private key belonging to the
   leaf certificate. Catches a wholesale forgery.

4. **Certificate chain** — leaf to root, each certificate signed by the next,
   validity dates checked, CA constraints enforced.

What is deliberately *not* claimed
----------------------------------

A verified chain says the manifest was signed by whoever holds that key. It
does not say that key belongs to a legitimate signer, unless its root is in a
trust list you supplied — anyone can generate a self-signed chain claiming to be
anyone. `trust_state` reports this separately and honestly, and the default is
"no-trust-list", not "trusted".

Timestamp tokens (RFC 3161) are parsed for display but their own signatures are
not validated, so a chain that expired after signing is reported as expired.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import asn1, crypto_min
from .cbor_min import CborError, dumps as cbor_dumps, loads as cbor_loads

# COSE header labels
COSE_ALG = 1
COSE_X5CHAIN = 33
COSE_SIGTST = "sigTst"          # C2PA timestamp header (string label)
COSE_SIGTST_V2 = "sigTst2"

#: COSE algorithm identifier -> (scheme, hash)
COSE_ALGS = {
    -7:  ("ecdsa", "sha256"),      # ES256
    -35: ("ecdsa", "sha384"),      # ES384
    -36: ("ecdsa", "sha512"),      # ES512
    -37: ("rsa-pss", "sha256"),    # PS256
    -38: ("rsa-pss", "sha384"),    # PS384
    -39: ("rsa-pss", "sha512"),    # PS512
    -257: ("rsa-pkcs1", "sha256"),  # RS256 (legacy chains)
    -8:  ("ed25519", "sha512"),    # EdDSA
}

HASH_FUNCS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384,
              "sha512": hashlib.sha512}


@dataclass
class Verification:
    """The outcome of verifying one manifest."""

    #: Assertions referenced by the claim but absent from the store. C2PA 2.x
    #: permits redaction, so absence is NOT evidence of tampering — only a hash
    #: that disagrees is. Reported separately so the two never get conflated.
    assertions_absent: list[str] = field(default_factory=list)

    # binding: matched | mismatched | unsupported | unchecked | absent
    binding_state: str = "unchecked"
    binding_detail: str = ""

    # assertions: matched | mismatched | unchecked
    assertion_state: str = "unchecked"
    assertions_checked: int = 0
    assertions_failed: list[str] = field(default_factory=list)

    # signature: valid | invalid | unsupported | unchecked
    signature_state: str = "unchecked"
    signature_detail: str = ""
    algorithm: str = ""

    # chain: verified | broken | incomplete | unchecked
    chain_state: str = "unchecked"
    chain_detail: str = ""
    chain: list[asn1.Certificate] = field(default_factory=list)
    expired: bool = False

    #: Revocation status of the signing credential (see markcleanse.ocsp).
    revocation: object | None = None

    #: C2PA certificate-profile violations of the signing credential. A
    #: credential problem, not an integrity one: it says the signer is out of
    #: policy, not that the file was altered.
    profile_problems: list[str] = field(default_factory=list)

    # trust: trusted | untrusted-root | no-trust-list
    trust_state: str = "no-trust-list"
    root_fingerprint: str = ""

    signed_at: str = ""
    backend: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def tampered(self) -> bool:
        """Positive evidence that the manifest does not describe this file."""
        return (self.binding_state == "mismatched"
                or self.assertion_state == "mismatched"
                or self.signature_state == "invalid")

    @property
    def expired_unproven(self) -> bool:
        """Signed with an expired credential and nothing proves it predates that.

        A timestamp token would settle it, but markcleanse does not validate the
        token's own signature, so a bare `signed_at` cannot be leaned on.
        c2patool reports this case as Invalid; matching that judgement is the
        conservative call.
        """
        return self.expired and not self.signed_at

    @property
    def cryptographically_valid(self) -> bool:
        """Fully checked and every check passed.

        A missing hard binding does NOT qualify. C2PA requires one, and without
        it a valid signature says only "somebody signed this claim", not "this
        claim is about this file" — which is precisely the gap a transplanted
        manifest exploits.
        """
        return (self.signature_state == "valid"
                and self.binding_state == "matched"
                and self.assertion_state in ("matched", "unchecked")
                and self.chain_state in ("verified", "incomplete")
                and not self.expired_unproven
                and not self.profile_problems
                and not self.revoked)

    @property
    def revoked(self) -> bool:
        return bool(self.revocation and self.revocation.state == "revoked")

    @property
    def signature_only(self) -> bool:
        """Signature is valid but the manifest asserts no binding at all.

        Distinct from `binding_unchecked`: here the manifest genuinely lacks a
        hard binding, which is a defect in the manifest. There, we simply could
        not perform the check — a limitation of this tool, not of the file.
        """
        return self.signature_state == "valid" and self.binding_state == "absent"

    @property
    def binding_unchecked(self) -> bool:
        return (self.signature_state == "valid"
                and self.binding_state in ("unsupported", "unchecked"))

    def summary(self) -> str:
        bits = []
        if self.signature_state == "valid":
            bits.append("signature valid")
        elif self.signature_state == "invalid":
            bits.append("SIGNATURE INVALID")
        elif self.signature_state != "unchecked":
            bits.append(f"signature {self.signature_state}")

        if self.binding_state == "matched":
            bits.append("bound to this file")
        elif self.binding_state == "mismatched":
            bits.append("DOES NOT MATCH THIS FILE")
        elif self.binding_state == "unsupported":
            bits.append("binding type unsupported")

        if self.assertion_state == "mismatched":
            bits.append(f"{len(self.assertions_failed)} assertion(s) altered")
        if self.assertions_absent:
            bits.append(f"{len(self.assertions_absent)} assertion(s) absent "
                        f"(possibly redacted)")
        elif self.assertion_state == "matched":
            bits.append(f"{self.assertions_checked} assertions intact")

        if self.chain_state == "verified":
            bits.append(f"chain of {len(self.chain)} verified")
        elif self.chain_state == "broken":
            bits.append("CHAIN BROKEN")

        if self.expired:
            bits.append("certificate expired")
        if self.profile_problems:
            bits.append(f"{len(self.profile_problems)} credential-profile "
                        f"violation(s)")
        if self.revocation and self.revocation.state == "revoked":
            bits.append("CREDENTIAL REVOKED")
        elif (self.revocation and self.revocation.state == "good"
                and self.revocation.signature_verified):
            bits.append("not revoked")
        if self.trust_state == "trusted":
            bits.append("root trusted")
        elif self.trust_state == "untrusted-root":
            bits.append("root NOT in trust list")
        return "; ".join(bits) or "not verified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding": self.binding_state,
            "binding_detail": self.binding_detail,
            "assertions": self.assertion_state,
            "assertions_checked": self.assertions_checked,
            "assertions_failed": self.assertions_failed[:8],
            "assertions_absent": self.assertions_absent[:8],
            "signature": self.signature_state,
            "signature_detail": self.signature_detail,
            "algorithm": self.algorithm,
            "chain": self.chain_state,
            "chain_detail": self.chain_detail,
            "chain_subjects": [c.describe() for c in self.chain],
            "expired": self.expired,
            "profile_problems": self.profile_problems[:6],
            "revocation": self.revocation.to_dict() if self.revocation else None,
            "trust": self.trust_state,
            "root_fingerprint": self.root_fingerprint,
            "signed_at": self.signed_at,
            "crypto_backend": self.backend,
            "errors": self.errors[:8],
        }


# ---------------------------------------------------------------------------
# Trust anchors
# ---------------------------------------------------------------------------

class TrustStore:
    """SHA-256 fingerprints of certificates you have decided to trust."""

    def __init__(self, fingerprints: set[str] | None = None):
        self.fingerprints = {f.lower().replace(":", "").strip()
                             for f in (fingerprints or set()) if f.strip()}

    def __bool__(self) -> bool:
        return bool(self.fingerprints)

    def trusts(self, cert: asn1.Certificate) -> bool:
        return cert.fingerprint in self.fingerprints

    @classmethod
    def from_file(cls, path: str) -> "TrustStore":
        """Load anchors from a PEM bundle or a list of SHA-256 fingerprints.

        PEM is detected rather than declared, so the official C2PA trust list
        can be passed straight through with no conversion step.
        """
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        if "BEGIN CERTIFICATE" in text:
            return cls(cls._fingerprints_from_pem(text))
        anchors: set[str] = set()
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                anchors.add(line)
        return cls(anchors)

    @staticmethod
    def _fingerprints_from_pem(text: str) -> set[str]:
        import base64
        import re
        out: set[str] = set()
        for block in re.findall(
                r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                text, re.S):
            try:
                der = base64.b64decode(re.sub(r"\s", "", block))
            except Exception:
                continue
            if der:
                out.add(hashlib.sha256(der).hexdigest())
        return out

    @classmethod
    def official(cls, root: str) -> "TrustStore | None":
        """The C2PA Conformance Program trust list, if it has been fetched.

        Not bundled: a trust list is a security decision with an expiry date,
        and shipping a stale copy in a git repo is how a revoked CA stays
        trusted. `tools/update-trust-list.sh` fetches the current one.
        """
        import os
        anchors: set[str] = set()
        for name in ("C2PA-TRUST-LIST.pem", "C2PA-TSA-TRUST-LIST.pem"):
            path = os.path.join(root, "trust", name)
            if os.path.exists(path):
                anchors |= cls.from_file(path).fingerprints
        return cls(anchors) if anchors else None


# ---------------------------------------------------------------------------
# Manifest navigation
# ---------------------------------------------------------------------------

def _find(boxes, predicate):
    for box in boxes:
        if predicate(box):
            return box
    return None


def _content_bytes(box) -> bytes:
    return b"".join(payload for _t, payload in box.content)


def _decode_content(box) -> Any:
    for ctype, payload in box.content:
        if ctype == b"cbor":
            try:
                return cbor_loads(payload)
            except (CborError, Exception):
                return None
        if ctype == b"json":
            import json
            try:
                return json.loads(payload.decode("utf-8", "replace"))
            except Exception:
                return None
    return None


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------

def active_manifest(roots: list) -> list:
    """The boxes belonging to the manifest that describes this asset.

    A store usually holds several manifests: the active one plus an *ingredient*
    manifest for every asset that was consumed to make it. They contain
    identically-labelled boxes (`c2pa.claim`, `c2pa.hash.data`, ...), so
    flattening the whole store and picking the first match verifies an
    ingredient's claim against the wrong file and reports a bogus tamper.
    Per the C2PA spec the last manifest in the store is the active one.
    """
    store = None
    for root in roots:
        if root.label == "c2pa":
            store = root
            break
    if store is None:
        store = roots[0] if roots else None
    if store is None:
        return []

    manifests = [c for c in store.children if c.label] or [store]
    return list(manifests[-1].walk())


def verify_manifest(roots: list, asset: bytes, asset_complete: bool,
                    trust: TrustStore | None = None,
                    fmt: str = "", revocation: str = "stapled") -> Verification:
    """Run every available check over the active manifest in a store."""
    result = Verification(backend=crypto_min.backend())
    trust = trust or TrustStore()
    boxes = active_manifest(roots)
    if not boxes:
        result.errors.append("no manifest boxes")
        return result

    claim_box = _find(boxes, lambda b: b.label.startswith("c2pa.claim"))
    sig_box = _find(boxes, lambda b: b.label.startswith("c2pa.signature"))
    claim = _decode_content(claim_box) if claim_box else None

    if claim_box is None or not isinstance(claim, dict):
        result.errors.append("no parsable claim box")
        return result

    _check_assertions(result, boxes, claim)
    _check_binding(result, boxes, asset, asset_complete, fmt)

    if sig_box is None:
        result.signature_state = "unchecked"
        result.errors.append("no signature box")
        return result

    _check_signature(result, _content_bytes(sig_box), _content_bytes(claim_box),
                     trust, revocation)
    return result


def _hashed_uri_list(claim: dict) -> list[dict]:
    out: list[dict] = []
    for key in ("assertions", "created_assertions", "gathered_assertions"):
        value = claim.get(key)
        if isinstance(value, list):
            out.extend(v for v in value if isinstance(v, dict))
    return out


def _check_assertions(result: Verification, boxes: list, claim: dict) -> None:
    entries = _hashed_uri_list(claim)
    if not entries:
        result.assertion_state = "unchecked"
        return

    by_label = {b.label: b for b in boxes if b.label}
    checked = 0
    for entry in entries:
        url = entry.get("url") or entry.get("uri") or ""
        expected = entry.get("hash")
        alg = (entry.get("alg") or "sha256").lower()
        if not isinstance(expected, bytes) or alg not in HASH_FUNCS:
            continue
        label = str(url).rsplit("/", 1)[-1]
        box = by_label.get(label)
        if box is None:
            # Redaction is a legitimate C2PA operation; treating a removed
            # assertion as an altered one would report a conforming file as
            # forged.
            result.assertions_absent.append(label)
            continue

        # `box.hashable` is the encoding real producers use; the other two are
        # tried so a non-conforming writer degrades to a pass rather than a
        # false accusation of tampering.
        candidates = [box.hashable, _content_bytes(box), box.raw_bytes]
        digest_fn = HASH_FUNCS[alg]
        if any(c and digest_fn(c).digest() == expected for c in candidates):
            checked += 1
        else:
            result.assertions_failed.append(label)

    result.assertions_checked = checked
    redacted = claim.get("redacted_assertions")
    if isinstance(redacted, list) and redacted:
        result.errors.append(f"claim redacts {len(redacted)} assertion(s)")
    if result.assertions_failed:
        result.assertion_state = "mismatched"
    elif checked:
        result.assertion_state = "matched"


def _check_binding(result: Verification, boxes: list, asset: bytes,
                   asset_complete: bool, fmt: str = "") -> None:
    box = _find(boxes, lambda b: b.label.startswith("c2pa.hash."))
    if box is None:
        result.binding_state = "absent"
        result.binding_detail = "manifest contains no hard binding to the asset"
        return

    if box.label.startswith("c2pa.hash.bmff"):
        suffix = box.label.rsplit(".", 1)[-1]
        version = 1
        if suffix.startswith("v") and suffix[1:].isdigit():
            version = int(suffix[1:])
        if version > 3:
            # Never compute a digest for an algorithm revision we do not know:
            # a wrong digest reads as forgery, which is the worst output here.
            result.binding_state = "unsupported"
            result.binding_detail = (
                f"{box.label}: BMFF hash version {version} is newer than this "
                f"implementation, so the binding was NOT checked")
            return
        _check_bmff_binding(result, box, asset, asset_complete, version)
        return

    if box.label.startswith("c2pa.hash.boxes"):
        _check_boxes_binding(result, box, asset, asset_complete, fmt)
        return

    if box.label.startswith("c2pa.hash.collection"):
        result.binding_state = "unsupported"
        result.binding_detail = f"{box.label} binding is not implemented"
        return

    if not asset_complete:
        result.binding_state = "unchecked"
        result.binding_detail = "file was too large to read in full"
        return

    data = _decode_content(box)
    if not isinstance(data, dict):
        result.binding_state = "unchecked"
        result.binding_detail = "hash assertion could not be decoded"
        return

    expected = data.get("hash")
    alg = str(data.get("alg") or "sha256").lower()
    if not isinstance(expected, bytes) or alg not in HASH_FUNCS:
        result.binding_state = "unchecked"
        result.binding_detail = f"unsupported hash algorithm {alg!r}"
        return

    exclusions = []
    for item in data.get("exclusions") or []:
        if isinstance(item, dict):
            start, length = item.get("start"), item.get("length")
            if isinstance(start, int) and isinstance(length, int) and length >= 0:
                exclusions.append((start, start + length))
    exclusions.sort()

    digest = HASH_FUNCS[alg]()
    cursor = 0
    for start, end in exclusions:
        start = max(0, min(start, len(asset)))
        end = max(start, min(end, len(asset)))
        if start > cursor:
            digest.update(asset[cursor:start])
        cursor = max(cursor, end)
    digest.update(asset[cursor:])

    if digest.digest() == expected:
        result.binding_state = "matched"
        result.binding_detail = (f"{alg} over {len(asset):,} bytes with "
                                 f"{len(exclusions)} excluded range(s)")
    else:
        result.binding_state = "mismatched"
        result.binding_detail = (
            f"{alg} over the asset does not match the value in the claim "
            f"({len(exclusions)} excluded range(s)) — the manifest describes "
            f"different bytes than this file contains")


def _check_boxes_binding(result: Verification, box, asset: bytes,
                         asset_complete: bool, fmt: str) -> None:
    """Verify a `c2pa.hash.boxes` (BoxHash) binding.

    The assertion lists runs of the container's own boxes by name, each with
    its own digest. Names are consumed from the asset's box map **in order**,
    so a reordered or inserted box breaks verification even if every individual
    digest would still match.

    Two kinds of entry are hashed by nobody: the run named `C2PA` (the
    manifest's own bytes, which cannot hash themselves) and anything flagged
    `excluded`.
    """
    from . import boxmap

    if not asset_complete:
        result.binding_state = "unchecked"
        result.binding_detail = "file was too large to read in full"
        return

    data = _decode_content(box)
    entries = data.get("boxes") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        result.binding_state = "unchecked"
        result.binding_detail = "box hash assertion could not be decoded"
        return

    source = boxmap.box_map(asset, fmt)
    if not source:
        result.binding_state = "unsupported"
        result.binding_detail = f"no box map is defined for {fmt} files"
        return

    # The reference skips a leading synthetic `PNGh` when the assertion does
    # not open with it.
    index = 0
    first_named = next((e.get("names") for e in entries
                        if isinstance(e, dict) and e.get("names")), None)
    if source[0].name == "PNGh" and first_named and first_named[0] != "PNGh":
        index = 1

    checked = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        names = entry.get("names")
        if not isinstance(names, list) or not names:
            continue

        start = end = None
        skip = bool(entry.get("excluded"))
        for name in names:
            if index >= len(source):
                result.binding_state = "mismatched"
                result.binding_detail = (
                    f"box hash names run past the end of the file "
                    f"(expected '{name}')")
                return
            found = source[index]
            if found.name != name:
                result.binding_state = "mismatched"
                result.binding_detail = (
                    f"box order differs from the claim: expected '{name}', "
                    f"found '{found.name}' — a box was inserted, removed or "
                    f"reordered after signing")
                return
            if name == boxmap.C2PA_BOXHASH:
                skip = True
            start = found.start if start is None else start
            end = found.end
            index += 1

        if skip or start is None:
            continue

        alg = str(entry.get("alg") or data.get("alg") or "sha256").lower()
        expected = entry.get("hash")
        if not isinstance(expected, bytes) or alg not in HASH_FUNCS:
            continue
        if HASH_FUNCS[alg](asset[start:end]).digest() != expected:
            result.binding_state = "mismatched"
            result.binding_detail = (
                f"box hash mismatch over {'+'.join(names[:4])} "
                f"({end - start:,} bytes) — those bytes changed after signing")
            return
        checked += 1

    result.binding_state = "matched" if checked else "unchecked"
    result.binding_detail = (f"box hash over {checked} box run(s) of "
                             f"{len(source)} named boxes")


def _check_bmff_binding(result: Verification, box, asset: bytes,
                        asset_complete: bool, version: int = 1) -> None:
    """Verify a `c2pa.hash.bmff` binding (AVIF, HEIC, HEIF, MP4).

    Unlike the flat byte ranges of `c2pa.hash.data`, a BMFF binding excludes
    *boxes*, addressed by an xpath such as `/uuid` and narrowed by predicates:
    a `data` list pinning bytes at an offset inside the box (this is how the
    C2PA manifest's own uuid box is singled out from any other uuid box), an
    exact `length`, or `subset` ranges to exclude only part of a box.

    Without this, a manifest could be lifted from one AVIF onto another and
    nothing would notice — which is precisely the check `hash.data` provides
    for JPEG and PNG.
    """
    from . import bmff

    if not asset_complete:
        result.binding_state = "unchecked"
        result.binding_detail = "file was too large to read in full"
        return

    data = _decode_content(box)
    if not isinstance(data, dict):
        result.binding_state = "unchecked"
        result.binding_detail = "BMFF hash assertion could not be decoded"
        return

    expected = data.get("hash")
    alg = str(data.get("alg") or "sha256").lower()
    if not isinstance(expected, bytes) or alg not in HASH_FUNCS:
        result.binding_state = "unchecked"
        result.binding_detail = f"unsupported hash algorithm {alg!r}"
        return

    boxes = bmff.flatten(bmff.walk(asset))
    if not boxes:
        result.binding_state = "unchecked"
        result.binding_detail = "no parsable BMFF box structure"
        return

    exclusions = [e for e in (data.get("exclusions") or []) if isinstance(e, dict)]
    ranges: list[tuple[int, int]] = []
    matched = 0
    for rule in exclusions:
        for target in boxes:
            if not _bmff_rule_matches(rule, target, asset):
                continue
            matched += 1
            subsets = [s for s in (rule.get("subset") or []) if isinstance(s, dict)]
            if not subsets:
                ranges.append((target.offset, target.end))
                continue
            for subset in subsets:
                start = subset.get("offset")
                length = subset.get("length")
                if not isinstance(start, int):
                    continue
                begin = target.offset + start
                # length 0 means "to the end of the box"
                stop = target.end if not length else min(begin + length, target.end)
                ranges.append((begin, stop))

    included = _complement(ranges, len(asset))

    # BMFF hash v2 and v3 additionally fold each surviving top-level box's own
    # offset into the digest, as an 8-byte big-endian value emitted immediately
    # before that box's bytes. Without it the digest is simply wrong, and a
    # correctly signed file reads as forged. (Recovered from c2pa-rs:
    # `bmff_to_jumbf_exclusions` marks each retained top-level box, and the
    # hasher emits `start.to_be_bytes()` for those markers.)
    markers: list[int] = []
    if version >= 2:
        top_level = bmff.walk(asset)
        fully_excluded = {start for start, stop in ranges
                          if any(b.offset == start and b.end == stop
                                 for b in top_level)}
        markers = sorted(b.offset for b in top_level
                         if b.offset not in fully_excluded)
        included = _split_at(included, markers)

    digest = HASH_FUNCS[alg]()
    emitted = set()
    for start, stop in included:
        if start in markers and start not in emitted:
            digest.update(struct.pack(">Q", start))
            emitted.add(start)
        digest.update(asset[start:stop])

    described = ", ".join(str(r.get("xpath")) for r in exclusions[:4]) or "none"
    if digest.digest() == expected:
        result.binding_state = "matched"
        result.binding_detail = (f"BMFF v{version} {alg} over {len(asset):,} "
                                 f"bytes, excluding {matched} box(es) [{described}]")
    else:
        result.binding_state = "mismatched"
        result.binding_detail = (
            f"BMFF v{version} {alg} does not match the value in the claim (excluded "
            f"{matched} box(es) [{described}]) — the manifest describes "
            f"different bytes than this file contains")


def _complement(ranges: list[tuple[int, int]], total: int) -> list[tuple[int, int]]:
    """The byte ranges *not* covered by `ranges`, in file order."""
    out: list[tuple[int, int]] = []
    cursor = 0
    for start, stop in sorted(ranges):
        start = max(0, min(start, total))
        stop = max(start, min(stop, total))
        if start > cursor:
            out.append((cursor, start))
        cursor = max(cursor, stop)
    if cursor < total:
        out.append((cursor, total))
    return out


def _split_at(ranges: list[tuple[int, int]], points: list[int]) -> list[tuple[int, int]]:
    """Split ranges so every point in `points` begins a range."""
    out = list(ranges)
    for point in points:
        for i, (start, stop) in enumerate(out):
            if start < point < stop:
                out[i:i + 1] = [(start, point), (point, stop)]
                break
    return sorted(out)


def _bmff_rule_matches(rule: dict, box, asset: bytes) -> bool:
    xpath = rule.get("xpath")
    if not isinstance(xpath, str) or box.path != xpath:
        return False

    length = rule.get("length")
    if isinstance(length, int) and box.size != length:
        return False

    for entry in rule.get("data") or []:
        if not isinstance(entry, dict):
            continue
        offset, value = entry.get("offset"), entry.get("value")
        if not isinstance(offset, int) or not isinstance(value, (bytes, bytearray)):
            continue
        start = box.offset + offset
        if asset[start:start + len(value)] != bytes(value):
            return False

    version = rule.get("version")
    if isinstance(version, int):
        at = box.offset + box.header_len
        if at >= len(asset) or asset[at] != version:
            return False

    flags = rule.get("flags")
    if isinstance(flags, (bytes, bytearray)) and len(flags) == 3:
        at = box.offset + box.header_len + 1
        if asset[at:at + 3] != bytes(flags):
            return False

    return True


def _check_signature(result: Verification, sig_bytes: bytes, claim_bytes: bytes,
                     trust: TrustStore, revocation: str = "stapled") -> None:
    try:
        cose = cbor_loads(sig_bytes)
    except Exception as exc:
        result.signature_state = "unchecked"
        result.errors.append(f"COSE not decodable: {exc}")
        return

    if not isinstance(cose, list) or len(cose) != 4:
        result.signature_state = "unchecked"
        result.errors.append("signature is not a COSE_Sign1 structure")
        return

    protected_bytes, unprotected, payload, signature = cose
    if not isinstance(protected_bytes, bytes) or not isinstance(signature, bytes):
        result.signature_state = "unchecked"
        result.errors.append("malformed COSE_Sign1 fields")
        return

    try:
        protected = cbor_loads(protected_bytes) if protected_bytes else {}
    except Exception:
        protected = {}
    if not isinstance(protected, dict):
        protected = {}
    headers = {**(unprotected if isinstance(unprotected, dict) else {}), **protected}

    alg_id = headers.get(COSE_ALG)
    if alg_id not in COSE_ALGS:
        result.signature_state = "unsupported"
        result.signature_detail = f"COSE algorithm {alg_id!r} is not supported"
        return
    scheme, hash_name = COSE_ALGS[alg_id]
    result.algorithm = {(-7): "ES256", (-35): "ES384", (-36): "ES512",
                        (-37): "PS256", (-38): "PS384", (-39): "PS512",
                        (-257): "RS256", (-8): "EdDSA"}.get(alg_id, str(alg_id))

    # --- certificate chain --------------------------------------------
    chain_der = headers.get(COSE_X5CHAIN)
    if isinstance(chain_der, bytes):
        chain_der = [chain_der]
    if not isinstance(chain_der, list) or not chain_der:
        result.signature_state = "unchecked"
        result.errors.append("no x5chain in the COSE headers")
        return

    for der in chain_der:
        if not isinstance(der, bytes):
            continue
        try:
            result.chain.append(asn1.parse_certificate(der))
        except asn1.Asn1Error as exc:
            result.errors.append(f"unparsable certificate: {exc}")
    if not result.chain:
        result.signature_state = "unchecked"
        result.errors.append("no parsable certificates in the chain")
        return

    _validate_chain(result, trust)
    _read_timestamp(result, headers)
    _check_revocation(result, headers, revocation)

    # --- the signature itself ------------------------------------------
    leaf = result.chain[0]
    if leaf.public_key is None:
        result.signature_state = "unchecked"
        result.errors.append("leaf certificate has no usable public key")
        return

    # C2PA detaches the payload: the claim bytes are supplied externally.
    candidates = []
    if isinstance(payload, bytes) and payload:
        candidates.append(payload)
    candidates.append(claim_bytes)

    for candidate in candidates:
        sig_structure = cbor_dumps(["Signature1", protected_bytes, b"", candidate])
        if crypto_min.verify(leaf.public_key, scheme, hash_name,
                             sig_structure, signature, raw_ecdsa=True):
            result.signature_state = "valid"
            result.signature_detail = (
                f"{result.algorithm} over the claim, verified against "
                f"'{leaf.describe()}' using {result.backend}")
            return

    result.signature_state = "invalid"
    result.signature_detail = (
        f"{result.algorithm} signature does not verify against the public key in "
        f"'{leaf.describe()}' — the manifest was altered after signing, or the "
        f"certificate does not belong to the signer")


def _validate_chain(result: Verification, trust: TrustStore) -> None:
    from . import cert_profile

    now = datetime.now(timezone.utc)
    problems: list[str] = []

    # The profile constrains the signing credential — the leaf. Intermediates
    # are governed by the trust list, not by this check.
    if result.chain:
        result.profile_problems = cert_profile.check(result.chain[0])

    for cert in result.chain:
        if cert.not_after and now > cert.not_after:
            result.expired = True
        if cert.errors:
            problems.extend(cert.errors)

    # Each certificate must be signed by the next one along.
    verified_links = 0
    for i in range(len(result.chain) - 1):
        child, parent = result.chain[i], result.chain[i + 1]
        if parent.public_key is None:
            problems.append(f"{parent.describe()} has no usable public key")
            break
        if parent.is_ca is False:
            problems.append(f"{parent.describe()} is not marked as a CA")
        scheme_hash = asn1.SIG_ALG_OIDS.get(child.sig_algorithm)
        if scheme_hash is None:
            problems.append(f"unsupported certificate signature algorithm "
                            f"{child.sig_algorithm} on {child.describe()}")
            break
        scheme, hash_name = scheme_hash
        if crypto_min.verify(parent.public_key, scheme, hash_name,
                             child.tbs_der, child.signature):
            verified_links += 1
        else:
            problems.append(f"{child.describe()} is not signed by "
                            f"{parent.describe()}")
            break

    root = result.chain[-1]
    result.root_fingerprint = root.fingerprint

    if trust:
        result.trust_state = "trusted" if any(trust.trusts(c) for c in result.chain) \
            else "untrusted-root"
    else:
        result.trust_state = "no-trust-list"

    if problems:
        result.chain_state = "broken"
        result.chain_detail = "; ".join(problems[:3])
    elif len(result.chain) == 1:
        result.chain_state = "incomplete"
        result.chain_detail = ("only the leaf certificate was supplied; nothing "
                               "to validate it against")
    else:
        result.chain_state = "verified"
        result.chain_detail = (
            f"{verified_links} link(s) verified, "
            f"{result.chain[0].describe()} -> {root.describe()}")


def _check_revocation(result: Verification, headers: dict, mode: str) -> None:
    """Stapled OCSP first; the network only when explicitly asked for."""
    from . import ocsp

    if mode == "off" or not result.chain:
        return

    stapled: list[bytes] = []
    rvals = headers.get("rVals")
    if isinstance(rvals, dict):
        for value in rvals.get("ocspVals") or []:
            if isinstance(value, (bytes, bytearray)):
                stapled.append(bytes(value))

    try:
        outcome = ocsp.check_stapled(stapled, result.chain[0], result.chain)
        if mode == "online" and outcome.state in ("absent", "unparsed", "unknown"):
            outcome = ocsp.check_online(result.chain[0], result.chain)
    except Exception as exc:                     # never let this break a scan
        result.errors.append(f"revocation check failed: {exc}")
        return
    result.revocation = outcome


def _read_timestamp(result: Verification, headers: dict) -> None:
    """Surface the RFC 3161 timestamp if one is present (not itself validated)."""
    token = headers.get(COSE_SIGTST) or headers.get(COSE_SIGTST_V2)
    if not token:
        return
    blob = token if isinstance(token, bytes) else _first_bytes(token)
    if not blob:
        return
    # Rather than parse the full TSTInfo, pull the first GeneralizedTime, which
    # is the genTime field. Display only — it drives no decision.
    for i in range(len(blob) - 2):
        if blob[i] == 0x18 and 13 <= blob[i + 1] <= 20:
            raw = blob[i + 2:i + 2 + blob[i + 1]]
            try:
                text = raw.decode("ascii")
                if text.endswith("Z") and text[:8].isdigit():
                    result.signed_at = (f"{text[0:4]}-{text[4:6]}-{text[6:8]}T"
                                        f"{text[8:10]}:{text[10:12]}:{text[12:14]}Z")
                    return
            except UnicodeDecodeError:
                continue


def _first_bytes(obj: Any, depth: int = 0) -> bytes | None:
    if depth > 6:
        return None
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, list):
        for item in obj:
            found = _first_bytes(item, depth + 1)
            if found:
                return found
    if isinstance(obj, dict):
        for item in obj.values():
            found = _first_bytes(item, depth + 1)
            if found:
                return found
    return None
