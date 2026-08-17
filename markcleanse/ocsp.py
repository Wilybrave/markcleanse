"""OCSP revocation checking (RFC 6960).

C2PA signers staple an OCSP response into the COSE unprotected header
(``rVals`` → ``ocspVals``), so the question "was this credential revoked?" can
usually be answered **from the file alone**. That matters more than
convenience: a live OCSP query tells the certificate authority — and anyone on
the network path — exactly which certificate you are examining and when, which
is an information leak about an investigation. Offline is the default here for
that reason, not merely because it is easier.

What is parsed and checked:

* the OCSP response status and each ``SingleResponse`` (good / revoked /
  unknown), with revocation time and reason;
* whether the response actually covers *this* certificate, matched on serial
  number;
* the responder's signature over ``tbsResponseData``, verified against the
  responder certificate embedded in the response or against the issuing CA
  from the manifest's own chain.

Unverified status is reported as unverified. A stapled "good" that nobody
signed for is worth very little — anyone assembling a forged manifest can
staple whatever they like.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from . import asn1, crypto_min

OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1"

STATUS_NAMES = {0: "good", 1: "revoked", 2: "unknown"}

#: RFC 5280 §5.3.1 CRLReason values.
REVOCATION_REASONS = {
    0: "unspecified", 1: "key compromise", 2: "CA compromise",
    3: "affiliation changed", 4: "superseded", 5: "cessation of operation",
    6: "certificate hold", 8: "removed from CRL", 9: "privilege withdrawn",
    10: "AA compromise",
}


@dataclass
class CertStatus:
    serial: int
    status: str                       # good | revoked | unknown
    revoked_at: datetime | None = None
    reason: str = ""
    this_update: datetime | None = None
    next_update: datetime | None = None


@dataclass
class OcspResult:
    state: str = "absent"             # good | revoked | unknown | absent | unparsed
    detail: str = ""
    signature_verified: bool = False
    responder: str = ""
    checked_serial: int = 0
    statuses: list[CertStatus] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.statuses is None:
            self.statuses = []

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "detail": self.detail,
            "signature_verified": self.signature_verified,
            "responder": self.responder,
        }


def _gtime(tlv: asn1.TLV) -> datetime | None:
    return asn1._parse_time(tlv)


def parse_basic_response(der: bytes) -> tuple[list[CertStatus], bytes, str,
                                              bytes, list[asn1.Certificate]]:
    """Return (statuses, tbs_der, sig_alg_oid, signature, embedded certs)."""
    top = asn1.read_tlv(der)
    parts = asn1.children(top)

    # An OCSPResponse wraps the BasicOCSPResponse; a bare BasicOCSPResponse is
    # also seen in the wild, so accept either.
    basic = top
    if parts and parts[0].tag == 0x0A:                      # responseStatus
        if int.from_bytes(parts[0].data, "big") != 0:
            raise ValueError("OCSP responder returned a non-successful status")
        holder = next((p for p in parts if p.tag == 0xA0), None)
        if holder is None:
            raise ValueError("OCSP response carries no responseBytes")
        inner = asn1.children(holder)[0]
        fields = asn1.children(inner)
        if len(fields) < 2 or asn1.decode_oid(fields[0].data) != OID_OCSP_BASIC:
            raise ValueError("unsupported OCSP response type")
        basic = asn1.read_tlv(fields[1].data)

    bparts = asn1.children(basic)
    if len(bparts) < 3:
        raise ValueError("malformed BasicOCSPResponse")

    tbs, alg, sig = bparts[0], bparts[1], bparts[2]
    tbs_der = basic.data[tbs.start:tbs.end]
    sig_alg = asn1.decode_oid(asn1.children(alg)[0].data) if asn1.children(alg) else ""
    signature = sig.data[1:] if sig.data[:1] == b"\x00" else sig.data

    certs: list[asn1.Certificate] = []
    for extra in bparts[3:]:
        if extra.tag != 0xA0:
            continue
        # [0] EXPLICIT wraps a SEQUENCE OF Certificate, so descend twice and
        # slice relative to that inner sequence — not to the [0] wrapper.
        wrappers = asn1.children(extra)
        if not wrappers:
            continue
        seq = wrappers[0]
        for item in asn1.children(seq):
            try:
                certs.append(asn1.parse_certificate(seq.data[item.start:item.end]))
            except Exception:
                continue

    return _parse_response_data(tbs), tbs_der, sig_alg, signature, certs


def _parse_response_data(tbs: asn1.TLV) -> list[CertStatus]:
    out: list[CertStatus] = []
    fields = asn1.children(tbs)
    responses = None
    for field in fields:
        if field.tag == 0x30:            # SEQUENCE OF SingleResponse
            responses = field
    if responses is None:
        return out

    for single in asn1.children(responses):
        if single.tag != 0x30:
            continue
        items = asn1.children(single)
        if len(items) < 3:
            continue
        cert_id = asn1.children(items[0])
        serial = 0
        if cert_id:
            for item in cert_id:
                if item.tag == 0x02:
                    serial = int.from_bytes(item.data, "big")
        status_tlv = items[1]
        code = status_tlv.tag & 0x1F
        status = STATUS_NAMES.get(code, "unknown")

        revoked_at = None
        reason = ""
        if code == 1:                    # revoked [1] IMPLICIT RevokedInfo
            info = asn1.children(status_tlv)
            if info:
                revoked_at = _gtime(info[0])
            for extra in info[1:]:
                if extra.tag == 0xA0:
                    inner = asn1.children(extra)
                    if inner and inner[0].data:
                        reason = REVOCATION_REASONS.get(
                            inner[0].data[0], f"reason {inner[0].data[0]}")

        this_update = _gtime(items[2]) if len(items) > 2 else None
        next_update = None
        for extra in items[3:]:
            if extra.tag == 0xA0:
                inner = asn1.children(extra)
                if inner:
                    next_update = _gtime(inner[0])
        out.append(CertStatus(serial=serial, status=status,
                              revoked_at=revoked_at, reason=reason,
                              this_update=this_update, next_update=next_update))
    return out


def check_stapled(responses: list[bytes], leaf: asn1.Certificate,
                  chain: list[asn1.Certificate]) -> OcspResult:
    """Evaluate stapled OCSP responses against the signing certificate."""
    result = OcspResult(checked_serial=leaf.serial)
    if not responses:
        result.detail = "no OCSP response is stapled to the manifest"
        return result

    for der in responses:
        if not isinstance(der, (bytes, bytearray)):
            continue
        try:
            statuses, tbs, sig_alg, signature, certs = parse_basic_response(bytes(der))
        except Exception as exc:
            result.state = "unparsed"
            result.detail = f"OCSP response could not be parsed: {exc}"
            continue

        match = next((s for s in statuses if s.serial == leaf.serial), None)
        if match is None:
            continue                     # this response covers a different cert

        result.statuses = statuses
        result.state = match.status
        result.signature_verified = _verify_response(tbs, sig_alg, signature,
                                                     certs, chain)
        result.responder = (certs[0].describe() if certs
                            else (chain[1].describe() if len(chain) > 1 else ""))

        if match.status == "revoked":
            when = match.revoked_at.strftime("%Y-%m-%d") if match.revoked_at else "?"
            result.detail = (f"certificate was REVOKED on {when}"
                             + (f" ({match.reason})" if match.reason else ""))
        elif match.status == "good":
            asof = match.this_update.strftime("%Y-%m-%d") if match.this_update else "?"
            result.detail = f"not revoked as of {asof}"
        else:
            result.detail = "responder does not know this certificate"

        if not result.signature_verified:
            result.detail += " — but the OCSP response signature was NOT verified"
        return result

    if result.state == "absent":
        result.detail = ("stapled OCSP responses do not cover the signing "
                         "certificate")
    return result


# ---------------------------------------------------------------------------
# Live OCSP — opt-in only
# ---------------------------------------------------------------------------

def _der(tag: int, payload: bytes) -> bytes:
    if len(payload) < 0x80:
        return bytes([tag, len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + payload


def build_request(leaf: asn1.Certificate, issuer: asn1.Certificate) -> bytes:
    """A minimal RFC 6960 OCSPRequest for one certificate.

    CertID identifies the certificate by hashes of the *issuer's* name and key
    plus the serial — never by the certificate itself, which is why the issuer
    is required here.
    """
    import hashlib

    key_bits = issuer.public_key.spki_der if issuer.public_key else b""
    # issuerKeyHash is over the BIT STRING contents of the issuer's SPKI.
    spki_children = asn1.children(asn1.read_tlv(key_bits)) if key_bits else []
    raw_key = b""
    if len(spki_children) >= 2:
        raw_key = spki_children[1].data
        if raw_key[:1] == b"\x00":
            raw_key = raw_key[1:]

    sha1_null = _der(0x30, _der(0x06, bytes.fromhex("2b0e03021a")) + _der(0x05, b""))
    serial = leaf.serial.to_bytes((leaf.serial.bit_length() + 8) // 8, "big") or b"\x00"
    cert_id = _der(0x30,
                   sha1_null
                   + _der(0x04, hashlib.sha1(issuer.subject_raw).digest())
                   + _der(0x04, hashlib.sha1(raw_key).digest())
                   + _der(0x02, serial))
    request_list = _der(0x30, _der(0x30, cert_id))
    return _der(0x30, _der(0x30, request_list))


def check_online(leaf: asn1.Certificate, chain: list[asn1.Certificate],
                 timeout: float = 10.0) -> OcspResult:
    """Query the CA's OCSP responder. Never called unless explicitly enabled.

    This tells the certificate authority which certificate you are examining
    and when. For a forensics tool that is a disclosure about an ongoing
    investigation, which is why it is opt-in rather than a fallback.
    """
    import urllib.error
    import urllib.request

    result = OcspResult(checked_serial=leaf.serial)
    if len(chain) < 2:
        result.detail = "no issuer certificate available to build a query"
        return result
    if not leaf.ocsp_urls:
        result.detail = "certificate names no OCSP responder"
        return result

    issuer = chain[1]
    try:
        body = build_request(leaf, issuer)
    except Exception as exc:
        result.detail = f"could not build an OCSP request: {exc}"
        return result

    for url in leaf.ocsp_urls[:2]:
        try:
            request = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/ocsp-request",
                         "User-Agent": "markcleanse"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                der = response.read(1024 * 1024)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            result.detail = f"OCSP query to {url} failed: {exc}"
            continue

        try:
            statuses, tbs, sig_alg, signature, certs = parse_basic_response(der)
        except Exception as exc:
            result.state = "unparsed"
            result.detail = f"OCSP responder returned an unparsable reply: {exc}"
            continue

        match = next((s for s in statuses if s.serial == leaf.serial), None)
        if match is None:
            result.detail = "responder did not answer for this serial"
            continue

        result.statuses = statuses
        result.state = match.status
        result.signature_verified = _verify_response(tbs, sig_alg, signature,
                                                     certs, chain)
        result.responder = certs[0].describe() if certs else issuer.describe()
        if match.status == "revoked":
            when = match.revoked_at.strftime("%Y-%m-%d") if match.revoked_at else "?"
            result.detail = (f"live OCSP: certificate was REVOKED on {when}"
                             + (f" ({match.reason})" if match.reason else ""))
        else:
            asof = match.this_update.strftime("%Y-%m-%d") if match.this_update else "?"
            result.detail = f"live OCSP: {match.status} as of {asof}"
        if not result.signature_verified:
            result.detail += " — response signature NOT verified"
        return result
    return result


def _verify_response(tbs: bytes, sig_alg: str, signature: bytes,
                     certs: list[asn1.Certificate],
                     chain: list[asn1.Certificate]) -> bool:
    """Verify the responder's signature over the response data."""
    scheme_hash = asn1.SIG_ALG_OIDS.get(sig_alg)
    if not scheme_hash or not tbs or not signature:
        return False
    scheme, hash_name = scheme_hash
    # The responder is either a delegated certificate carried in the response
    # or the issuing CA itself.
    candidates = [c for c in certs] + [c for c in chain[1:]]
    for cert in candidates:
        if cert.public_key and crypto_min.verify(cert.public_key, scheme,
                                                 hash_name, tbs, signature):
            return True
    return False
