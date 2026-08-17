"""Minimal DER/ASN.1 reader and X.509 certificate model.

Enough of RFC 5280 to walk a C2PA certificate chain: names, validity, public
keys, the basic extensions that decide whether a certificate is allowed to sign
another one, and the exact TBS byte range (which is what actually gets hashed).

No dependencies — this is used even when `cryptography` is installed, because
the byte offsets and raw structures are needed either way.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone


class Asn1Error(ValueError):
    pass


# ---------------------------------------------------------------------------
# TLV
# ---------------------------------------------------------------------------

@dataclass
class TLV:
    tag: int
    start: int          # offset of the tag byte
    header_len: int
    length: int
    data: bytes         # the value bytes only

    @property
    def end(self) -> int:
        return self.start + self.header_len + self.length

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def tag_number(self) -> int:
        return self.tag & 0x1F


def read_tlv(buf: bytes, offset: int = 0) -> TLV:
    if offset + 2 > len(buf):
        raise Asn1Error("truncated TLV header")
    tag = buf[offset]
    if tag & 0x1F == 0x1F:
        raise Asn1Error("high-tag-number form is not supported")
    i = offset + 1
    first = buf[i]
    i += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise Asn1Error("indefinite length is not valid in DER")
    else:
        n = first & 0x7F
        if n > 8 or i + n > len(buf):
            raise Asn1Error("bad long-form length")
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    if i + length > len(buf):
        raise Asn1Error("TLV runs past the end of the buffer")
    return TLV(tag=tag, start=offset, header_len=i - offset,
               length=length, data=buf[i:i + length])


def children(tlv: TLV) -> list[TLV]:
    """Parse the children of a constructed TLV, with offsets relative to it."""
    out: list[TLV] = []
    i = 0
    while i < len(tlv.data):
        child = read_tlv(tlv.data, i)
        out.append(child)
        i = child.end
    return out


# ---------------------------------------------------------------------------
# OIDs
# ---------------------------------------------------------------------------

def decode_oid(data: bytes) -> str:
    if not data:
        return ""
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "E",
}

OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
OID_ED25519 = "1.3.101.112"

CURVE_OIDS = {
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
}

#: certificate signatureAlgorithm -> (scheme, hash name)
SIG_ALG_OIDS = {
    "1.2.840.113549.1.1.5":  ("rsa-pkcs1", "sha1"),
    "1.2.840.113549.1.1.11": ("rsa-pkcs1", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa-pkcs1", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa-pkcs1", "sha512"),
    "1.2.840.113549.1.1.10": ("rsa-pss", "sha256"),
    "1.2.840.10045.4.3.2":   ("ecdsa", "sha256"),
    "1.2.840.10045.4.3.3":   ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4":   ("ecdsa", "sha512"),
    "1.3.101.112":           ("ed25519", "sha512"),
}

OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_SUBJECT_KEY_ID = "2.5.29.14"
OID_AUTHORITY_KEY_ID = "2.5.29.35"
OID_EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
OID_EKU_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
OID_EKU_DOCUMENT_SIGNING = "1.3.6.1.5.5.7.3.36"
OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"
OID_AD_OCSP = "1.3.6.1.5.5.7.48.1"


# ---------------------------------------------------------------------------
# X.509
# ---------------------------------------------------------------------------

@dataclass
class PublicKey:
    algorithm: str                  # "ec" | "rsa" | "ed25519"
    curve: str = ""                 # EC only
    point: bytes = b""              # EC only, uncompressed SEC1
    modulus: int = 0                # RSA only
    exponent: int = 0               # RSA only
    raw: bytes = b""                # Ed25519 only
    spki_der: bytes = b""           # the whole SubjectPublicKeyInfo


@dataclass
class Certificate:
    der: bytes
    tbs_der: bytes = b""
    version: int = 1                # 1, 2 or 3 (decoded from the [0] tag + 1)
    has_unique_ids: bool = False    # issuerUniqueID / subjectUniqueID present
    critical_unknown: list[str] = field(default_factory=list)
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    serial: int = 0
    not_before: datetime | None = None
    not_after: datetime | None = None
    public_key: PublicKey | None = None
    sig_algorithm: str = ""         # OID
    signature: bytes = b""
    is_ca: bool | None = None
    path_len: int | None = None
    key_usage: set[str] = field(default_factory=set)
    ext_key_usage: list[str] = field(default_factory=list)
    subject_key_id: bytes = b""
    authority_key_id: bytes = b""
    subject_raw: bytes = b""        # DER of the subject Name, for OCSP CertID
    ocsp_urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def subject_cn(self) -> str:
        return self.subject.get("CN") or self.subject.get("O") or ""

    @property
    def issuer_cn(self) -> str:
        return self.issuer.get("CN") or self.issuer.get("O") or ""

    @property
    def self_signed(self) -> bool:
        return self.subject == self.issuer and bool(self.subject)

    def valid_at(self, when: datetime) -> bool:
        if self.not_before and when < self.not_before:
            return False
        if self.not_after and when > self.not_after:
            return False
        return True

    def describe(self) -> str:
        return self.subject_cn or f"serial {self.serial:x}"


KEY_USAGE_BITS = ["digitalSignature", "nonRepudiation", "keyEncipherment",
                  "dataEncipherment", "keyAgreement", "keyCertSign",
                  "cRLSign", "encipherOnly", "decipherOnly"]


def parse_certificate(der: bytes) -> Certificate:
    cert = Certificate(der=der)
    top = read_tlv(der)
    if top.tag != 0x30:
        raise Asn1Error("certificate is not a SEQUENCE")
    parts = children(top)
    if len(parts) < 3:
        raise Asn1Error("certificate has too few fields")

    tbs, sig_alg, sig_value = parts[0], parts[1], parts[2]
    # The signature covers the TBSCertificate *including* its own tag and
    # length, so slice it out of the original buffer rather than re-encoding.
    tbs_abs_start = top.header_len + tbs.start
    cert.tbs_der = der[tbs_abs_start:tbs_abs_start + tbs.header_len + tbs.length]

    cert.sig_algorithm = decode_oid(children(sig_alg)[0].data) if children(sig_alg) else ""
    cert.signature = sig_value.data[1:] if sig_value.data[:1] == b"\x00" else sig_value.data

    fields = children(tbs)
    idx = 0
    if fields and fields[0].tag == 0xA0:          # [0] EXPLICIT version
        inner = children(fields[0])
        if inner and inner[0].data:
            cert.version = int.from_bytes(inner[0].data, "big") + 1
        idx = 1
    else:
        cert.version = 1
    try:
        cert.serial = int.from_bytes(fields[idx].data, "big")
        cert.issuer = _parse_name(fields[idx + 2])
        _subj = fields[idx + 4]
        cert.subject_raw = tbs.data[_subj.start:_subj.end]
        cert.not_before, cert.not_after = _parse_validity(fields[idx + 3])
        cert.subject = _parse_name(fields[idx + 4])
        cert.public_key = _parse_spki(fields[idx + 5], tbs.data)
    except (IndexError, Asn1Error) as exc:
        cert.errors.append(f"malformed TBSCertificate: {exc}")
        return cert

    for extra in fields[idx + 6:]:
        # [1]/[2] IMPLICIT issuerUniqueID / subjectUniqueID — prohibited by the
        # C2PA certificate profile.
        if extra.tag in (0x81, 0x82):
            cert.has_unique_ids = True
        if extra.tag == 0xA3:                     # [3] EXPLICIT extensions
            try:
                _parse_extensions(extra, cert)
            except Asn1Error as exc:
                cert.errors.append(f"bad extensions: {exc}")
    return cert


def _parse_name(tlv: TLV) -> dict[str, str]:
    out: dict[str, str] = {}
    for rdn in children(tlv):
        for attr in children(rdn):
            pieces = children(attr)
            if len(pieces) < 2:
                continue
            oid = decode_oid(pieces[0].data)
            key = OID_NAMES.get(oid, oid)
            try:
                value = pieces[1].data.decode("utf-8")
            except UnicodeDecodeError:
                value = pieces[1].data.decode("latin-1", "replace")
            out.setdefault(key, value.strip())
    return out


def _parse_time(tlv: TLV) -> datetime | None:
    raw = tlv.data.decode("ascii", "replace").strip()
    fmt = "%y%m%d%H%M%S" if tlv.tag == 0x17 else "%Y%m%d%H%M%S"
    if raw.endswith("Z"):
        raw = raw[:-1]
    try:
        return datetime.strptime(raw[:len(fmt.replace("%", "")) + 4], fmt).replace(
            tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _parse_validity(tlv: TLV) -> tuple[datetime | None, datetime | None]:
    kids = children(tlv)
    if len(kids) < 2:
        return None, None
    return _parse_time(kids[0]), _parse_time(kids[1])


def _parse_spki(tlv: TLV, tbs_data: bytes) -> PublicKey:
    spki_der = tbs_data[tlv.start:tlv.end]
    kids = children(tlv)
    if len(kids) < 2:
        raise Asn1Error("bad SubjectPublicKeyInfo")
    alg_parts = children(kids[0])
    oid = decode_oid(alg_parts[0].data) if alg_parts else ""
    bitstring = kids[1].data
    key_bytes = bitstring[1:] if bitstring[:1] == b"\x00" else bitstring

    if oid == OID_EC_PUBLIC_KEY:
        curve = ""
        if len(alg_parts) > 1 and alg_parts[1].tag == 0x06:
            curve = CURVE_OIDS.get(decode_oid(alg_parts[1].data), "")
        return PublicKey(algorithm="ec", curve=curve, point=key_bytes,
                         spki_der=spki_der)
    if oid in (OID_RSA_ENCRYPTION, OID_RSASSA_PSS):
        inner = read_tlv(key_bytes)
        nums = children(inner)
        if len(nums) < 2:
            raise Asn1Error("bad RSA public key")
        return PublicKey(algorithm="rsa",
                         modulus=int.from_bytes(nums[0].data, "big"),
                         exponent=int.from_bytes(nums[1].data, "big"),
                         spki_der=spki_der)
    if oid == OID_ED25519:
        return PublicKey(algorithm="ed25519", raw=key_bytes, spki_der=spki_der)
    raise Asn1Error(f"unsupported public key algorithm {oid}")


#: Extension OIDs a conforming validator is expected to understand. A *critical*
#: extension outside this set means the certificate demands handling we cannot
#: provide, which the C2PA profile treats as invalid.
KNOWN_EXTENSIONS = {
    "2.5.29.35", "2.5.29.14", "2.5.29.15", "2.5.29.32", "2.5.29.33",
    "2.5.29.17", "2.5.29.18", "2.5.29.19", "2.5.29.30", "2.5.29.36",
    "2.5.29.37", "2.5.29.31", "2.5.29.54", "2.5.29.20", "2.5.29.21",
    "2.5.29.24", "1.3.6.1.5.5.7.1.1", "2.16.840.1.113730.1.1",
}


def _parse_extensions(tlv: TLV, cert: Certificate) -> None:
    seq = children(tlv)
    if not seq:
        return
    for ext in children(seq[0]):
        parts = children(ext)
        if not parts:
            continue
        oid = decode_oid(parts[0].data)
        critical = any(p.tag == 0x01 and p.data not in (b"\x00", b"")
                       for p in parts[1:-1])
        if critical and oid not in KNOWN_EXTENSIONS:
            cert.critical_unknown.append(oid)
        value = parts[-1].data                      # OCTET STRING contents

        if oid == OID_BASIC_CONSTRAINTS:
            inner = children(read_tlv(value))
            cert.is_ca = False
            for item in inner:
                if item.tag == 0x01:
                    cert.is_ca = item.data != b"\x00"
                elif item.tag == 0x02:
                    cert.path_len = int.from_bytes(item.data, "big")

        elif oid == OID_KEY_USAGE:
            bits = read_tlv(value)
            if bits.data:
                unused = bits.data[0]
                body = bits.data[1:]
                total = len(body) * 8 - unused
                for i in range(min(total, len(KEY_USAGE_BITS))):
                    if body[i // 8] & (0x80 >> (i % 8)):
                        cert.key_usage.add(KEY_USAGE_BITS[i])

        elif oid == OID_EXT_KEY_USAGE:
            for item in children(read_tlv(value)):
                cert.ext_key_usage.append(decode_oid(item.data))

        elif oid == OID_SUBJECT_KEY_ID:
            cert.subject_key_id = read_tlv(value).data

        elif oid == OID_AUTHORITY_INFO_ACCESS:
            # AccessDescription ::= SEQUENCE { accessMethod OID,
            #                                  accessLocation GeneralName }
            for entry in children(read_tlv(value)):
                items = children(entry)
                if len(items) < 2 or decode_oid(items[0].data) != OID_AD_OCSP:
                    continue
                if items[1].tag == 0x86:           # uniformResourceIdentifier
                    url = items[1].data.decode("ascii", "replace")
                    if url.startswith(("http://", "https://")):
                        cert.ocsp_urls.append(url)

        elif oid == OID_AUTHORITY_KEY_ID:
            for item in children(read_tlv(value)):
                if item.tag == 0x80:
                    cert.authority_key_id = item.data


def decode_ecdsa_signature(der: bytes) -> tuple[int, int]:
    """DER SEQUENCE { r INTEGER, s INTEGER } -> (r, s)."""
    parts = children(read_tlv(der))
    if len(parts) < 2:
        raise Asn1Error("bad ECDSA signature")
    return (int.from_bytes(parts[0].data, "big"),
            int.from_bytes(parts[1].data, "big"))
