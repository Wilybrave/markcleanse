"""Signature verification with a pure-Python fallback.

If `cryptography` is importable we use it — it is audited and constant-time.
If it is not, we fall back to the implementations here, so a locked-down
machine still gets real chain validation instead of a shrug.

Covers every algorithm C2PA permits: ES256/384/512, PS256/384/512, RS256
(legacy chains) and Ed25519.

These fallbacks verify *signatures*, which is public-key-only work on public
data. There is no secret to leak, so the lack of constant-time arithmetic is
not a vulnerability here. Do not lift this module to do anything else.
"""

from __future__ import annotations

import hashlib

from .asn1 import PublicKey, decode_ecdsa_signature

try:                                                   # pragma: no cover
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes as _ch
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.hazmat.primitives.asymmetric import utils as _ecutils
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    HAVE_CRYPTOGRAPHY = True
except Exception:                                      # pragma: no cover
    HAVE_CRYPTOGRAPHY = False


def backend() -> str:
    return "cryptography" if HAVE_CRYPTOGRAPHY else "pure-python"


HASHES = {"sha256": hashlib.sha256, "sha384": hashlib.sha384,
          "sha512": hashlib.sha512, "sha1": hashlib.sha1}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def verify(key: PublicKey, scheme: str, hash_name: str,
           message: bytes, signature: bytes, raw_ecdsa: bool = False) -> bool:
    """Verify `signature` over `message`.

    `raw_ecdsa` selects the fixed-width r||s encoding COSE uses, as opposed to
    the DER SEQUENCE that X.509 certificates use.
    """
    try:
        if HAVE_CRYPTOGRAPHY:
            return _verify_lib(key, scheme, hash_name, message, signature, raw_ecdsa)
        return _verify_pure(key, scheme, hash_name, message, signature, raw_ecdsa)
    except Exception:
        return False


def _verify_lib(key, scheme, hash_name, message, signature, raw_ecdsa) -> bool:
    algo = {"sha256": _ch.SHA256(), "sha384": _ch.SHA384(),
            "sha512": _ch.SHA512(), "sha1": _ch.SHA1()}[hash_name]
    pub = load_der_public_key(key.spki_der)
    try:
        if scheme == "ecdsa":
            sig = signature
            if raw_ecdsa:
                half = len(signature) // 2
                r = int.from_bytes(signature[:half], "big")
                s = int.from_bytes(signature[half:], "big")
                sig = _ecutils.encode_dss_signature(r, s)
            pub.verify(sig, message, _ec.ECDSA(algo))
        elif scheme == "rsa-pkcs1":
            pub.verify(signature, message, _pad.PKCS1v15(), algo)
        elif scheme == "rsa-pss":
            pub.verify(signature, message,
                       _pad.PSS(mgf=_pad.MGF1(algo), salt_length=algo.digest_size),
                       algo)
        elif scheme == "ed25519":
            if not isinstance(pub, _ed.Ed25519PublicKey):
                return False
            pub.verify(signature, message)
        else:
            return False
        return True
    except InvalidSignature:
        return False


def _verify_pure(key, scheme, hash_name, message, signature, raw_ecdsa) -> bool:
    if scheme == "ecdsa":
        if raw_ecdsa:
            half = len(signature) // 2
            r = int.from_bytes(signature[:half], "big")
            s = int.from_bytes(signature[half:], "big")
        else:
            r, s = decode_ecdsa_signature(signature)
        return ecdsa_verify(key.curve, key.point, message, r, s, hash_name)
    if scheme == "rsa-pkcs1":
        return rsa_pkcs1_verify(key.modulus, key.exponent, message, signature, hash_name)
    if scheme == "rsa-pss":
        return rsa_pss_verify(key.modulus, key.exponent, message, signature, hash_name)
    if scheme == "ed25519":
        return ed25519_verify(key.raw, message, signature)
    return False


# ---------------------------------------------------------------------------
# ECDSA over the NIST prime curves
# ---------------------------------------------------------------------------

class Curve:
    __slots__ = ("p", "a", "b", "n", "gx", "gy", "size")

    def __init__(self, p, a, b, n, gx, gy, size):
        self.p, self.a, self.b, self.n = p, a, b, n
        self.gx, self.gy, self.size = gx, gy, size


CURVES = {
    "P-256": Curve(
        p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        a=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        size=32),
    "P-384": Curve(
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        a=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
        b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        gx=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        gy=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        size=48),
    "P-521": Curve(
        p=(1 << 521) - 1,
        a=(1 << 521) - 4,
        b=0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        n=0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
        gx=0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        gy=0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
        size=66),
}


def _inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _point_add(curve: Curve, p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + curve.a) * _inv(2 * y1, curve.p) % curve.p
    else:
        lam = (y2 - y1) * _inv(x2 - x1, curve.p) % curve.p
    x3 = (lam * lam - x1 - x2) % curve.p
    return (x3, (lam * (x1 - x3) - y1) % curve.p)


def _point_mul(curve: Curve, point, scalar: int):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(curve, result, addend)
        addend = _point_add(curve, addend, addend)
        scalar >>= 1
    return result


def _on_curve(curve: Curve, point) -> bool:
    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def ecdsa_verify(curve_name: str, point_bytes: bytes, message: bytes,
                 r: int, s: int, hash_name: str) -> bool:
    curve = CURVES.get(curve_name)
    if curve is None or not point_bytes:
        return False
    if point_bytes[0] != 0x04:
        return False                       # compressed points are not used here
    size = curve.size
    if len(point_bytes) < 1 + 2 * size:
        return False
    qx = int.from_bytes(point_bytes[1:1 + size], "big")
    qy = int.from_bytes(point_bytes[1 + size:1 + 2 * size], "big")
    if not _on_curve(curve, (qx, qy)):
        return False
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False

    digest = HASHES[hash_name](message).digest()
    e = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - curve.n.bit_length()
    if excess > 0:
        e >>= excess

    w = _inv(s, curve.n)
    u1 = e * w % curve.n
    u2 = r * w % curve.n
    pt = _point_add(curve,
                    _point_mul(curve, (curve.gx, curve.gy), u1),
                    _point_mul(curve, (qx, qy), u2))
    if pt is None:
        return False
    return pt[0] % curve.n == r


# ---------------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------------

DIGEST_INFO_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
    "sha1":   bytes.fromhex("3021300906052b0e03021a05000414"),
}


def _rsa_raw(modulus: int, exponent: int, signature: bytes) -> bytes:
    k = (modulus.bit_length() + 7) // 8
    if len(signature) > k:
        raise ValueError("signature longer than modulus")
    m = pow(int.from_bytes(signature, "big"), exponent, modulus)
    return m.to_bytes(k, "big")


def rsa_pkcs1_verify(modulus: int, exponent: int, message: bytes,
                     signature: bytes, hash_name: str) -> bool:
    em = _rsa_raw(modulus, exponent, signature)
    digest = HASHES[hash_name](message).digest()
    expected = DIGEST_INFO_PREFIX[hash_name] + digest
    padding_len = len(em) - len(expected) - 3
    if padding_len < 8:
        return False
    target = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + expected
    return _equal(em, target)


def _mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += HASHES[hash_name](seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def rsa_pss_verify(modulus: int, exponent: int, message: bytes,
                   signature: bytes, hash_name: str) -> bool:
    h_len = HASHES[hash_name]().digest_size
    em_bits = modulus.bit_length() - 1
    em_len = (em_bits + 7) // 8
    em = _rsa_raw(modulus, exponent, signature)[-em_len:]
    if len(em) < h_len + 2 or em[-1] != 0xBC:
        return False

    masked_db = em[:em_len - h_len - 1]
    h = em[em_len - h_len - 1:-1]
    db = bytes(a ^ b for a, b in zip(masked_db, _mgf1(h, len(masked_db), hash_name)))

    # Clear the leftmost bits that are not part of the encoded message.
    db = bytes([db[0] & (0xFF >> (8 * em_len - em_bits))]) + db[1:]
    sep = db.find(b"\x01")
    if sep < 0 or any(db[:sep]):
        return False
    salt = db[sep + 1:]
    m_prime = b"\x00" * 8 + HASHES[hash_name](message).digest() + salt
    return _equal(HASHES[hash_name](m_prime).digest(), h)


def _equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032 reference construction)
# ---------------------------------------------------------------------------

_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, -1, _ED_P) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int, sign: int) -> int | None:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, -1, _ED_P) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = x * _ED_I % _ED_P
    if (x * x - xx) % _ED_P != 0:
        return None
    if x & 1 != sign:
        x = _ED_P - x
    return x


def _ed_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * t1 * t2 * _ED_D % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_mul(point, scalar: int):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _ed_add(result, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return result


def _ed_point(y_bytes: bytes):
    y = int.from_bytes(y_bytes, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED_P)


_ED_BY = 4 * pow(5, -1, _ED_P) % _ED_P
_ED_BX = _ed_recover_x(_ED_BY, 0)
_ED_B = (_ED_BX, _ED_BY, 1, _ED_BX * _ED_BY % _ED_P)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _ed_point(public_key)
    if a is None:
        return False
    r_point = _ed_point(signature[:32])
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    k = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _ED_L
    left = _ed_mul(_ED_B, s)
    right = _ed_add(r_point, _ed_mul(a, k))
    return _ed_equal(left, right)


def _ed_equal(p, q) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return ((x1 * z2 - x2 * z1) % _ED_P == 0
            and (y1 * z2 - y2 * z1) % _ED_P == 0)
