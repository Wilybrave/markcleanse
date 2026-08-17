"""The C2PA certificate profile.

A signature can verify perfectly against a certificate that has no business
signing C2PA claims — wrong key size, a curve outside the permitted set, an
extended key usage that says "this is a web server", or a self-signed CA
pretending to be an end entity. The C2PA specification therefore constrains
the signing credential itself, and `c2patool` reports a violation as
``signingCredential.invalid``.

Rules transcribed from the reference implementation
(`c2pa-rs/sdk/src/crypto/cose/certificate_profile.rs`) rather than paraphrased
from the spec, because the two differ in detail and the reference is what
everyone else's verdicts are compared against.

A violation is reported here as a **credential** problem, never as tampering:
a non-conforming certificate says the signer is out of policy, not that the
file was altered.
"""

from __future__ import annotations

from . import asn1

#: Algorithms a C2PA certificate may itself be signed with.
ALLOWED_SIG_ALGS = {
    "1.2.840.113549.1.1.11",   # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12",   # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13",   # sha512WithRSAEncryption
    "1.2.840.10045.4.3.2",     # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3",     # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4",     # ecdsa-with-SHA512
    "1.2.840.113549.1.1.10",   # RSASSA-PSS
    "1.3.101.112",             # Ed25519
}

ALLOWED_CURVES = {"P-256", "P-384", "P-521"}
MIN_RSA_BITS = 2048

EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
EKU_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
EKU_DOCUMENT_SIGNING = "1.3.6.1.5.5.7.3.36"
EKU_ANY = "2.5.29.37.0"

#: An end-entity signing certificate must carry at least one of these.
ALLOWED_EKUS = {EKU_EMAIL_PROTECTION, EKU_DOCUMENT_SIGNING,
                EKU_TIME_STAMPING, EKU_OCSP_SIGNING}

#: EKUs that must not appear alongside a lone timeStamping/OCSPSigning.
CONFLICTING_EKUS = {EKU_SERVER_AUTH, EKU_CLIENT_AUTH, EKU_CODE_SIGNING,
                    EKU_EMAIL_PROTECTION}


def check(cert: asn1.Certificate) -> list[str]:
    """Return the profile violations of a signing certificate, or []."""
    problems: list[str] = []
    is_ca = bool(cert.is_ca)

    if cert.version != 3:
        problems.append(f"certificate is v{cert.version}, the profile requires v3")

    if cert.sig_algorithm and cert.sig_algorithm not in ALLOWED_SIG_ALGS:
        problems.append(f"signed with a disallowed algorithm ({cert.sig_algorithm})")

    key = cert.public_key
    if key is None:
        problems.append("no usable public key")
    elif key.algorithm == "ec":
        if key.curve and key.curve not in ALLOWED_CURVES:
            problems.append(f"EC curve {key.curve} is outside the permitted set")
        elif not key.curve:
            problems.append("EC key uses an unnamed or unrecognised curve")
    elif key.algorithm == "rsa":
        bits = key.modulus.bit_length()
        if bits < MIN_RSA_BITS:
            problems.append(f"RSA key is {bits} bits, the profile requires "
                            f"{MIN_RSA_BITS} or more")

    # A self-signed CA is a trust anchor, not a signing credential.
    if is_ca and cert.self_signed:
        problems.append("self-signed CA certificates may not sign claims")

    if cert.has_unique_ids:
        problems.append("issuer/subject unique IDs are not permitted")

    if cert.critical_unknown:
        problems.append("carries unrecognised critical extension(s): "
                        + ", ".join(cert.critical_unknown[:3]))

    # --- key usage ------------------------------------------------------
    if cert.key_usage:
        signing = ("digitalSignature" in cert.key_usage
                   or "nonRepudiation" in cert.key_usage
                   or "keyCertSign" in cert.key_usage)
        if not signing:
            problems.append("keyUsage does not permit signing")
        if ("digitalSignature" in cert.key_usage
                and "keyCertSign" in cert.key_usage and not is_ca):
            problems.append("non-CA certificate asserts keyCertSign")
    else:
        problems.append("no keyUsage extension")

    # --- extended key usage ---------------------------------------------
    ekus = set(cert.ext_key_usage)
    if not ekus:
        if not is_ca:
            problems.append("end-entity certificate has no extendedKeyUsage")
    else:
        if EKU_ANY in ekus:
            problems.append("anyExtendedKeyUsage is not permitted")
        if not (ekus & ALLOWED_EKUS):
            problems.append("extendedKeyUsage lacks a permitted purpose "
                            "(emailProtection, documentSigning, timeStamping "
                            "or OCSPSigning)")
        ocsp, tsa = EKU_OCSP_SIGNING in ekus, EKU_TIME_STAMPING in ekus
        if ocsp and tsa:
            problems.append("OCSPSigning and timeStamping may not both be set")
        elif (ocsp ^ tsa) and (ekus & CONFLICTING_EKUS):
            problems.append("OCSPSigning/timeStamping must appear alone")

    if not is_ca and not cert.authority_key_id:
        problems.append("no authorityKeyIdentifier")
    if is_ca and not cert.subject_key_id:
        problems.append("CA certificate has no subjectKeyIdentifier")

    return problems
