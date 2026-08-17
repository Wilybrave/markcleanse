"""C2PA / Content Credentials detector.

This is the strongest evidence markcleanse can produce. A C2PA manifest is a
cryptographically signed JUMBF store embedded in the file, written by
OpenAI, Adobe Firefly, Microsoft, Leica, Sony, Nikon and others. It records
what made the asset and what was done to it.

We parse the container ourselves (ISO 19566-5 JUMBF + RFC 8949 CBOR) so this
works with no third-party packages.

Verification lives in `markcleanse.c2pa_verify` and runs on every manifest found:
the asset hash binding, the assertion hashes, the COSE signature and the
certificate chain. A manifest that fails any of them is reported as an
integrity failure and its provenance claim is demoted to heuristic strength —
a manifest lifted from one file and pasted onto another fails the binding check
and says so.

What verification does not establish is *trust*: a valid chain proves the
manifest was signed by whoever holds that key, not that the key belongs to a
legitimate signer. Supply trust anchors with `--trust` to make that a decision
rather than an assumption. Absence of a manifest still proves nothing at all.
"""

from __future__ import annotations

import re
import struct
from typing import Any, Iterator

from ..cbor_min import CborError, loads as cbor_loads
from ..result import Finding, Tier
from .. import c2pa_verify, signatures as sig

DETECTOR = "c2pa"

C2PA_UUID = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")
JUMBF_JSON_UUID = bytes.fromhex("6a736f6e00110010800000aa00389b71")
JUMBF_CBOR_UUID = bytes.fromhex("63626f7200110010800000aa00389b71")

AI_SOURCE_TYPES = re.compile(
    r"trainedAlgorithmicMedia|compositeWithTrainedAlgorithmicMedia|algorithmicMedia",
    re.I,
)


# ---------------------------------------------------------------------------
# Container extraction
# ---------------------------------------------------------------------------

def extract_store(data: bytes, fmt: str) -> bytes | None:
    """Pull the raw JUMBF manifest store out of a container."""
    try:
        if fmt == "jpeg":
            return _from_jpeg(data)
        if fmt == "png":
            return _from_png(data)
        if fmt == "webp":
            return _from_webp(data)
        if fmt in ("avif", "heic", "bmff", "mp4"):
            return _from_bmff(data)
        if fmt == "gif":
            return _from_gif(data)
    except Exception:
        return None
    return None


def _from_jpeg(data: bytes) -> bytes | None:
    """Reassemble APP11 packets (ISO 19566-5 fragmentation)."""
    packets: dict[int, list[tuple[int, bytes]]] = {}
    i = 2
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xD9 or marker == 0xDA:      # EOI / start of scan
            break
        seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
        payload = data[i + 4:i + 2 + seg_len]
        if marker == 0xEB and payload[:2] == b"JP" and len(payload) > 8:
            en = struct.unpack(">H", payload[2:4])[0]
            z = struct.unpack(">I", payload[4:8])[0]
            packets.setdefault(en, []).append((z, payload[8:]))
        i += 2 + seg_len

    if not packets:
        return None

    # Prefer the instance whose reassembly self-describes correctly.
    best: bytes | None = None
    for _en, parts in sorted(packets.items()):
        parts.sort(key=lambda p: p[0])
        # Variant A: LBox/TBox repeated in every packet (the spec).
        a = parts[0][1] + b"".join(p[1][8:] for p in parts[1:])
        # Variant B: header only in the first packet.
        b = b"".join(p[1] for p in parts)
        chosen = a if _self_consistent(a) else (b if _self_consistent(b) else a)
        if b"c2pa" in chosen and (best is None or len(chosen) > len(best)):
            best = chosen
        elif best is None:
            best = chosen
    return best


def _self_consistent(store: bytes) -> bool:
    if len(store) < 8:
        return False
    lbox = struct.unpack(">I", store[:4])[0]
    if store[4:8] != b"jumb":
        return False
    if lbox == 1 and len(store) >= 16:
        lbox = struct.unpack(">Q", store[8:16])[0]
    return lbox == len(store)


def _from_png(data: bytes) -> bytes | None:
    for ctype, payload in iter_png_chunks(data):
        if ctype == b"caBX":
            return payload
    return None


def iter_png_chunks(data: bytes) -> Iterator[tuple[bytes, bytes]]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return
    i = 8
    n = len(data)
    while i + 8 <= n:
        length = struct.unpack(">I", data[i:i + 4])[0]
        ctype = data[i + 4:i + 8]
        if length > n:
            return
        yield ctype, data[i + 8:i + 8 + length]
        i += 12 + length
        if ctype == b"IEND":
            return


def _from_webp(data: bytes) -> bytes | None:
    for fourcc, payload in iter_riff_chunks(data):
        if fourcc in (b"C2PA", b"c2pa"):
            return payload
    return None


def iter_riff_chunks(data: bytes) -> Iterator[tuple[bytes, bytes]]:
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return
    i = 12
    n = len(data)
    while i + 8 <= n:
        fourcc = data[i:i + 4]
        size = struct.unpack("<I", data[i + 4:i + 8])[0]
        yield fourcc, data[i + 8:i + 8 + size]
        i += 8 + size + (size & 1)


def _from_bmff(data: bytes) -> bytes | None:
    """AVIF/HEIC/HEIF/MP4 keep the store in a `uuid` box with the C2PA UUID.

    The box may sit at the top level or nested (some writers put it inside
    `meta`), so the whole tree is searched rather than only the first level.
    """
    from .. import bmff

    box = bmff.find_uuid_box(data, C2PA_UUID)
    if box is not None:
        store = box.payload(data)
        if store[4:8] == b"jumb":
            return store
        # A few writers prefix the store with a 4-byte version/purpose field.
        idx = store.find(b"jumb")
        if 0 < idx <= 32:
            return store[idx - 4:]
        return store or None

    # Fallback: a JUMBF store carried as a `meta` item rather than a uuid box.
    idx = data.find(b"jumb")
    if idx > 4 and b"c2pa" in data[idx:idx + 4096]:
        return data[idx - 4:]
    return None


def _from_gif(data: bytes) -> bytes | None:
    idx = data.find(b"\x21\xff\x0bC2PA_GIF\x00")
    return data[idx + 14:] if idx >= 0 else None


# ---------------------------------------------------------------------------
# JUMBF box tree
# ---------------------------------------------------------------------------

class Box:
    __slots__ = ("label", "type_uuid", "children", "content", "raw_bytes",
                 "header_len")

    def __init__(self) -> None:
        self.label: str = ""
        self.type_uuid: bytes = b""
        self.children: list[Box] = []
        self.content: list[tuple[bytes, bytes]] = []   # (box type, payload)
        self.raw_bytes: bytes = b""      # complete JUMBF box, header included
        self.header_len: int = 8         # 16 when the XLBox form is used

    @property
    def hashable(self) -> bytes:
        """The bytes a C2PA assertion hash covers.

        Verified empirically against real Google and OpenAI manifests: the
        digest is over the JUMBF box payload — the description box plus the
        content boxes — with the outer LBox/TBox header excluded.
        """
        return self.raw_bytes[self.header_len:]

    def walk(self) -> Iterator["Box"]:
        yield self
        for c in self.children:
            yield from c.walk()


def _iter_boxes(data: bytes) -> Iterator[tuple[bytes, bytes, bytes]]:
    """Yield (type, payload, whole box including header)."""
    i = 0
    n = len(data)
    while i + 8 <= n:
        lbox = struct.unpack(">I", data[i:i + 4])[0]
        tbox = data[i + 4:i + 8]
        hdr = 8
        if lbox == 1:
            if i + 16 > n:
                return
            size = struct.unpack(">Q", data[i + 8:i + 16])[0]
            hdr = 16
        elif lbox == 0:
            size = n - i
        else:
            size = lbox
        if size < hdr or i + size > n:
            # Tolerate a truncated tail rather than losing the whole manifest.
            yield tbox, data[i + hdr:n], data[i:n]
            return
        yield tbox, data[i + hdr:i + size], data[i:i + size]
        i += size


def parse_store(store: bytes, depth: int = 0) -> list[Box]:
    """Parse a JUMBF byte string into a box tree."""
    out: list[Box] = []
    if depth > 24:
        return out
    for tbox, payload, whole in _iter_boxes(store):
        if tbox != b"jumb":
            continue
        box = Box()
        box.raw_bytes = whole
        box.header_len = 16 if whole[:4] == b"\x00\x00\x00\x01" else 8
        for ctype, cpayload, cwhole in _iter_boxes(payload):
            if ctype == b"jumd":
                box.type_uuid, box.label = _parse_description(cpayload)
            elif ctype == b"jumb":
                box.children.extend(parse_store(cwhole, depth + 1))
            else:
                box.content.append((ctype, cpayload))
        out.append(box)
    return out


def _parse_description(payload: bytes) -> tuple[bytes, str]:
    if len(payload) < 17:
        return b"", ""
    type_uuid = payload[:16]
    toggles = payload[16]
    i = 17
    label = ""
    if toggles & 0x02:
        end = payload.find(b"\x00", i)
        if end < 0:
            end = len(payload)
        label = payload[i:end].decode("utf-8", "replace")
    return type_uuid, label


# ---------------------------------------------------------------------------
# Manifest interpretation
# ---------------------------------------------------------------------------

def _decode_content(box: Box) -> Any:
    for ctype, payload in box.content:
        if ctype in (b"cbor", b"bfdb", b"bidb", b"json"):
            if ctype == b"json":
                import json
                try:
                    return json.loads(payload.decode("utf-8", "replace"))
                except Exception:
                    return None
            try:
                return cbor_loads(payload)
            except (CborError, Exception):
                return None
    return None


def _raw_content(box: Box) -> bytes:
    return b"".join(p for _t, p in box.content)


def analyse(store: bytes) -> dict[str, Any]:
    """Turn a manifest store into the handful of facts we actually report."""
    info: dict[str, Any] = {
        "present": True,
        "generators": [],
        "actions": [],
        "digital_source_types": [],
        "signers": [],
        "assertion_labels": [],
        "titles": [],
        "parse_ok": False,
    }

    roots = parse_store(store)
    boxes = [b for r in roots for b in r.walk()]
    info["parse_ok"] = bool(boxes)

    for box in boxes:
        label = box.label
        if label:
            info["assertion_labels"].append(label)

        if label.startswith("c2pa.claim"):
            claim = _decode_content(box)
            if isinstance(claim, dict):
                _collect_generators(claim, info)
                for key in ("dc:title", "title"):
                    if isinstance(claim.get(key), str):
                        info["titles"].append(claim[key])

        elif label.startswith("c2pa.actions"):
            payload = _decode_content(box)
            actions = payload.get("actions") if isinstance(payload, dict) else None
            if isinstance(actions, list):
                for act in actions:
                    if not isinstance(act, dict):
                        continue
                    name = act.get("action") or act.get("name")
                    if isinstance(name, str):
                        info["actions"].append(name)
                    dst = act.get("digitalSourceType")
                    if isinstance(dst, str):
                        info["digital_source_types"].append(dst)
                    agent = act.get("softwareAgent")
                    if isinstance(agent, str):
                        info["generators"].append(agent)
                    elif isinstance(agent, dict) and isinstance(agent.get("name"), str):
                        info["generators"].append(agent["name"])

        elif label.startswith("c2pa.signature"):
            info["signers"].extend(_cert_common_names(_raw_content(box)))

        elif "CreativeWork" in label or label.startswith("stds."):
            payload = _decode_content(box)
            if isinstance(payload, dict):
                _collect_generators(payload, info)

    # Belt-and-braces: some producers only expose the source type as a raw
    # string in a box we did not model. Scan the store as a last resort.
    if not info["digital_source_types"]:
        for m in AI_SOURCE_TYPES.finditer(store.decode("latin-1")):
            info["digital_source_types"].append(m.group(0))

    if not info["generators"]:
        info["generators"].extend(_scrape_generators(store))

    for key in ("generators", "actions", "digital_source_types", "signers",
                "assertion_labels", "titles"):
        info[key] = _dedupe(info[key])
    return info


def _collect_generators(obj: Any, info: dict[str, Any], depth: int = 0) -> None:
    if depth > 8 or not isinstance(obj, (dict, list)):
        return
    if isinstance(obj, list):
        for item in obj:
            _collect_generators(item, info, depth + 1)
        return
    for key, value in obj.items():
        k = str(key).lower()
        if k in ("claim_generator", "softwareagent", "creatortool", "producer"):
            if isinstance(value, str):
                info["generators"].append(value)
            elif isinstance(value, dict) and isinstance(value.get("name"), str):
                ver = value.get("version")
                info["generators"].append(
                    f"{value['name']} {ver}" if isinstance(ver, str) else value["name"]
                )
        elif k in ("claim_generator_info", "author", "creator", "publisher"):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and isinstance(item.get("name"), str):
                        info["generators"].append(item["name"])
                    elif isinstance(item, str):
                        info["generators"].append(item)
            elif isinstance(value, dict) and isinstance(value.get("name"), str):
                info["generators"].append(value["name"])
        elif k == "digitalsourcetype" and isinstance(value, str):
            info["digital_source_types"].append(value)
        elif isinstance(value, (dict, list)):
            _collect_generators(value, info, depth + 1)


def _scrape_generators(store: bytes) -> list[str]:
    """Last-ditch: printable runs in the store that match a known generator."""
    found: list[str] = []
    for run in re.findall(rb"[\x20-\x7e]{4,120}", store):
        text = run.decode("ascii", "ignore")
        if sig.identify(text):
            found.append(text.strip())
    return found[:10]


_CN_OID = b"\x06\x03\x55\x04\x03"


def _cert_common_names(der: bytes) -> list[str]:
    """Scrape X.509 Common Names out of the COSE signature's cert chain."""
    names: list[str] = []
    start = 0
    while True:
        idx = der.find(_CN_OID, start)
        if idx < 0:
            break
        j = idx + len(_CN_OID)
        if j + 2 <= len(der) and der[j] in (0x0C, 0x13, 0x16, 0x1E, 0x14):
            length = der[j + 1]
            if length < 0x80:
                value = der[j + 2:j + 2 + length]
                try:
                    text = value.decode("utf-8" if der[j] == 0x0C else "ascii")
                except UnicodeDecodeError:
                    text = value.decode("latin-1", "replace")
                text = text.strip()
                if 2 <= len(text) <= 120 and text.isprintable():
                    names.append(text)
        start = idx + 1
    return _dedupe(names)[:6]


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for item in items:
        key = item.strip()
        if key and key.lower() not in seen:
            seen.add(key.lower())
            out.append(key)
    return out


# ---------------------------------------------------------------------------
# Detector entry point
# ---------------------------------------------------------------------------

def detect(ctx) -> list[Finding]:
    data, fmt = ctx.data, ctx.fmt
    store = extract_store(data, fmt)
    if not store or b"jumb" not in store[:64]:
        return []

    info = analyse(store)
    findings: list[Finding] = []

    # --- verification -----------------------------------------------------
    verification = None
    if getattr(ctx, "verify_c2pa", True):
        try:
            verification = c2pa_verify.verify_manifest(
                parse_store(store), data, getattr(ctx, "complete", True),
                getattr(ctx, "trust_store", None), fmt,
                getattr(ctx, "revocation", "stapled"))
        except Exception as exc:
            verification = c2pa_verify.Verification(
                errors=[f"{type(exc).__name__}: {exc}"])

    caveat = (verification.summary() if verification
              else "manifest content parsed; signatures not checked")

    generators = info["generators"]
    named = None
    for gen in generators:
        named = sig.identify(gen)
        if named:
            break

    ai_source = [d for d in info["digital_source_types"] if AI_SOURCE_TYPES.search(d)]
    #: A declared non-AI source type is positive counter-evidence. `c2pa.created`
    #: on its own means "this asset was created here" — a camera says it too.
    capture_source = [d for d in info["digital_source_types"]
                      if not AI_SOURCE_TYPES.search(d)]
    ai_action = any("generative" in a.lower() or a.lower().endswith(".ai")
                    for a in info["actions"])

    evidence = {
        "claim_generator": generators[:5],
        "actions": info["actions"][:12],
        "digital_source_type": info["digital_source_types"][:5],
        "signed_by": info["signers"][:5],
        "assertions": info["assertion_labels"][:20],
        "store_bytes": len(store),
        "verification": verification.to_dict() if verification else None,
        "caveat": caveat,
    }

    # A manifest that fails verification is not evidence of what it claims —
    # it is evidence that someone assembled it. Report the provenance claim at
    # heuristic strength and raise the integrity failure as its own finding.
    tampered = bool(verification and verification.tampered)
    claim_tier = Tier.C if tampered else Tier.A

    if ai_source:
        findings.append(Finding(
            tier=claim_tier,
            detector=DETECTOR,
            signal="c2pa.digital_source_type.ai",
            summary=(f"C2PA manifest declares digitalSourceType "
                     f"'{ai_source[0].rsplit('/', 1)[-1]}'"
                     + (f", generator '{generators[0]}'" if generators else "")
                     + (" — BUT THE MANIFEST FAILED VERIFICATION, so this claim "
                        "cannot be relied on" if tampered else "")),
            source=named or (generators[0] if generators else None),
            evidence=evidence,
        ))
    elif named:
        findings.append(Finding(
            tier=claim_tier,
            detector=DETECTOR,
            signal="c2pa.generator.ai",
            summary=(f"C2PA manifest names AI generator '{generators[0]}'"
                     + (" — BUT THE MANIFEST FAILED VERIFICATION" if tampered else "")),
            source=named,
            evidence=evidence,
        ))
    elif ai_action and not capture_source:
        findings.append(Finding(
            tier=Tier.C if tampered else Tier.B,
            detector=DETECTOR,
            signal="c2pa.action.generative",
            summary=f"C2PA manifest records generative action(s): "
                    f"{', '.join(info['actions'][:3])}",
            source=generators[0] if generators else None,
            evidence=evidence,
        ))
    else:
        # A manifest with no AI markers is positive provenance — this is a
        # signed capture or a signed human edit. Report it as such.
        findings.append(Finding(
            tier=Tier.C if tampered else Tier.B,
            detector=DETECTOR,
            signal="capture.signed.c2pa" if not tampered else "c2pa.unverified_capture",
            summary=("C2PA manifest present with no AI markers"
                     + (f"; declares '{capture_source[0].rsplit('/', 1)[-1]}'"
                        if capture_source else "")
                     + (f"; signed by {info['signers'][0]}" if info["signers"] else "")
                     + (f"; generator '{generators[0]}'" if generators else "")),
            source=None,
            evidence=evidence,
        ))

    if not info["parse_ok"]:
        findings.append(Finding(
            tier=Tier.C,
            detector=DETECTOR,
            signal="c2pa.unparsed",
            summary="C2PA/JUMBF data present but the box tree could not be parsed "
                    "(non-standard or damaged manifest)",
            evidence={"store_bytes": len(store)},
        ))

    findings.extend(_verification_findings(verification))
    return findings


def _verification_findings(v) -> list[Finding]:
    """Turn a Verification into user-facing findings.

    Integrity failures get their own findings rather than a footnote, because
    "this file carries someone else's provenance" is usually a more important
    fact than whatever that provenance says.
    """
    if v is None:
        return []
    out: list[Finding] = []
    evidence = v.to_dict()

    if v.binding_state == "mismatched":
        out.append(Finding(
            tier=Tier.A, detector=DETECTOR,
            signal="integrity.c2pa.binding_mismatch",
            summary=("C2PA manifest is NOT bound to this file — the hash in the "
                     "claim covers different bytes. The manifest was copied from "
                     "another asset, or the file was modified after signing"),
            evidence=evidence,
        ))
    if v.assertion_state == "mismatched":
        out.append(Finding(
            tier=Tier.A, detector=DETECTOR,
            signal="integrity.c2pa.assertion_mismatch",
            summary=(f"C2PA assertion hashes do not match: "
                     f"{', '.join(v.assertions_failed[:3])} — the manifest's "
                     f"contents were altered after signing"),
            evidence=evidence,
        ))
    if v.signature_state == "invalid":
        out.append(Finding(
            tier=Tier.A, detector=DETECTOR,
            signal="integrity.c2pa.signature_invalid",
            summary=f"C2PA signature does not verify: {v.signature_detail}",
            evidence=evidence,
        ))
    if v.chain_state == "broken":
        out.append(Finding(
            tier=Tier.B, detector=DETECTOR,
            signal="integrity.c2pa.chain_broken",
            summary=f"C2PA certificate chain does not validate: {v.chain_detail}",
            evidence=evidence,
        ))

    if v.cryptographically_valid and not out:
        signer = v.chain[0].describe() if v.chain else "unknown signer"
        # The identity caveat leads. "Verified" reads as an endorsement, and
        # without a trust list all that was verified is internal consistency —
        # anyone can self-sign a chain naming themselves Leica.
        if v.trust_state == "trusted":
            headline = f"C2PA manifest verified and signed by a trusted root"
            note = f"signer '{signer}'"
        elif v.trust_state == "untrusted-root":
            headline = ("C2PA manifest is internally valid but its root is NOT "
                        "in your trust list")
            note = f"claims to be signed by '{signer}' — identity NOT established"
        else:
            headline = ("C2PA manifest is internally valid; signer identity "
                        "UNVERIFIED (no trust list configured)")
            note = (f"claims to be signed by '{signer}' — a self-signed chain "
                    f"can name anyone, pass --trust to check this")
        out.append(Finding(
            tier=Tier.A, detector=DETECTOR,
            signal="c2pa.verified",
            summary=f"{headline}: {v.summary()}. {note}",
            evidence=evidence,
        ))
    elif v.revoked and v.signature_state == "valid" and not out:
        signer = v.chain[0].describe() if v.chain else "unknown signer"
        out.append(Finding(
            tier=Tier.B, detector=DETECTOR,
            signal="c2pa.credential_revoked",
            summary=(f"C2PA manifest is intact, but the signing certificate "
                     f"'{signer}' has been REVOKED — {v.revocation.detail}. "
                     f"The manifest may predate the revocation; without a "
                     f"validated timestamp that cannot be established"),
            evidence=evidence,
        ))
    elif (v.profile_problems and v.signature_state == "valid"
            and v.binding_state == "matched" and not out):
        signer = v.chain[0].describe() if v.chain else "unknown signer"
        out.append(Finding(
            tier=Tier.B, detector=DETECTOR,
            signal="c2pa.credential_nonconforming",
            summary=(f"C2PA manifest is intact and bound to this file, but the "
                     f"signing certificate '{signer}' violates the C2PA "
                     f"certificate profile: {'; '.join(v.profile_problems[:2])}"
                     f" — the reference implementation rejects such a "
                     f"credential"),
            evidence=evidence,
        ))
    elif (v.expired_unproven and v.signature_state == "valid"
            and v.binding_state == "matched" and not out):
        signer = v.chain[0].describe() if v.chain else "unknown signer"
        expiry = v.chain[0].not_after if v.chain else None
        out.append(Finding(
            tier=Tier.A, detector=DETECTOR,
            signal="c2pa.verified_expired",
            summary=(f"C2PA manifest checks out structurally, but the signing "
                     f"certificate '{signer}' had EXPIRED"
                     + (f" on {expiry:%Y-%m-%d}" if expiry else "")
                     + " and no validated timestamp proves the signature predates "
                       "that — the reference implementation treats this as "
                       "invalid: " + v.summary()),
            evidence=evidence,
        ))
    elif v.binding_unchecked and not out:
        out.append(Finding(
            tier=Tier.C, detector=DETECTOR,
            signal="info.c2pa.binding_unchecked",
            summary=(f"C2PA signature and assertions verify, but the binding to "
                     f"this file could not be checked: {v.binding_detail} — the "
                     f"manifest may or may not describe these bytes"),
            evidence=evidence,
        ))
    elif v.signature_only and not out:
        # Not an `integrity.` signal: C2PA 2.x update manifests legitimately
        # carry no hard binding, so forcing PROVENANCE-FORGED here would
        # condemn conforming files.
        out.append(Finding(
            tier=Tier.C, detector=DETECTOR,
            signal="info.c2pa.no_binding",
            summary=(f"C2PA signature is valid but the manifest asserts no hard "
                     f"binding to this file — it cannot be shown to describe "
                     f"these bytes (normal for an update manifest)"),
            evidence=evidence,
        ))
    elif v.signature_state in ("unchecked", "unsupported") and not out:
        out.append(Finding(
            tier=Tier.C, detector=DETECTOR,
            signal="info.c2pa.unverified",
            summary=(f"C2PA manifest could not be cryptographically verified "
                     f"({v.signature_detail or '; '.join(v.errors[:2]) or 'no signature'})"
                     f" — the provenance claim above is unconfirmed"),
            evidence=evidence,
        ))
    return out
