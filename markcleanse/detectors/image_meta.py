"""EXIF / XMP / IPTC metadata detector for images.

Two layers:

* pure-Python EXIF + XMP parsing (JPEG/PNG/WebP/GIF), always available;
* exiftool tags when the binary is installed, which adds HEIC/AVIF/TIFF/RAW
  and every obscure XMP namespace.

Metadata is Tier B: explicit, almost always honest, and trivially stripped or
forged. The IPTC `DigitalSourceType` field is the one exception we promote to
Tier A — it is the industry standard machine-readable "this was AI generated"
statement, written deliberately by the generator.
"""

from __future__ import annotations

import re
import struct

from ..context import FileCtx
from ..result import Finding, Tier
from .. import signatures as sig
from ..exif_tool import flat_strings
from .c2pa import iter_png_chunks, iter_riff_chunks
from .png_text import read_text_chunks

DETECTOR = "image_meta"

EXIF_TAGS = {
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0131: "Software",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x9C9B: "XPTitle",
    0x9C9C: "XPComment",
    0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords",
    0x9C9F: "XPSubject",
    0xA430: "OwnerName",
}
EXIF_SUB_TAGS = {0x9286: "UserComment", 0xA004: "RelatedSoundFile"}
EXIF_IFD_POINTER = 0x8769

#: Tags whose value we run through the generator signature table.
INTERESTING_TAG = re.compile(
    r"(software|creatortool|producer|description|comment|credit|source|"
    r"author|artist|creator|title|keywords|make|model|history|instructions|"
    r"digitalsourcetype|usage|rights|copyright|toolkit|generator|prompt)",
    re.I,
)

DST_RE = re.compile(
    r"digitalsourcetype[^a-zA-Z]{0,40}([A-Za-z:/\.\-]*?(trainedAlgorithmicMedia|"
    r"compositeWithTrainedAlgorithmicMedia|algorithmicMedia|algorithmicallyEnhanced|"
    r"digitalArt|compositeSynthetic|virtualRecording|softwareImage|"
    r"trainedAlgorithmicData|"
    r"digitalCapture|originalPhotograph|negativeFilm|positiveFilm|print))",
    re.I,
)


# ---------------------------------------------------------------------------
# Raw parsing helpers
# ---------------------------------------------------------------------------

def _jpeg_segments(data: bytes):
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
        if marker in (0xD9, 0xDA):
            break
        seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
        yield marker, data[i + 4:i + 2 + seg_len]
        i += 2 + seg_len


def exif_block(data: bytes, fmt: str) -> bytes | None:
    if fmt == "jpeg":
        for marker, payload in _jpeg_segments(data):
            if marker == 0xE1 and payload[:6] == b"Exif\x00\x00":
                return payload[6:]
    elif fmt == "png":
        for ctype, payload in iter_png_chunks(data):
            if ctype == b"eXIf":
                return payload
    elif fmt == "webp":
        for fourcc, payload in iter_riff_chunks(data):
            if fourcc == b"EXIF":
                return payload[6:] if payload[:6] == b"Exif\x00\x00" else payload
    elif fmt == "tiff":
        return data
    return None


def parse_exif(tiff: bytes) -> dict[str, str]:
    """Minimal TIFF/EXIF reader for the string tags we care about."""
    out: dict[str, str] = {}
    if len(tiff) < 8:
        return out
    if tiff[:2] == b"II":
        endian = "<"
    elif tiff[:2] == b"MM":
        endian = ">"
    else:
        return out
    try:
        (magic,) = struct.unpack(endian + "H", tiff[2:4])
        if magic != 42:
            return out
        (ifd0,) = struct.unpack(endian + "I", tiff[4:8])
        _read_ifd(tiff, ifd0, endian, EXIF_TAGS, out, follow=True)
    except Exception:
        pass
    return out


def _read_ifd(tiff: bytes, offset: int, endian: str, wanted: dict[int, str],
              out: dict[str, str], follow: bool = False, depth: int = 0) -> None:
    if depth > 4 or offset <= 0 or offset + 2 > len(tiff):
        return
    (count,) = struct.unpack(endian + "H", tiff[offset:offset + 2])
    if count > 4096:
        return
    for k in range(count):
        entry = offset + 2 + k * 12
        if entry + 12 > len(tiff):
            return
        tag, typ, num = struct.unpack(endian + "HHI", tiff[entry:entry + 8])
        raw_val = tiff[entry + 8:entry + 12]

        if follow and tag == EXIF_IFD_POINTER and typ == 4:
            (sub,) = struct.unpack(endian + "I", raw_val)
            _read_ifd(tiff, sub, endian, EXIF_SUB_TAGS, out, follow=False, depth=depth + 1)
            continue

        name = wanted.get(tag)
        if not name:
            continue

        size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8, 11: 4, 12: 8}.get(typ, 1)
        total = size * num
        if total > 4:
            (val_off,) = struct.unpack(endian + "I", raw_val)
            if val_off + total > len(tiff) or total > 65536:
                continue
            blob = tiff[val_off:val_off + total]
        else:
            blob = raw_val[:total]

        text = _decode_tag(name, typ, blob)
        if text:
            out[name] = text


def _decode_tag(name: str, typ: int, blob: bytes) -> str:
    if name.startswith("XP"):
        try:
            return blob.decode("utf-16-le").rstrip("\x00").strip()
        except UnicodeDecodeError:
            return ""
    if name == "UserComment" and len(blob) > 8:
        charset, body = blob[:8], blob[8:]
        if charset.startswith(b"UNICODE"):
            try:
                return body.decode("utf-16-be").rstrip("\x00").strip()
            except UnicodeDecodeError:
                return body.decode("utf-16-le", "replace").rstrip("\x00").strip()
        return body.decode("utf-8", "replace").rstrip("\x00").strip()
    if typ in (2, 7):
        return blob.decode("utf-8", "replace").rstrip("\x00").strip()
    return ""


_XMP_RE = re.compile(rb"<x:xmpmeta[^>]*>.*?</x:xmpmeta>", re.S)
_RDF_RE = re.compile(rb"<rdf:RDF[^>]*>.*?</rdf:RDF>", re.S)


def xmp_blocks(data: bytes, fmt: str) -> list[str]:
    blocks: list[str] = []
    for pattern in (_XMP_RE, _RDF_RE):
        for m in pattern.finditer(data[:8 * 1024 * 1024]):
            blocks.append(m.group(0).decode("utf-8", "replace"))
        if blocks:
            break
    if fmt == "png" and not blocks:
        for key, value in read_text_chunks(data):
            if key.lower().startswith("xml:com.adobe.xmp"):
                blocks.append(value)
    return blocks


_XMP_PAIR = re.compile(
    r"<([A-Za-z0-9_]+:[A-Za-z0-9_\-]+)[^>/]*>([^<>]{1,4000})</\1>"
    r"|([A-Za-z0-9_]+:[A-Za-z0-9_\-]+)\s*=\s*\"([^\"]{1,4000})\""
)


def xmp_pairs(block: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for m in _XMP_PAIR.finditer(block):
        key = m.group(1) or m.group(3)
        val = (m.group(2) or m.group(4) or "").strip()
        if key and val and not val.startswith("http://ns.adobe.com"):
            pairs.append((key, val))
    return pairs


def dimensions(data: bytes, fmt: str) -> tuple[int, int]:
    try:
        if fmt == "png" and len(data) > 24 and data[12:16] == b"IHDR":
            return struct.unpack(">II", data[16:24])
        if fmt == "gif" and len(data) > 10:
            return struct.unpack("<HH", data[6:10])
        if fmt == "jpeg":
            for marker, payload in _jpeg_segments(data):
                if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                    h, w = struct.unpack(">HH", payload[1:5])
                    return w, h
        if fmt == "webp":
            for fourcc, payload in iter_riff_chunks(data):
                if fourcc == b"VP8X" and len(payload) >= 10:
                    w = int.from_bytes(payload[4:7], "little") + 1
                    h = int.from_bytes(payload[7:10], "little") + 1
                    return w, h
                if fourcc == b"VP8 " and len(payload) >= 10:
                    w = struct.unpack("<H", payload[6:8])[0] & 0x3FFF
                    h = struct.unpack("<H", payload[8:10])[0] & 0x3FFF
                    return w, h
                if fourcc == b"VP8L" and len(payload) >= 5:
                    bits = int.from_bytes(payload[1:5], "little")
                    return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    except Exception:
        pass
    return 0, 0


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def detect(ctx: FileCtx) -> list[Finding]:
    if ctx.kind != "image":
        return []

    findings: list[Finding] = []
    pairs: list[tuple[str, str]] = []

    block = exif_block(ctx.data, ctx.fmt)
    exif = parse_exif(block) if block else {}
    pairs.extend(exif.items())

    xmp_raw = ""
    for xblock in xmp_blocks(ctx.data, ctx.fmt):
        xmp_raw += xblock
        pairs.extend(xmp_pairs(xblock))

    if ctx.exif:
        pairs.extend(flat_strings(ctx.exif))

    ctx.width, ctx.height = dimensions(ctx.data, ctx.fmt)
    if not ctx.width and ctx.exif:
        try:
            ctx.width = int(ctx.exif.get("File:ImageWidth") or 0)
            ctx.height = int(ctx.exif.get("File:ImageHeight") or 0)
        except (TypeError, ValueError):
            pass

    # --- IPTC digital source type (Tier A) -------------------------------
    haystack = xmp_raw + "\n" + "\n".join(f"{k}={v}" for k, v in pairs)
    for m in DST_RE.finditer(haystack):
        token = m.group(2).lower()
        if token in sig.IPTC_DIGITAL_SOURCE_AI:
            findings.append(Finding(
                tier=Tier.A, detector=DETECTOR,
                signal="iptc.digital_source_type.ai",
                summary=f"IPTC DigitalSourceType declares "
                        f"{sig.IPTC_DIGITAL_SOURCE_AI[token]}",
                source=_first_named(pairs),
                evidence={"value": m.group(1)},
            ))
            break
        if token in sig.IPTC_DIGITAL_SOURCE_CAPTURE:
            findings.append(Finding(
                tier=Tier.B, detector=DETECTOR,
                signal="capture.signed.iptc",
                summary=f"IPTC DigitalSourceType declares "
                        f"{sig.IPTC_DIGITAL_SOURCE_CAPTURE[token]}",
                evidence={"value": m.group(1)},
            ))
            break

    # --- Named generator in any metadata field (Tier B) -------------------
    seen_sources: set[str] = set()
    for key, value in pairs:
        if not INTERESTING_TAG.search(key):
            continue
        named = sig.identify(value)
        if not named or named in seen_sources:
            continue
        if _is_camera_field(key, value):
            continue
        seen_sources.add(named)
        findings.append(Finding(
            tier=Tier.B, detector=DETECTOR,
            signal="meta.generator_name",
            summary=f"Metadata field {key} = \"{_clip(value)}\" identifies {named}",
            source=named,
            evidence={"tag": key, "value": _clip(value, 400)},
        ))

    # --- Prompt-shaped payloads hiding in comment fields (Tier A) ---------
    for key, value in pairs:
        low = value.lower()
        hits = sum(marker in low for marker in sig.SD_PARAM_MARKERS)
        if hits >= 3:
            findings.append(Finding(
                tier=Tier.A, detector=DETECTOR,
                signal="meta.generation_parameters",
                summary=f"Metadata field {key} contains full diffusion generation "
                        f"parameters (prompt/steps/sampler/seed)",
                source=sig.identify(value) or "Stable Diffusion (unspecified UI)",
                evidence={"tag": key, "value": _clip(value, 2000)},
            ))
            break

    # --- Camera evidence (counter-evidence, reported for balance) ---------
    has_camera = bool(exif.get("Make") or exif.get("Model")) or any(
        k.endswith(("EXIF:Make", "IFD0:Make", "EXIF:Model", "IFD0:Model"))
        for k, _ in pairs
    )
    if has_camera and not any(f.tier is Tier.A for f in findings):
        make = exif.get("Make", "")
        model = exif.get("Model", "")
        findings.append(Finding(
            tier=Tier.C, detector=DETECTOR,
            signal="capture.exif_camera",
            summary=f"Camera EXIF present ({make} {model}".strip() + ") — "
                    "consistent with a real capture (forgeable)",
            evidence={"make": make, "model": model},
        ))

    # --- Heuristics: native generator dimensions with no provenance -------
    if ctx.width and ctx.height and not has_camera:
        candidates = sig.dimension_candidates(ctx.width, ctx.height)
        if candidates and not any(f.tier in (Tier.A, Tier.B) for f in findings):
            findings.append(Finding(
                tier=Tier.C, detector=DETECTOR,
                signal="heuristic.native_dimensions",
                summary=f"{ctx.width}x{ctx.height} is a native output size for "
                        f"{', '.join(candidates[:3])}, and the file carries no "
                        f"camera metadata",
                source=candidates[0] if len(candidates) == 1 else None,
                evidence={"width": ctx.width, "height": ctx.height,
                          "candidates": candidates},
            ))

    return findings


def _first_named(pairs: list[tuple[str, str]]) -> str | None:
    for key, value in pairs:
        if INTERESTING_TAG.search(key):
            named = sig.identify(value)
            if named:
                return named
    return None


def _is_camera_field(key: str, value: str) -> bool:
    """Suppress false hits like a Sony camera model containing a matched word."""
    return key.lower().endswith(("make", "model")) and len(value) < 24 and (
        value.lower() in ("meta", "sora", "grok")
    )


def _clip(text: str, limit: int = 90) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"
