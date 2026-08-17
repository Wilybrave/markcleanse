"""Removal of provenance markers, hidden payloads and privacy metadata.

Four categories, because they carry very different consequences:

``hidden``
    Invisible-character payloads and whitespace steganography. Removing these
    is the defensive action — the same channel carries watermarks, leak-tracing
    beacons and prompt-injection payloads, and none of them should survive into
    a document you are about to trust or forward.

``privacy``
    GPS coordinates, camera serial numbers, owner and author names, timestamps.
    Standard practice before publishing anything.

``generator``
    Metadata that names the tool: PNG generation parameters, ``Software``,
    ``CreatorTool``, PDF ``/Producer``.

``provenance``
    C2PA manifests. Requires an explicit opt-in, because unlike everything
    above it destroys a *verifiable* signed record rather than an unverifiable
    string — including the record that proves a photograph is a photograph.

What cannot be removed
----------------------

Pixel-space watermarks — Google SynthID, Meta's Stable Signature — survive
every operation in this module. They are not metadata; they are a modification
of the image content itself, recoverable only with the vendor's detector.
Stripping a Gemini image's metadata leaves SynthID fully intact, and the
sanitiser says so rather than implying the file came out clean.

All rewriting here is lossless and structural: chunks and segments are dropped
from the container, image data is never re-encoded.
"""

from __future__ import annotations

import io
import re
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass, field

from .context import FileCtx, sniff
from .detectors.c2pa import iter_png_chunks, iter_riff_chunks
from .detectors.unicode_wm import (BIDI_OVERRIDES, HOMOGLYPHS, RARE_SPACES,
                                   TAGS_START, TAGS_END, VS_HIGH, VS_LOW,
                                   ZERO_WIDTH, is_functional_zero_width)
from .signatures import identify

CATEGORIES = ("hidden", "privacy", "generator", "provenance")
DEFAULT_CATEGORIES = ("hidden", "privacy", "generator")


@dataclass
class Action:
    category: str
    detail: str
    bytes_removed: int = 0


@dataclass
class SanitizeResult:
    path: str
    data: bytes | None = None            # None when nothing changed
    actions: list[Action] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unsupported: str = ""

    @property
    def changed(self) -> bool:
        return bool(self.effective_actions) and self.data is not None

    @property
    def effective_actions(self) -> list["Action"]:
        """Actions that actually removed something (``info`` ones explain)."""
        return [a for a in self.actions if a.category != "info"]

    @property
    def bytes_removed(self) -> int:
        return sum(a.bytes_removed for a in self.actions)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "changed": self.changed,
            "bytes_removed": self.bytes_removed,
            "actions": [{"category": a.category, "detail": a.detail,
                         "bytes_removed": a.bytes_removed} for a in self.actions],
            "warnings": self.warnings,
            "unsupported": self.unsupported,
        }


# ---------------------------------------------------------------------------
# PNG
# ---------------------------------------------------------------------------

#: Chunks that affect how the image renders. Never dropped.
PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM",
            b"sRGB", b"iCCP", b"bKGD", b"pHYs", b"sBIT", b"hIST", b"sPLT",
            b"acTL", b"fcTL", b"fdAT"}

PNG_TEXT_CHUNKS = {b"tEXt", b"zTXt", b"iTXt"}

#: PNG text keys that carry generation parameters outright.
PNG_GENERATOR_KEYS = {"parameters", "prompt", "workflow", "sd-metadata",
                      "invokeai_metadata", "invokeai_graph", "dream",
                      "fooocus_scheme", "fooocus_v2_expansion",
                      "software", "source", "comment", "description",
                      "aigenerated", "generation_data"}

PNG_PRIVACY_KEYS = {"author", "creator", "copyright", "artist", "owner",
                    "email", "url", "disclaimer", "warning", "creation time",
                    "title"}


def _png_chunk(ctype: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + ctype + payload
            + struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF))


def _png_text_key(ctype: bytes, payload: bytes) -> str:
    key, _, _rest = payload.partition(b"\x00")
    return key.decode("latin-1", "replace").strip().lower()


def sanitize_png(data: bytes, cats: set[str]) -> tuple[bytes, list[Action]]:
    actions: list[Action] = []
    out = [data[:8]]

    for ctype, payload in iter_png_chunks(data):
        size = len(payload) + 12
        drop_reason = None

        if ctype == b"caBX":
            if "provenance" in cats:
                drop_reason = ("provenance", "C2PA manifest (caBX chunk)")
        elif ctype == b"eXIf":
            if "privacy" in cats or "generator" in cats:
                drop_reason = ("privacy", "embedded EXIF block")
        elif ctype == b"tIME":
            if "privacy" in cats:
                drop_reason = ("privacy", "modification timestamp")
        elif ctype in PNG_TEXT_CHUNKS:
            key = _png_text_key(ctype, payload)
            named = identify(payload.decode("latin-1", "replace"))
            if key.startswith("xml:com.adobe.xmp"):
                if "generator" in cats or "privacy" in cats:
                    drop_reason = ("generator", "XMP packet")
            elif key in PNG_GENERATOR_KEYS or named:
                if "generator" in cats:
                    label = f"text chunk '{key or ctype.decode()}'"
                    if named:
                        label += f" naming {named}"
                    drop_reason = ("generator", label)
            elif key in PNG_PRIVACY_KEYS:
                if "privacy" in cats:
                    drop_reason = ("privacy", f"text chunk '{key}'")
            elif "generator" in cats:
                drop_reason = ("generator", f"text chunk '{key or 'unnamed'}'")
        elif ctype not in PNG_KEEP:
            # An unknown ancillary chunk. Lowercase first letter = safe to copy.
            if "provenance" in cats and ctype[:1].islower() is False:
                pass

        if drop_reason:
            category, detail = drop_reason
            if category in cats:
                actions.append(Action(category, detail, size))
                continue
        out.append(_png_chunk(ctype, payload))

    cleaned = b"".join(out)
    if "hidden" in cats:
        cleaned, lsb = _scrub_stealth_lsb(cleaned)
        actions.extend(lsb)
    return cleaned, actions


def _scrub_stealth_lsb(data: bytes) -> tuple[bytes, list[Action]]:
    """Zero the low bit of every sample when a stealth payload is present.

    This is the one payload that lives in the pixels rather than the metadata,
    so chunk stripping cannot touch it. Clearing the least significant bit of
    each sample destroys the carrier. It genuinely alters the image — by one
    step out of 256 per channel, which is imperceptible but not nothing — so it
    only runs when a payload was actually decoded, never speculatively.

    The image is re-encoded with filter type 0 on every row. That is a larger
    file than an optimised encoder would produce; correctness matters more here
    than bytes, and re-filtering could reintroduce carrier-shaped noise.
    """
    from .detectors import stealth_png

    if not stealth_png.extract(data):
        return data, []
    decoded = stealth_png.decode_png(data)
    if decoded is None:                       # 16-bit, palette, interlaced …
        return data, []
    width, height, channels, samples = decoded
    if len(samples) < width * height * channels:
        return data, []

    scrubbed = bytes(b & 0xFE for b in samples)
    if scrubbed == samples:
        return data, []

    stride = width * channels
    raw = bytearray()
    for row in range(height):
        raw.append(0)                          # filter: None
        raw += scrubbed[row * stride:(row + 1) * stride]
    idat = zlib.compress(bytes(raw), 9)

    out = [data[:8]]
    written = False
    for ctype, payload in iter_png_chunks(data):
        if ctype == b"IDAT":
            if not written:                    # collapse the IDAT run into one
                out.append(_png_chunk(b"IDAT", idat))
                written = True
            continue
        out.append(_png_chunk(ctype, payload))
    if not written:
        return data, []

    rebuilt = b"".join(out)
    # Prove it worked rather than assuming: the decoder that found the payload
    # must no longer find one.
    if stealth_png.extract(rebuilt):
        return data, []
    return rebuilt, [Action("hidden",
                            "stealth pixel payload (cleared the low bit of "
                            "every sample — pixels altered by 1/256)",
                            max(0, len(data) - len(rebuilt)))]


# ---------------------------------------------------------------------------
# JPEG
# ---------------------------------------------------------------------------

#: APP segments safe to keep: JFIF (0xE0), ICC profile (0xE2), Adobe (0xEE).
JPEG_KEEP_APP = {0xE0, 0xE2, 0xEE}


def sanitize_jpeg(data: bytes, cats: set[str]) -> tuple[bytes, list[Action]]:
    actions: list[Action] = []
    out = bytearray(data[:2])
    i = 2
    n = len(data)

    while i + 4 <= n:
        if data[i] != 0xFF:
            out.append(data[i])
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            out += data[i:i + 2]
            i += 2
            continue
        if marker == 0xDA:
            # Entropy-coded data runs to EOI. Anything after EOI is appended
            # payload, not image — a classic place to staple a watermark or a
            # tracking blob that survives every metadata scrub.
            end = data.rfind(b"\xff\xd9")
            if end > i:
                trailing = len(data) - (end + 2)
                out += data[i:end + 2]
                if trailing > 0:
                    actions.append(Action("hidden",
                                          f"{trailing} bytes appended after the "
                                          f"JPEG end-of-image marker", trailing))
            else:
                out += data[i:]
            break
        seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
        segment = data[i:i + 2 + seg_len]
        payload = data[i + 4:i + 2 + seg_len]
        drop = None

        if marker == 0xEB and payload[:2] == b"JP":
            if "provenance" in cats:
                drop = ("provenance", "C2PA manifest (APP11/JUMBF)")
        elif marker == 0xE1:
            if payload[:6] == b"Exif\x00\x00":
                if "privacy" in cats or "generator" in cats:
                    drop = ("privacy", "EXIF block (APP1)")
            elif b"ns.adobe.com/xap" in payload[:64]:
                if "generator" in cats or "privacy" in cats:
                    drop = ("generator", "XMP packet (APP1)")
            elif "privacy" in cats:
                drop = ("privacy", "APP1 segment")
        elif marker == 0xED:
            if "privacy" in cats:
                drop = ("privacy", "Photoshop/IPTC block (APP13)")
        elif marker == 0xEC:
            if "privacy" in cats:
                drop = ("privacy", "APP12 segment")
        elif marker == 0xFE:
            if "privacy" in cats or "generator" in cats:
                drop = ("generator", "JPEG comment")
        elif 0xE0 <= marker <= 0xEF and marker not in JPEG_KEEP_APP:
            if "privacy" in cats:
                drop = ("privacy", f"APP{marker - 0xE0} segment")

        if drop and drop[0] in cats:
            actions.append(Action(drop[0], drop[1], len(segment)))
        else:
            out += segment
        i += 2 + seg_len

    return bytes(out), actions


# ---------------------------------------------------------------------------
# WebP
# ---------------------------------------------------------------------------

#: VP8X feature flag bits that must be cleared when their chunk is dropped.
VP8X_EXIF = 0x08
VP8X_XMP = 0x04


def sanitize_webp(data: bytes, cats: set[str]) -> tuple[bytes, list[Action]]:
    actions: list[Action] = []
    kept: list[tuple[bytes, bytes]] = []
    cleared = 0

    for fourcc, payload in iter_riff_chunks(data):
        size = 8 + len(payload) + (len(payload) & 1)
        if fourcc in (b"C2PA", b"c2pa"):
            if "provenance" in cats:
                actions.append(Action("provenance", "C2PA manifest chunk", size))
                continue
        elif fourcc == b"EXIF":
            if "privacy" in cats or "generator" in cats:
                actions.append(Action("privacy", "EXIF chunk", size))
                cleared |= VP8X_EXIF
                continue
        elif fourcc == b"XMP ":
            if "generator" in cats or "privacy" in cats:
                actions.append(Action("generator", "XMP chunk", size))
                cleared |= VP8X_XMP
                continue
        kept.append((fourcc, payload))

    if not actions:
        return data, actions

    # The VP8X header advertises which optional chunks exist; leaving stale
    # flags set produces a file some decoders reject.
    rebuilt: list[bytes] = []
    for fourcc, payload in kept:
        if fourcc == b"VP8X" and cleared and payload:
            payload = bytes([payload[0] & ~cleared]) + payload[1:]
        chunk = fourcc + struct.pack("<I", len(payload)) + payload
        if len(payload) & 1:
            chunk += b"\x00"
        rebuilt.append(chunk)

    body = b"WEBP" + b"".join(rebuilt)
    return b"RIFF" + struct.pack("<I", len(body)) + body, actions


# ---------------------------------------------------------------------------
# GIF
# ---------------------------------------------------------------------------

def sanitize_gif(data: bytes, cats: set[str]) -> tuple[bytes, list[Action]]:
    if "provenance" not in cats:
        return data, []
    idx = data.find(b"\x21\xff\x0bC2PA_GIF\x00")
    if idx < 0:
        return data, []
    # Walk the sub-block chain to find where the extension ends.
    i = idx + 14
    while i < len(data) and data[i]:
        i += 1 + data[i]
    end = min(i + 1, len(data))
    return (data[:idx] + data[end:],
            [Action("provenance", "C2PA application extension", end - idx)])


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------

_TRAILING_WS = re.compile(r"[ \t]+$", re.M)
_DOUBLE_SPACE = re.compile(r"(?<=[A-Za-z,;:.!?’'\)])  +(?=[A-Za-z\"'“(])")


def whitespace_payload_present(text: str) -> bool:
    """Is there actual evidence of a whitespace-encoded payload?

    Spacing changes are *visible* edits. Stripping trailing whitespace and
    collapsing double spaces across every document someone scrubs for metadata
    would silently reflow their prose, so those transforms are gated on the
    same test the detector uses rather than applied on principle.
    """
    from .detectors import whitespace_wm as ws

    channels = [ws.inter_word_bits(text), ws.inter_sentence_bits(text),
                ws.trailing_bits(text)[0]]
    for bits in channels:
        ones = bits.count("1")
        if len(bits) < ws.MIN_BITS_DECODE or ones in (0, len(bits)):
            continue
        if ws.decode_bits(bits):
            return True
        if len(bits) >= ws.MIN_BITS_ENTROPY and ws.entropy(bits) >= ws.MIN_ENTROPY:
            return True
    return False


def sanitize_text(text: str, cats: set[str],
                  xml_safe: bool = False) -> tuple[str, list[Action]]:
    """Strip hidden payload carriers.

    Invisible characters are always removed — they cannot change how the text
    renders. Whitespace normalisation can, so it only runs when a payload is
    actually detected, and never inside XML (`xml_safe`), where our spacing is
    markup rather than prose.
    """
    if "hidden" not in cats:
        return text, []

    actions: list[Action] = []
    original = text
    touch_spacing = not xml_safe and whitespace_payload_present(text)

    # --- Unicode Tags block ------------------------------------------------
    tags = sum(1 for c in text if TAGS_START <= ord(c) <= TAGS_END)
    if tags:
        text = "".join(c for c in text if not TAGS_START <= ord(c) <= TAGS_END)
        actions.append(Action("hidden", f"{tags} Unicode Tag characters", tags))

    # --- zero-width, keeping the ones that do a job ------------------------
    removed_zw = 0
    if any(c in ZERO_WIDTH for c in text):
        kept = []
        for i, ch in enumerate(text):
            if ch in ZERO_WIDTH and not is_functional_zero_width(text, i):
                removed_zw += 1
                continue
            kept.append(ch)
        text = "".join(kept)
        if removed_zw:
            actions.append(Action(
                "hidden",
                f"{removed_zw} zero-width characters (emoji joiners and "
                f"script-required ZWNJ preserved)", removed_zw))

    # --- variation selectors carrying bytes --------------------------------
    vs = [i for i, c in enumerate(text) if ord(c) in VS_LOW or ord(c) in VS_HIGH]
    if len(vs) >= 4:
        kept = []
        removed_vs = 0
        for i, ch in enumerate(text):
            cp = ord(ch)
            if (cp in VS_LOW or cp in VS_HIGH) and not _emoji_adjacent(text, i):
                removed_vs += 1
                continue
            kept.append(ch)
        if removed_vs:
            text = "".join(kept)
            actions.append(Action("hidden",
                                  f"{removed_vs} variation selectors carrying a "
                                  f"byte payload (emoji presentation preserved)",
                                  removed_vs))

    # --- bidi overrides ----------------------------------------------------
    overrides = sum(1 for c in text if c in BIDI_OVERRIDES)
    if overrides:
        text = "".join(c for c in text if c not in BIDI_OVERRIDES)
        actions.append(Action("hidden", f"{overrides} bidirectional override "
                                        f"characters", overrides))

    # --- whitespace steganography -----------------------------------------
    rare = sum(1 for c in text if c in RARE_SPACES) if touch_spacing else 0
    if rare:
        text = "".join(" " if c in RARE_SPACES else c for c in text)
        actions.append(Action("hidden", f"{rare} rare space characters "
                                        f"normalised to U+0020", rare))

    trailing = len(_TRAILING_WS.findall(text)) if touch_spacing else 0
    if trailing:
        text = _TRAILING_WS.sub("", text)
        actions.append(Action("hidden", f"trailing whitespace on {trailing} lines",
                              trailing))

    doubles = len(_DOUBLE_SPACE.findall(text)) if touch_spacing else 0
    if doubles:
        text = _DOUBLE_SPACE.sub(" ", text)
        actions.append(Action("hidden", f"{doubles} multi-space gaps between "
                                        f"words collapsed", doubles))

    # --- homoglyphs --------------------------------------------------------
    swapped = 0
    if any(c in HOMOGLYPHS for c in text):
        chars = list(text)
        for i, ch in enumerate(chars):
            if ch in HOMOGLYPHS and _latin_neighbour(chars, i):
                chars[i] = HOMOGLYPHS[ch]
                swapped += 1
        if swapped:
            text = "".join(chars)
            actions.append(Action("hidden", f"{swapped} Cyrillic/Greek homoglyphs "
                                            f"normalised to Latin", swapped))

    if text == original:
        return original, []
    return text, actions


def _emoji_adjacent(text: str, index: int) -> bool:
    if index == 0:
        return False
    return unicodedata.category(text[index - 1]) in ("So", "Sk")


def _latin_neighbour(chars: list[str], index: int) -> bool:
    for j in (index - 1, index + 1):
        if 0 <= j < len(chars):
            ch = chars[j]
            if ch.isalpha() and "LATIN" in unicodedata.name(ch, ""):
                return True
    return False


# ---------------------------------------------------------------------------
# OOXML
# ---------------------------------------------------------------------------

OOXML_META_PARTS = {"docProps/app.xml", "docProps/core.xml",
                    "docProps/custom.xml", "meta.xml"}

#: Media inside a container gets sanitised in its own right.
EMBEDDED_MEDIA_EXTS = (".png", ".jpg", ".jpeg", ".jpe", ".webp", ".gif")


def sanitize_ooxml(data: bytes, cats: set[str]) -> tuple[bytes, list[Action]]:
    actions: list[Action] = []
    try:
        src = zipfile.ZipFile(io.BytesIO(data))
        names = src.namelist()
    except Exception:
        return data, []

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for name in names:
            try:
                blob = src.read(name)
            except Exception:
                continue
            if name in OOXML_META_PARTS and ("privacy" in cats or "generator" in cats):
                actions.append(Action("privacy", f"document properties ({name})",
                                      len(blob)))
                continue
            # Embedded media carries its own metadata and manifests. Detection
            # reaches into word/media/, so removal has to as well — otherwise a
            # sanitised deliverable still flags on the very next scan.
            if name.lower().endswith(EMBEDDED_MEDIA_EXTS):
                nested = sanitize_bytes(name, blob, cats)
                if nested.changed:
                    actions.extend(Action(a.category, f"{name}: {a.detail}",
                                          a.bytes_removed) for a in nested.actions)
                    blob = nested.data
                dst.writestr(name, blob)
                continue

            if "hidden" in cats and name.endswith((".xml", ".xhtml", ".html")):
                try:
                    text = blob.decode("utf-8")
                except UnicodeDecodeError:
                    dst.writestr(name, blob)
                    continue
                cleaned, sub = sanitize_text(text, {"hidden"}, xml_safe=True)
                if sub:
                    actions.extend(Action(a.category, f"{name}: {a.detail}",
                                          a.bytes_removed) for a in sub)
                    blob = cleaned.encode("utf-8")
            dst.writestr(name, blob)

    return (buf.getvalue(), actions) if actions else (data, [])
# --------------------------------------------------------------------------
# BMFF (AVIF / HEIC / HEIF / MP4)
# --------------------------------------------------------------------------

def sanitize_bmff(data: bytes, cats: set[str]) -> tuple[bytes, list[Action]]:
    """Drop C2PA / XMP / EXIF boxes from AVIF, HEIC, HEIF and MP4.

    `iloc` extents are absolute file offsets, so removing a box that sits
    *before* referenced media silently invalidates every item in the file.
    Rather than rewrite the offset table — easy to get subtly wrong, and a
    corrupted deliverable is worse than an un-scrubbed one — only boxes that
    lie beyond the last referenced byte are removed. Anything else is reported
    as skipped, with the reason.
    """
    from . import bmff

    boxes = bmff.walk(data)
    if not boxes:
        return data, []

    # Everything that other structures point at by absolute file offset:
    # `iloc` extents in HEIF/AVIF, and the media boxes that MP4's `stco`/`co64`
    # tables index. Only boxes lying beyond all of it can be dropped without
    # rewriting an offset table.
    extents = bmff.iloc_absolute_extents(data)
    safe_from = max((off + length for off, length in extents), default=0)
    for box in bmff.flatten(boxes):
        if box.type in (b"mdat", b"idat", b"moov", b"moof"):
            safe_from = max(safe_from, box.end)

    actions: list[Action] = []
    drop: list[tuple[int, int]] = []
    blocked = 0

    for box in boxes:
        category = None
        if box.type == b"uuid" and box.uuid == C2PA_BMFF_UUID:
            category = ("provenance", "C2PA manifest (uuid box)")
        elif box.type in (b"xml ", b"XMP_"):
            category = ("generator", f"{box.type.decode('latin-1').strip()} metadata box")
        if category is None or category[0] not in cats:
            continue
        if box.offset < safe_from:
            blocked += 1
            continue
        drop.append((box.offset, box.end))
        actions.append(Action(category[0], category[1], box.size))

    if not drop:
        if blocked:
            return data, [Action(
                "info", f"{blocked} metadata box(es) left in place: they sit "
                        f"before media referenced by absolute file offsets, and "
                        f"removing them would invalidate the offset tables", 0)]
        return data, []
    if blocked:
        actions.append(Action(
            "info", f"{blocked} metadata box(es) left in place: they sit before "
                    f"media referenced by absolute file offsets, and removing "
                    f"them would invalidate the offset tables", 0))

    out = bytearray()
    cursor = 0
    for start, end in sorted(drop):
        out += data[cursor:start]
        cursor = end
    out += data[cursor:]
    return bytes(out), actions


C2PA_BMFF_UUID = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")




# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

#: Document-info keys worth erasing. Values, not the keys: the dictionary keeps
#: its shape so every byte offset in the file stays valid.
PDF_INFO_KEYS = (b"Producer", b"Creator", b"Author", b"Title", b"Subject",
                 b"Keywords")

_PDF_INFO_RE = re.compile(
    rb"/(" + b"|".join(PDF_INFO_KEYS) + rb")\s*\(((?:\\.|[^\\)])*)\)")


def sanitize_pdf(data: bytes, cats: set[str]) -> tuple[bytes, list[Action]]:
    """Blank PDF document-info strings in place, without restructuring.

    Deliberately not a rewriter. Rebuilding a PDF (ghostscript, or writing a
    fresh object graph) re-renders the document, drops signatures and forms,
    and — measured on this machine — can turn a 596 KB file into a 2 KB stub
    that still passes a header check. An incremental update, which is what
    `exiftool -all=` performs, leaves the original bytes in the file where they
    remain recoverable, so it does not actually remove anything.

    What is safe is overwriting a literal string with spaces of exactly the same
    length: the old bytes are gone, every offset in the xref table still points
    where it did, and nothing is re-encoded. That only works for metadata
    sitting in the file as plain bytes; inside a compressed object stream it
    cannot be reached without re-encoding, and then this refuses and says so.
    """
    if not ({"generator", "privacy"} & cats):
        return data, []

    out = bytearray(data)
    actions: list[Action] = []
    for match in _PDF_INFO_RE.finditer(data):
        key = match.group(1).decode("ascii")
        value = match.group(2)
        if not value.strip():
            continue
        named = identify(value.decode("latin-1", "replace"))
        privacy_key = key in ("Author", "Title", "Subject", "Keywords")
        if named or key in ("Producer", "Creator"):
            if "generator" not in cats:
                continue
        elif privacy_key:
            if "privacy" not in cats:
                continue
        else:
            continue
        start, end = match.span(2)
        out[start:end] = b" " * (end - start)
        label = f"/{key} = \"{value.decode('latin-1', 'replace')[:60]}\""
        if named:
            label += f" naming {named}"
        actions.append(Action("generator" if not privacy_key else "privacy",
                              label + " (blanked in place)", 0))

    if not actions and (b"/Producer" in data or b"/Creator" in data
                        or b"ObjStm" in data):
        actions.append(Action(
            "info",
            "this PDF keeps its document info inside a compressed object "
            "stream (or as a hex string), which blanking in place cannot reach "
            "without re-encoding the file. `exiftool -all=` writes an "
            "incremental update, so the old bytes stay recoverable; a clean "
            "re-export is the only real fix"))
    return bytes(out), actions


BINARY_HANDLERS = {
    "pdf": sanitize_pdf,
    "png": sanitize_png,
    "jpeg": sanitize_jpeg,
    "webp": sanitize_webp,
    "gif": sanitize_gif,
    "avif": sanitize_bmff,
    "heic": sanitize_bmff,
    "bmff": sanitize_bmff,
    "docx": sanitize_ooxml,
    "xlsx": sanitize_ooxml,
    "pptx": sanitize_ooxml,
    "odt": sanitize_ooxml,
    "ods": sanitize_ooxml,
    "odp": sanitize_ooxml,
    "epub": sanitize_ooxml,
}



#: Formats we deliberately refuse to rewrite rather than risk corrupting.
REFUSED = {
    "tiff": ("TIFF rewriting is not implemented — use `exiftool -all= file`"),
}


def sanitize_bytes(name: str, data: bytes,
                   categories: set[str] | None = None) -> SanitizeResult:
    cats = set(categories or DEFAULT_CATEGORIES)
    result = SanitizeResult(path=name)
    fmt, kind = sniff(name, data)

    if fmt in REFUSED:
        result.unsupported = REFUSED[fmt]
        return result

    handler = BINARY_HANDLERS.get(fmt)
    if handler:
        new_data, actions = handler(data, cats)
    elif kind == "text":
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            result.unsupported = "not valid UTF-8 text"
            return result
        cleaned, actions = sanitize_text(text, cats)
        new_data = cleaned.encode("utf-8")
    else:
        result.unsupported = f"no sanitiser for {fmt} files"
        return result

    notes = [a for a in actions if a.category == "info"]
    if [a for a in actions if a.category != "info"]:
        result.data = new_data
        result.actions = actions
    result.warnings.extend(a.detail for a in notes)
    _add_warnings(result, data, fmt, cats, changed=bool(actions))
    return result


def _add_warnings(result: SanitizeResult, original: bytes, fmt: str,
                  cats: set[str], changed: bool) -> None:
    """Say plainly what survived, so nobody assumes the file is now clean.

    The pixel-watermark warning is attached only when something was actually
    removed: that is the moment someone might conclude the file is clean.
    """
    from .detectors import c2pa as c2pa_mod

    lowered = original[:200000].lower()
    if changed and fmt in ("png", "jpeg", "webp", "gif"):
        result.warnings.append(
            "Pixel-space watermarks are NOT removed by metadata stripping. If "
            "this image came from Google (SynthID) or Meta, the watermark is "
            "still present in the image data and remains detectable by the "
            "vendor. Re-encoding, cropping and resizing do not reliably remove "
            "it either.")

    if "provenance" not in cats and c2pa_mod.extract_store(original, fmt):
        result.warnings.append(
            "A C2PA manifest is present and was kept. Pass --categories "
            "provenance to remove it — note that this destroys a signed, "
            "verifiable record, including one that may attest the file is a "
            "genuine capture.")

    if changed and (b"synthid" in lowered or b"gemini" in lowered
                    or b"imagen" in lowered):
        result.warnings.append(
            "Google-family origin was indicated in this file's metadata; "
            "SynthID is very likely embedded in the pixels regardless of what "
            "was stripped here.")
