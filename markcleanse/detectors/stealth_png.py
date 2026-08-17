"""Stealth pnginfo — generation data hidden in the image's own pixels.

NovelAI, and the `stealth_pnginfo` extension for A1111, embed the full
generation record in the *least significant bits* of the alpha channel (or of
the RGB channels for images without alpha). It is invisible, it is not
metadata, and it therefore survives every metadata strip, re-save through a
lossless encoder, and `exiftool -all=`.

That makes it the one pixel-space watermark this tool can actually read: the
encoding is public, so unlike SynthID there is no key to be missing. When it
decodes, the result is the prompt and seed in plain text — Tier A.

Layout, read as a bit stream in **column-major** order (x outer, y inner),
most-significant bit first:

    <magic string> <32-bit big-endian payload length in bits> <payload>

    stealth_pnginfo   alpha channel, UTF-8 JSON
    stealth_pngcomp   alpha channel, gzip-compressed JSON
    stealth_rgbinfo   RGB channels, UTF-8 JSON
    stealth_rgbcomp   RGB channels, gzip-compressed JSON

Removing it means changing pixels, so `sanitize` reports it rather than
silently rewriting the image — see the finding text.
"""

from __future__ import annotations

import gzip
import json
import struct
import zlib

from ..context import FileCtx
from ..result import Finding, Tier

DETECTOR = "stealth_png"

MAGICS = {
    "stealth_pnginfo": ("alpha", False),
    "stealth_pngcomp": ("alpha", True),
    "stealth_rgbinfo": ("rgb", False),
    "stealth_rgbcomp": ("rgb", True),
}
MAGIC_BITS = max(len(m) for m in MAGICS) * 8

#: Decoding is O(pixels); refuse absurd images rather than stall a scan.
MAX_PIXELS = 64 * 1024 * 1024
MAX_PAYLOAD_BITS = 64 * 1024 * 1024


# ---------------------------------------------------------------------------
# Minimal PNG decode — enough to recover the raw sample bytes
# ---------------------------------------------------------------------------

def decode_png(data: bytes, max_rows: int | None = None
               ) -> tuple[int, int, int, bytes] | None:
    """Return (width, height, channels, samples) for 8-bit non-interlaced PNG.

    Written out rather than pulled from Pillow so the zero-dependency promise
    holds; anything unusual (16-bit, palette, interlaced) returns None instead
    of guessing.
    """
    from .c2pa import iter_png_chunks

    header = None
    idat: list[bytes] = []
    for ctype, payload in iter_png_chunks(data):
        if ctype == b"IHDR" and len(payload) >= 13:
            header = struct.unpack(">IIBBBBB", payload[:13])
        elif ctype == b"IDAT":
            idat.append(payload)
        elif ctype == b"IEND":
            break
    if header is None or not idat:
        return None

    width, height, depth, colour, compression, filt, interlace = header
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colour)
    if (channels is None or depth != 8 or colour == 3 or interlace != 0
            or compression != 0 or filt != 0):
        return None
    if width * height > MAX_PIXELS or width == 0 or height == 0:
        return None

    try:
        raw = zlib.decompress(b"".join(idat))
    except zlib.error:
        return None

    stride = width * channels
    if len(raw) < (stride + 1) * height:
        return None

    rows = height if max_rows is None else min(height, max_rows)
    out = bytearray(stride * rows)
    prev = bytearray(stride)
    pos = 0
    for row in range(rows):
        ftype = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        _unfilter(ftype, line, prev, channels)
        out[row * stride:(row + 1) * stride] = line
        prev = line
    return width, height, channels, bytes(out)


def _unfilter(ftype: int, line: bytearray, prev: bytearray, bpp: int) -> None:
    if ftype == 0:
        return
    for i in range(len(line)):
        a = line[i - bpp] if i >= bpp else 0
        b = prev[i]
        c = prev[i - bpp] if i >= bpp else 0
        if ftype == 1:
            line[i] = (line[i] + a) & 0xFF
        elif ftype == 2:
            line[i] = (line[i] + b) & 0xFF
        elif ftype == 3:
            line[i] = (line[i] + ((a + b) >> 1)) & 0xFF
        elif ftype == 4:
            p = a + b - c
            pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
            pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
            line[i] = (line[i] + pred) & 0xFF


# ---------------------------------------------------------------------------
# Bit stream
# ---------------------------------------------------------------------------

def _bits(samples: bytes, width: int, height: int, channels: int, mode: str):
    """Yield LSBs in column-major order, the order the encoders write them."""
    stride = width * channels
    if mode == "alpha":
        if channels not in (2, 4):
            return
        offsets = (channels - 1,)
    else:
        offsets = (0, 1, 2) if channels >= 3 else (0,)
    for x in range(width):
        base_x = x * channels
        for y in range(height):
            row = y * stride
            for off in offsets:
                yield samples[row + base_x + off] & 1


def _take(stream, count: int) -> bytes | None:
    out = bytearray()
    acc = 0
    filled = 0
    for _ in range(count):
        bit = next(stream, None)
        if bit is None:
            return None
        acc = (acc << 1) | bit
        filled += 1
        if filled == 8:
            out.append(acc)
            acc = filled = 0
    if filled:
        out.append(acc << (8 - filled))
    return bytes(out)


def _magic_present(data: bytes) -> bool:
    """Cheap rejection: does column 0 begin with a stealth magic?

    The payload is written column-major, so the magic lives entirely in the
    first column — which needs only the first ~120 rows unfiltered, not the
    whole image. Decoding every PNG in full made a 700-file scan five times
    slower for a signal that is absent from almost all of them.
    """
    header = decode_png(data, max_rows=1)
    if header is None:
        return False
    width, height, channels, _ = header
    needed = MAGIC_BITS if channels in (2, 4) else (MAGIC_BITS + 2) // 3
    if height < needed:
        return True                      # too short to probe cheaply; do it properly

    decoded = decode_png(data, max_rows=needed)
    if decoded is None:
        return False
    _w, _h, channels, samples = decoded
    stride = width * channels
    for mode, offsets in (("alpha", (channels - 1,)), ("rgb", (0, 1, 2))):
        if mode == "alpha" and channels not in (2, 4):
            continue
        if mode == "rgb" and channels < 3:
            continue
        bits = []
        for y in range(needed):
            for off in offsets:
                bits.append(samples[y * stride + off] & 1)
        probe = _take(iter(bits), MAGIC_BITS)
        if probe and any(probe.decode("latin-1", "replace").startswith(m)
                         for m in MAGICS):
            return True
    return False


def extract(data: bytes) -> dict | None:
    """Recover a stealth payload, or None."""
    if not _magic_present(data):
        return None
    decoded = decode_png(data)
    if decoded is None:
        return None
    width, height, channels, samples = decoded

    for mode in ("alpha", "rgb"):
        if mode == "alpha" and channels not in (2, 4):
            continue
        stream = _bits(samples, width, height, channels, mode)
        head = _take(stream, MAGIC_BITS)
        if head is None:
            continue
        text = head.decode("latin-1", "replace")
        magic = next((m for m in MAGICS
                      if text.startswith(m) and MAGICS[m][0] == mode), None)
        if magic is None:
            continue

        # Re-open the stream and skip exactly the magic, since the magics
        # differ in length and the probe read a fixed number of bits.
        stream = _bits(samples, width, height, channels, mode)
        _take(stream, len(magic) * 8)
        length_bytes = _take(stream, 32)
        if not length_bytes or len(length_bytes) < 4:
            continue
        bit_len = struct.unpack(">I", length_bytes)[0]
        if not 0 < bit_len <= MAX_PAYLOAD_BITS:
            continue

        payload = _take(stream, bit_len)
        if payload is None:
            continue
        payload = payload[:bit_len // 8]

        compressed = MAGICS[magic][1]
        if compressed:
            try:
                payload = gzip.decompress(payload)
            except (OSError, zlib.error):
                continue
        try:
            text_payload = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue
        return {"magic": magic, "channel": mode, "compressed": compressed,
                "payload": text_payload}
    return None


# ---------------------------------------------------------------------------

def detect(ctx: FileCtx) -> list[Finding]:
    if ctx.fmt != "png" or ctx.kind != "image":
        return []
    try:
        found = extract(ctx.data)
    except Exception:
        return []
    if not found:
        return []

    payload = found["payload"]
    source = "NovelAI" if "novelai" in payload.lower() else None
    prompt = ""
    try:
        parsed = json.loads(payload)
        if isinstance(parsed, dict):
            for key in ("Description", "prompt", "parameters", "Comment"):
                if isinstance(parsed.get(key), str):
                    prompt = parsed[key]
                    break
            if not source and isinstance(parsed.get("Software"), str):
                from ..signatures import identify
                source = identify(parsed["Software"])
    except (json.JSONDecodeError, ValueError):
        prompt = payload

    return [Finding(
        tier=Tier.A, detector=DETECTOR,
        signal="pixels.stealth_pnginfo",
        summary=(f"Generation data hidden in the image's {found['channel']} "
                 f"least-significant bits ({found['magic']})"
                 + (f": \"{prompt[:90]}\"" if prompt else "")
                 + " — embedded in the pixels, so stripping metadata alone "
                   "leaves it in place"),
        source=source,
        evidence={"magic": found["magic"], "channel": found["channel"],
                  "compressed": found["compressed"],
                  "payload": payload[:2000],
                  "note": "Removable, but only by altering pixels: `markcleanse "
                          "sanitize` clears the low bit of every sample under "
                          "the `hidden` category, which destroys the carrier "
                          "and shifts each channel by at most 1/256. Any "
                          "re-encode does the same thing incidentally — saving "
                          "as JPEG, resizing, or sharpening all overwrite the "
                          "low bits. Unlike SynthID, this payload is not a "
                          "robust watermark; it survives only an exact copy."},
    )]
