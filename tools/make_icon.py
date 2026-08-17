"""Draw the launcher icon — a magnifier over a document, 256x256 PNG.

Written by hand rather than shipped as a binary blob so it stays reviewable and
regenerable, and so the repo keeps its no-dependencies property. Supersampled
3x for antialiasing.

    python3 tools/make_icon.py [out.png]
"""

from __future__ import annotations

import struct
import sys
import zlib

SIZE = 256
SS = 3                      # supersampling factor

BG = (24, 28, 38)           # deep slate
DOC = (238, 241, 245)       # paper
DOC_EDGE = (176, 184, 196)
LENS = (60, 130, 246)       # blue ring
ACCENT = (255, 122, 89)     # warm handle


def _rounded(x: float, y: float, w: float, h: float, r: float) -> bool:
    if not (0 <= x <= w and 0 <= y <= h):
        return False
    cx = min(max(x, r), w - r)
    cy = min(max(y, r), h - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def _ring(x, y, cx, cy, radius, width) -> bool:
    d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
    return radius - width / 2 <= d <= radius + width / 2


def _disc(x, y, cx, cy, radius) -> bool:
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius * radius


def _handle(x, y) -> bool:
    """Thick diagonal from the lens edge toward the bottom-right."""
    x0, y0, x1, y1 = 152, 152, 205, 205
    dx, dy = x1 - x0, y1 - y0
    length = (dx * dx + dy * dy) ** 0.5
    t = ((x - x0) * dx + (y - y0) * dy) / (length * length)
    if not 0 <= t <= 1:
        return False
    px, py = x0 + t * dx, y0 + t * dy
    return ((x - px) ** 2 + (y - py) ** 2) ** 0.5 <= 11


def sample(x: float, y: float) -> tuple[int, int, int, int]:
    if not _rounded(x, y, SIZE, SIZE, 54):
        return (0, 0, 0, 0)

    # document sheet, slightly rotated feel via offset corners
    if 62 <= x <= 168 and 44 <= y <= 190:
        on_edge = (x < 66 or x > 164 or y < 48 or y > 186)
        colour = DOC_EDGE if on_edge else DOC
        # ruled lines
        for line_y in (76, 100, 124, 148):
            if line_y <= y <= line_y + 6 and 78 <= x <= 152:
                colour = (198, 206, 216)
        base = colour
    else:
        base = BG

    if _handle(x, y):
        return ACCENT + (255,)
    if _ring(x, y, 132, 132, 46, 14):
        return LENS + (255,)
    if _disc(x, y, 132, 132, 39):
        # glass tint over whatever is beneath
        r, g, b = base
        return (int(r * 0.72 + 60 * 0.28),
                int(g * 0.72 + 130 * 0.28),
                int(b * 0.72 + 246 * 0.28), 255)
    return base + (255,)


def render() -> bytes:
    rows = []
    for py in range(SIZE):
        row = bytearray(b"\x00")
        for px in range(SIZE):
            acc = [0, 0, 0, 0]
            for sy in range(SS):
                for sx in range(SS):
                    r, g, b, a = sample(px + (sx + 0.5) / SS, py + (sy + 0.5) / SS)
                    acc[0] += r * a
                    acc[1] += g * a
                    acc[2] += b * a
                    acc[3] += a
            n = SS * SS
            alpha = acc[3] // n
            if alpha:
                row += bytes([min(255, acc[0] // acc[3]),
                              min(255, acc[1] // acc[3]),
                              min(255, acc[2] // acc[3]), alpha])
            else:
                row += b"\x00\x00\x00\x00"
        rows.append(bytes(row))
    return b"".join(rows)


def chunk(ctype: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + ctype + payload
            + struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF))


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "markcleanse.png"
    ihdr = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
           + chunk(b"IDAT", zlib.compress(render(), 9)) + chunk(b"IEND", b""))
    with open(out, "wb") as fh:
        fh.write(png)
    print(f"wrote {out} ({len(png):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
