"""Named byte ranges for the `c2pa.hash.boxes` binding.

BoxHash is the third hard binding C2PA 2.4 requires a validator to support
(alongside `hash.data` and `hash.bmff`). Instead of excluding byte ranges, it
names the container's own structures — PNG chunks, JPEG segments — and hashes
runs of them, so the digest survives operations that only touch untouched
boxes.

Verification therefore needs the asset's box map in exactly the naming and
ordering the reference implementation produces, because the assertion refers to
boxes by name and consumes them **in order**. The names below are taken from
c2pa-rs (`png_io.rs`, `jpeg_io.rs`), not invented:

* PNG — a synthetic ``PNGh`` covering the 8-byte signature, then one entry per
  chunk named by its 4-character type, each spanning length+type+data+CRC.
* JPEG — ``SOI``, ``APP0``..``APP15``, ``COM``, ``DQT``, ``DHT``, ``DRI``,
  ``SOF0``.., ``SOS``, ``EOI``. ``SOS`` runs to the end of the entropy-coded
  data, not just its own header.
* The manifest's own boxes are named ``C2PA`` in both formats, and a run of
  APP11 JUMBF segments collapses into a single ``C2PA`` entry.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

C2PA_BOXHASH = "C2PA"

#: JPEG markers that stand alone — no length field, so the "segment" is 2 bytes.
STANDALONE = {0xD8, 0xD9, 0x01} | set(range(0xD0, 0xD8))

JPEG_NAMES = {
    0xFE: "COM", 0xC4: "DHT", 0xDB: "DQT", 0xDD: "DRI", 0xD9: "EOI",
    0xD8: "SOI", 0xDA: "SOS",
}
for _i in range(16):
    JPEG_NAMES[0xE0 + _i] = f"APP{_i}"
for _i in range(8):
    JPEG_NAMES[0xD0 + _i] = f"RST{_i}"
for _i in range(3):
    JPEG_NAMES[0xC0 + _i] = f"SOF{_i}"
for _i in range(14):
    JPEG_NAMES[0xF0 + _i] = f"JPG{_i}"


@dataclass
class Box:
    name: str
    start: int
    length: int

    @property
    def end(self) -> int:
        return self.start + self.length


def box_map(data: bytes, fmt: str) -> list[Box]:
    if fmt == "png":
        return _png_boxes(data)
    if fmt == "jpeg":
        return _jpeg_boxes(data)
    return []


def _png_boxes(data: bytes) -> list[Box]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return []
    boxes = [Box("PNGh", 0, 8)]
    i = 8
    n = len(data)
    while i + 8 <= n:
        length = struct.unpack(">I", data[i:i + 4])[0]
        ctype = data[i + 4:i + 8]
        total = length + 12                      # length + type + data + CRC
        if length > n or i + total > n:
            break
        name = C2PA_BOXHASH if ctype == b"caBX" else ctype.decode("latin-1", "replace")
        boxes.append(Box(name, i, total))
        i += total
        if ctype == b"IEND":
            break
    return boxes


def _jpeg_boxes(data: bytes) -> list[Box]:
    if data[:2] != b"\xff\xd8":
        return []
    boxes: list[Box] = []
    i = 0
    n = len(data)
    in_c2pa_run = False

    while i + 2 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xFF, 0x00):
            i += 1
            continue

        if marker in STANDALONE:
            size = 2
        elif i + 4 <= n:
            size = 2 + struct.unpack(">H", data[i + 2:i + 4])[0]
        else:
            break

        # The C2PA manifest is fragmented across consecutive APP11 segments;
        # the reference collapses that whole run into one `C2PA` entry.
        is_c2pa = (marker == 0xEB and data[i + 4:i + 6] == b"JP")
        if is_c2pa:
            if in_c2pa_run and boxes:
                boxes[-1].length += size
            else:
                boxes.append(Box(C2PA_BOXHASH, i, size))
                in_c2pa_run = True
            i += size
            continue
        in_c2pa_run = False

        if marker == 0xDA:
            # Scan data: the segment header plus every entropy-coded byte up to
            # the terminating EOI. Restart markers stay inside it.
            end = _entropy_end(data, i + size)
            boxes.append(Box("SOS", i, end - i))
            i = end
            continue

        boxes.append(Box(JPEG_NAMES.get(marker, f"0x{marker:02X}"), i, size))
        i += size
        if marker == 0xD9:
            break
    return boxes


def _entropy_end(data: bytes, start: int) -> int:
    """First byte after the entropy-coded stream that follows an SOS header."""
    i = start
    n = len(data)
    while i + 1 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        nxt = data[i + 1]
        if nxt == 0x00 or nxt == 0xFF or 0xD0 <= nxt <= 0xD7:
            i += 2                                # stuffed byte or restart
            continue
        return i                                  # a real marker ends the scan
    return n
