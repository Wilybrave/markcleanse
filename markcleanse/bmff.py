"""ISO Base Media File Format box walker.

Shared by AVIF, HEIC, HEIF and MP4. C2PA addresses boxes in these containers by
an xpath-like string (``/uuid``, ``/meta/iloc``), so the walker records a path
for every box alongside its byte range — which is exactly what the BMFF hash
binding needs in order to exclude the manifest from its own digest.

Deliberately tolerant: a truncated or slightly malformed tail stops the walk
rather than raising, because a forensics tool should report what it could read.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

#: Boxes whose payload is a sequence of child boxes.
CONTAINERS = {
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"udta",
    b"mvex", b"moof", b"traf", b"mfra", b"skip", b"meco", b"strk",
    b"meta", b"iprp", b"ipco", b"iref", b"iinf", b"sinf", b"schi", b"paen",
}

#: FullBoxes — 4 bytes of version+flags sit before the children.
FULLBOX_CONTAINERS = {b"meta", b"iref", b"sinf"}

MAX_DEPTH = 12


@dataclass
class Box:
    type: bytes
    path: str                 # "/meta/iloc"
    offset: int               # absolute offset of the box header
    size: int                 # total size including header
    header_len: int
    children_offset: int      # absolute offset where children begin
    uuid: bytes = b""         # the 16-byte extended type, for `uuid` boxes
    children: list["Box"] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.offset + self.size

    @property
    def payload_offset(self) -> int:
        return self.offset + self.header_len + (16 if self.type == b"uuid" else 0)

    def payload(self, data: bytes) -> bytes:
        return data[self.payload_offset:self.end]


def _entry_count_bytes(btype: bytes, data: bytes, at: int) -> int:
    """Extra header bytes between a FullBox header and its children."""
    if btype == b"iinf":
        # version 0 uses a 16-bit entry_count, version >= 1 uses 32-bit.
        version = data[at] if at < len(data) else 0
        return 4 + (2 if version == 0 else 4)
    if btype in FULLBOX_CONTAINERS:
        return 4
    return 0


def walk(data: bytes, start: int = 0, end: int | None = None,
         path: str = "", depth: int = 0) -> list[Box]:
    """Parse boxes in ``data[start:end]``, recursing into containers."""
    if end is None:
        end = len(data)
    out: list[Box] = []
    i = start
    while i + 8 <= end:
        size = struct.unpack(">I", data[i:i + 4])[0]
        btype = data[i + 4:i + 8]
        header_len = 8
        if size == 1:
            if i + 16 > end:
                break
            size = struct.unpack(">Q", data[i + 8:i + 16])[0]
            header_len = 16
        elif size == 0:
            size = end - i               # extends to the end of the container
        if size < header_len or i + size > end:
            break

        uuid = data[i + header_len:i + header_len + 16] if btype == b"uuid" else b""
        name = "uuid" if btype == b"uuid" else btype.decode("latin-1", "replace")
        box = Box(type=btype, path=f"{path}/{name}", offset=i, size=size,
                  header_len=header_len, children_offset=i + header_len, uuid=uuid)

        if btype in CONTAINERS and depth < MAX_DEPTH:
            extra = _entry_count_bytes(btype, data, i + header_len)
            box.children_offset = i + header_len + extra
            box.children = walk(data, box.children_offset, i + size,
                                box.path, depth + 1)
        out.append(box)
        i += size
    return out


def flatten(boxes: list[Box]) -> list[Box]:
    """Depth-first list of every box, parents before children."""
    out: list[Box] = []
    for box in boxes:
        out.append(box)
        if box.children:
            out.extend(flatten(box.children))
    return out


def is_bmff(data: bytes) -> bool:
    return len(data) >= 12 and data[4:8] == b"ftyp"


def brand(data: bytes) -> str:
    return data[8:12].decode("latin-1", "replace") if is_bmff(data) else ""


def top_level(data: bytes) -> list[Box]:
    return walk(data)


def find_uuid_box(data: bytes, wanted: bytes) -> Box | None:
    for box in flatten(walk(data)):
        if box.type == b"uuid" and box.uuid == wanted:
            return box
    return None


# ---------------------------------------------------------------------------
# iloc — needed to know whether a box can be removed without breaking offsets
# ---------------------------------------------------------------------------

def iloc_absolute_extents(data: bytes) -> list[tuple[int, int]]:
    """Absolute (offset, length) extents referenced by the item location box.

    Only construction_method 0 (file offset) is returned; methods 1 and 2 are
    relative to `idat` or another item and are unaffected by moving boxes
    around them. Used to decide whether dropping a box would silently
    invalidate every item in the file.
    """
    extents: list[tuple[int, int]] = []
    box = None
    for candidate in flatten(walk(data)):
        if candidate.path.endswith("/iloc"):
            box = candidate
            break
    if box is None:
        return extents

    body = data[box.offset + box.header_len:box.end]
    if len(body) < 8:
        return extents
    version = body[0]
    p = 4
    sizes = body[p]
    offset_size, length_size = sizes >> 4, sizes & 0xF
    base_size = body[p + 1] >> 4
    index_size = body[p + 1] & 0xF if version in (1, 2) else 0
    p += 2

    def read(n: int) -> int:
        nonlocal p
        if n == 0 or p + n > len(body):
            return 0
        value = int.from_bytes(body[p:p + n], "big")
        p += n
        return value

    count = read(2 if version < 2 else 4)
    for _ in range(min(count, 4096)):
        read(2 if version < 2 else 4)                    # item_ID
        method = 0
        if version in (1, 2):
            method = read(2) & 0xF
        read(2)                                          # data_reference_index
        base_offset = read(base_size)
        extent_count = read(2)
        for _ in range(min(extent_count, 4096)):
            read(index_size)
            offset = read(offset_size)
            length = read(length_size)
            if method == 0:
                extents.append((base_offset + offset, length))
    return extents
