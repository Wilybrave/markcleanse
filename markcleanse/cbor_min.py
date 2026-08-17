"""Dependency-free CBOR decoder.

C2PA claims and assertions are CBOR. We refuse to make the crown-jewel
detector depend on an optional pip package, so this decodes enough of
RFC 8949 to read a manifest: ints, byte/text strings (definite and
indefinite), arrays, maps, tags, simple values, floats.

Unknown/undecodable input raises CborError; callers fall back to string
scraping.
"""

from __future__ import annotations

import struct
from typing import Any


class CborError(ValueError):
    pass


class _Decoder:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def _take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise CborError("truncated")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def _head(self) -> tuple[int, int, bool]:
        """Return (major, argument, is_indefinite)."""
        b = self._take(1)[0]
        major, minor = b >> 5, b & 0x1F
        if minor < 24:
            return major, minor, False
        if minor == 24:
            return major, self._take(1)[0], False
        if minor == 25:
            return major, struct.unpack(">H", self._take(2))[0], False
        if minor == 26:
            return major, struct.unpack(">I", self._take(4))[0], False
        if minor == 27:
            return major, struct.unpack(">Q", self._take(8))[0], False
        if minor == 31:
            return major, 0, True
        raise CborError(f"reserved additional info {minor}")

    def decode(self, depth: int = 0) -> Any:
        if depth > 64:
            raise CborError("too deep")
        major, arg, indef = self._head()

        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return self._string(2, arg, indef, depth)
        if major == 3:
            raw = self._string(3, arg, indef, depth)
            return raw.decode("utf-8", "replace")
        if major == 4:
            if indef:
                out = []
                while not self._break():
                    out.append(self.decode(depth + 1))
                return out
            if arg > len(self.d):
                raise CborError("array length beyond buffer")
            return [self.decode(depth + 1) for _ in range(arg)]
        if major == 5:
            out_map: dict[Any, Any] = {}
            if indef:
                while not self._break():
                    k = self.decode(depth + 1)
                    out_map[_hashable(k)] = self.decode(depth + 1)
                return out_map
            if arg > len(self.d):
                raise CborError("map length beyond buffer")
            for _ in range(arg):
                k = self.decode(depth + 1)
                out_map[_hashable(k)] = self.decode(depth + 1)
            return out_map
        if major == 6:
            # Tag: we keep the value, discarding the tag number. Good enough
            # for provenance reading (tag 18 = COSE_Sign1, tag 0/1 = dates).
            return self.decode(depth + 1)
        if major == 7:
            if indef:
                raise CborError("indefinite simple value")
            if arg == 20:
                return False
            if arg == 21:
                return True
            if arg == 22:
                return None
            if arg == 23:
                return None
            return arg
        raise CborError(f"bad major type {major}")

    def _break(self) -> bool:
        if self.i >= len(self.d):
            raise CborError("truncated before break")
        if self.d[self.i] == 0xFF:
            self.i += 1
            return True
        return False

    def _string(self, major: int, arg: int, indef: bool, depth: int) -> bytes:
        if not indef:
            return self._take(arg)
        chunks = []
        while not self._break():
            m, a, ind = self._head()
            if m != major or ind:
                raise CborError("bad indefinite string chunk")
            chunks.append(self._take(a))
        return b"".join(chunks)


def _hashable(key: Any) -> Any:
    if isinstance(key, (list, dict)):
        return repr(key)
    if isinstance(key, bytes):
        return key.decode("utf-8", "replace")
    return key


def loads(data: bytes) -> Any:
    """Decode the first CBOR item in ``data``."""
    return _Decoder(data).decode()


def loads_with_tag(data: bytes) -> tuple[int | None, Any]:
    """Decode, also returning the outermost tag number (COSE needs tag 18)."""
    tag = None
    if data and (data[0] >> 5) == 6:
        head = _Decoder(data)
        _major, tag, _indef = head._head()
    return tag, loads(data)


# ---------------------------------------------------------------------------
# Encoding
#
# Only what COSE signature verification needs: the Sig_structure is rebuilt
# and re-encoded so it can be hashed, so the encoder must be canonical for
# the handful of types that structure contains.
# ---------------------------------------------------------------------------

def _head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 0x100:
        return bytes([(major << 5) | 24, arg])
    if arg < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", arg)
    if arg < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack(">I", arg)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", arg)


def dumps(obj: Any) -> bytes:
    """Encode a value. Supports int, bytes, str, list, dict, bool, None."""
    if obj is None:
        return b"\xf6"
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if isinstance(obj, int):
        if obj >= 0:
            return _head(0, obj)
        return _head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _head(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        return _head(4, len(obj)) + b"".join(dumps(v) for v in obj)
    if isinstance(obj, dict):
        return _head(5, len(obj)) + b"".join(
            dumps(k) + dumps(v) for k, v in obj.items())
    raise CborError(f"cannot encode {type(obj).__name__}")
