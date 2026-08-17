"""Per-file scanning context.

Everything a detector might need is computed once here — bytes, format,
extracted text, exiftool tags — so ten detectors don't each re-read the file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

MAGIC: list[tuple[bytes, str, str]] = [
    (b"\xff\xd8\xff",            "jpeg", "image"),
    (b"\x89PNG\r\n\x1a\n",       "png",  "image"),
    (b"GIF87a",                  "gif",  "image"),
    (b"GIF89a",                  "gif",  "image"),
    (b"BM",                      "bmp",  "image"),
    (b"II*\x00",                 "tiff", "image"),
    (b"MM\x00*",                 "tiff", "image"),
    (b"%PDF",                    "pdf",  "document"),
    (b"PK\x03\x04",              "zip",  "document"),
    (b"\xd0\xcf\x11\xe0",        "ole",  "document"),
    (b"{\\rtf",                  "rtf",  "document"),
]

TEXT_EXTS = {".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".html", ".htm",
             ".xml", ".rst", ".srt", ".vtt", ".tex", ".org", ".log", ".yaml", ".yml"}

OOXML_EXTS = {".docx": "docx", ".xlsx": "xlsx", ".pptx": "pptx",
              ".odt": "odt", ".ods": "ods", ".odp": "odp", ".epub": "epub"}


@dataclass
class FileCtx:
    path: str
    data: bytes                       # head of the file (or all of it)
    size: int
    fmt: str = "unknown"
    kind: str = "unsupported"
    complete: bool = True             # is `data` the whole file?
    exif: dict[str, Any] = field(default_factory=dict)   # exiftool tags
    text: str | None = None           # extracted plain text, if any
    text_source: str = ""             # how the text was obtained
    width: int = 0
    height: int = 0
    notes: list[str] = field(default_factory=list)
    verify_c2pa: bool = True          # run cryptographic manifest verification
    trust_store: object | None = None  # c2pa_verify.TrustStore, if configured
    revocation: str = "stapled"        # off | stapled | online

    @property
    def ext(self) -> str:
        return os.path.splitext(self.path)[1].lower()


def sniff(path: str, data: bytes) -> tuple[str, str]:
    """Return (format, kind) from magic bytes, falling back to extension."""
    ext = os.path.splitext(path)[1].lower()

    for magic, fmt, kind in MAGIC:
        if data.startswith(magic):
            if fmt == "zip":
                return _zip_flavour(ext)
            if fmt == "ole":
                return ("doc", "document")
            return (fmt, kind)

    if data[4:12] == b"ftypavif" or data[4:8] == b"ftyp":
        brand = data[8:12].decode("ascii", "replace")
        if brand.startswith("avif") or brand.startswith("avis"):
            return ("avif", "image")
        if brand.startswith("hei") or brand.startswith("mif1") or brand.startswith("msf1"):
            return ("heic", "image")
        return ("bmff", "unsupported")

    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ("webp", "image")

    if ext in TEXT_EXTS:
        return (ext.lstrip("."), "text")
    if ext == ".svg" or data.lstrip()[:5].lower() in (b"<?xml", b"<svg "):
        return ("svg", "image")

    # Last resort: does it decode as text?
    try:
        data[:4096].decode("utf-8")
    except UnicodeDecodeError:
        return ("binary", "unsupported")
    return ("text", "text")


def _zip_flavour(ext: str) -> tuple[str, str]:
    if ext in OOXML_EXTS:
        return (OOXML_EXTS[ext], "document")
    return ("zip", "archive")
