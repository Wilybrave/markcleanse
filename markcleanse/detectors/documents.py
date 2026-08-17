"""Document detector: PDF, OOXML (docx/xlsx/pptx), ODF, RTF, HTML.

Two jobs:

1. Read the producer metadata. PDFs carry `/Producer` and `/Creator`; Office
   files carry `docProps/app.xml` `<Application>` and `docProps/core.xml`
   `<dc:creator>`. When an AI tool exports a document it usually signs its own
   name there — Gamma, Tome, Canva, ChatGPT's exporter, NotebookLM.

2. Extract the plain text, which the unicode and stylometry detectors then
   scan. Extraction is dependency-free (raw content-stream parsing for PDF,
   zip+XML for Office) and upgrades to pypdf when it is installed.
"""

from __future__ import annotations

import io
import re
import zipfile
import zlib

from ..context import FileCtx
from ..result import Finding, Tier
from .. import signatures as sig

DETECTOR = "documents"

_INFO_KEYS = ("Producer", "Creator", "Author", "Title", "Subject", "Keywords",
              "CreatorTool")

_PDF_LITERAL = re.compile(
    rb"/(" + b"|".join(k.encode() for k in _INFO_KEYS) + rb")\s*\(((?:[^()\\]|\\.)*)\)"
)
_PDF_HEX = re.compile(
    rb"/(" + b"|".join(k.encode() for k in _INFO_KEYS) + rb")\s*<([0-9A-Fa-f\s]+)>"
)


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def _pdf_string(raw: bytes) -> str:
    out = bytearray()
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x5C and i + 1 < len(raw):          # backslash escape
            nxt = raw[i + 1]
            mapping = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12}
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
            if 0x30 <= nxt <= 0x37:                 # octal
                digits = raw[i + 1:i + 4]
                oct_digits = bytes(d for d in digits if 0x30 <= d <= 0x37)
                out.append(int(oct_digits, 8) & 0xFF)
                i += 1 + len(oct_digits)
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(b)
        i += 1
    data = bytes(out)
    if data[:2] in (b"\xfe\xff", b"\xff\xfe"):
        return data.decode("utf-16", "replace").strip()
    return data.decode("utf-8", "replace").strip()


def _inflate_object_streams(data: bytes, limit: int = 64) -> bytes:
    """Return the concatenated contents of Flate-compressed streams.

    PDF 1.5+ moves the document catalogue and /Info dictionary into compressed
    object streams, so a regex over the raw file finds nothing. Inflating them
    is the difference between reading a modern PDF's producer and missing it.
    """
    out: list[bytes] = []
    for i, m in enumerate(re.finditer(rb"stream\r?\n", data)):
        if i >= limit:
            break
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        try:
            blob = zlib.decompress(data[start:end])
        except zlib.error:
            try:
                blob = zlib.decompressobj().decompress(data[start:end])
            except zlib.error:
                continue
        if b"/" in blob[:4096] or b"(" in blob[:4096]:
            out.append(blob)
    return b"\n".join(out)


def pdf_metadata(data: bytes) -> dict[str, str]:
    meta: dict[str, str] = {}
    # Uncompressed first, then anything hiding in an object stream.
    data = data + b"\n" + _inflate_object_streams(data)
    for m in _PDF_LITERAL.finditer(data):
        key = m.group(1).decode()
        value = _pdf_string(m.group(2))
        if value and key not in meta:
            meta[key] = value
    for m in _PDF_HEX.finditer(data):
        key = m.group(1).decode()
        if key in meta:
            continue
        try:
            blob = bytes.fromhex(re.sub(rb"\s", b"", m.group(2)).decode())
        except ValueError:
            continue
        text = (blob.decode("utf-16", "replace") if blob[:2] in (b"\xfe\xff", b"\xff\xfe")
                else blob.decode("utf-8", "replace")).strip()
        if text:
            meta[key] = text
    return meta


_TEXT_OPS = re.compile(rb"\((?:[^()\\]|\\.)*\)\s*T[jJ]|\[(?:[^\[\]\\]|\\.)*\]\s*TJ")
_STR_IN = re.compile(rb"\((?:[^()\\]|\\.)*\)")


def pdf_text(data: bytes, max_chars: int = 400_000) -> tuple[str, str]:
    """Extract text. Returns (text, method)."""
    try:
        from pypdf import PdfReader           # type: ignore

        reader = PdfReader(io.BytesIO(data))
        parts = []
        for page in reader.pages[:200]:
            parts.append(page.extract_text() or "")
            if sum(len(p) for p in parts) > max_chars:
                break
        text = "\n".join(parts)
        if text.strip():
            return text[:max_chars], "pypdf"
    except Exception:
        pass
    return _pdf_text_raw(data, max_chars), "raw-stream"


def _pdf_text_raw(data: bytes, max_chars: int) -> str:
    chunks: list[str] = []
    total = 0
    for m in re.finditer(rb"stream\r?\n", data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        raw = data[start:end]
        try:
            content = zlib.decompress(raw)
        except zlib.error:
            content = raw
        if b"Tj" not in content and b"TJ" not in content:
            continue
        for op in _TEXT_OPS.finditer(content):
            for s in _STR_IN.finditer(op.group(0)):
                chunks.append(_pdf_string(s.group(0)[1:-1]))
        total = sum(len(c) for c in chunks)
        if total > max_chars:
            break
    return " ".join(chunks)[:max_chars]


# ---------------------------------------------------------------------------
# OOXML / ODF
# ---------------------------------------------------------------------------

_TAG = re.compile(r"<[^>]+>")
_XML_FIELD = re.compile(r"<((?:\w+:)?(\w+))[^>/]*>([^<]{1,2000})</\1>")

OOXML_TEXT_PARTS = {
    "docx": ["word/document.xml"],
    "pptx": None,          # every slideN.xml
    "xlsx": ["xl/sharedStrings.xml"],
    "epub": None,
    "odt": ["content.xml"],
    "ods": ["content.xml"],
    "odp": ["content.xml"],
}

OOXML_META_PARTS = ["docProps/app.xml", "docProps/core.xml", "docProps/custom.xml",
                    "meta.xml", "META-INF/container.xml"]


def ooxml_read(data: bytes, fmt: str) -> tuple[dict[str, str], str]:
    meta: dict[str, str] = {}
    text_parts: list[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return meta, ""

    names = set(zf.namelist())
    for part in OOXML_META_PARTS:
        if part not in names:
            continue
        try:
            blob = zf.read(part).decode("utf-8", "replace")
        except Exception:
            continue
        for m in _XML_FIELD.finditer(blob):
            key, value = m.group(2), m.group(3).strip()
            if value and key not in meta:
                meta[key] = value

    wanted = OOXML_TEXT_PARTS.get(fmt)
    if wanted is None:
        wanted = sorted(
            n for n in names
            if n.endswith((".xml", ".xhtml", ".html"))
            and ("slide" in n or "content" in n or n.startswith("OEBPS")
                 or n.startswith("EPUB"))
        )[:60]
    for part in wanted:
        if part not in names:
            continue
        try:
            blob = zf.read(part).decode("utf-8", "replace")
        except Exception:
            continue
        # Preserve word boundaries that tags used to provide.
        text_parts.append(_TAG.sub(" ", blob))
        if sum(len(p) for p in text_parts) > 400_000:
            break

    text = re.sub(r"[ \t]{2,}", " ", " ".join(text_parts))
    return meta, text[:400_000]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def detect(ctx: FileCtx) -> list[Finding]:
    if ctx.kind not in ("document", "text", "archive"):
        return []

    findings: list[Finding] = []
    meta: dict[str, str] = {}

    if ctx.fmt == "pdf":
        meta = pdf_metadata(ctx.data)
        if ctx.text is None:
            ctx.text, ctx.text_source = pdf_text(ctx.data)
        for block in re.findall(rb"<x:xmpmeta.*?</x:xmpmeta>", ctx.data[:4_000_000], re.S):
            for m in _XML_FIELD.finditer(block.decode("utf-8", "replace")):
                meta.setdefault(m.group(2), m.group(3).strip())

    elif ctx.fmt in ("docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "zip"):
        meta, text = ooxml_read(ctx.data, ctx.fmt)
        if ctx.text is None and text:
            ctx.text, ctx.text_source = text, "ooxml"

    elif ctx.fmt in ("html", "htm"):
        if ctx.text is None:
            raw = ctx.data.decode("utf-8", "replace")
            for m in re.finditer(r"<meta[^>]+name=[\"']?(generator|author)[\"']?[^>]*"
                                 r"content=[\"']([^\"']+)", raw, re.I):
                meta[m.group(1)] = m.group(2)
            ctx.text, ctx.text_source = _TAG.sub(" ", raw), "html"

    elif ctx.kind == "text" and ctx.text is None:
        ctx.text, ctx.text_source = ctx.data.decode("utf-8", "replace"), "plain"

    if ctx.exif:
        from ..exif_tool import flat_strings
        for key, value in flat_strings(ctx.exif):
            meta.setdefault(key.split(":")[-1], value)

    # --- Producer / application naming an AI tool -------------------------
    seen: set[str] = set()
    for key, value in meta.items():
        named = sig.identify(value)
        if not named or named in seen:
            continue
        if sig.BENIGN_PRODUCERS.search(value) and not _strong_ai_term(value):
            continue
        seen.add(named)
        findings.append(Finding(
            tier=Tier.B, detector=DETECTOR,
            signal="doc.producer",
            summary=f"Document metadata {key} = \"{_clip(value)}\" identifies {named}",
            source=named,
            evidence={"field": key, "value": _clip(value, 400), "all_metadata":
                      {k: _clip(v, 200) for k, v in list(meta.items())[:25]}},
        ))

    # --- IPTC-style AI declaration inside XMP ------------------------------
    joined = " ".join(f"{k}={v}" for k, v in meta.items())
    if re.search(r"trainedAlgorithmicMedia", joined, re.I):
        findings.append(Finding(
            tier=Tier.A, detector=DETECTOR,
            signal="doc.digital_source_type.ai",
            summary="Document XMP declares IPTC digitalSourceType trainedAlgorithmicMedia",
            source=next(iter(seen), None),
            evidence={"metadata": {k: _clip(v, 200) for k, v in list(meta.items())[:25]}},
        ))

    if meta and not findings:
        ctx.notes.append("doc-metadata:" + ",".join(sorted(meta)[:12]))

    if ctx.text is not None and not ctx.text.strip() and ctx.fmt == "pdf":
        # `info.` signals are coverage notes, not evidence: they say what could
        # not be examined. Reporting "I couldn't read this" as SUSPECT would
        # flag every scanned contract and filled-in government form on the disk.
        findings.append(Finding(
            tier=Tier.C, detector=DETECTOR,
            signal="info.no_text_layer",
            summary="PDF has no extractable text layer (scanned or image-only) — "
                    "text-side analysis could not run on this file",
            evidence={"method": ctx.text_source},
        ))

    return findings


def _strong_ai_term(value: str) -> bool:
    return bool(re.search(r"\bai\b|gpt|claude|gemini|llm|generative", value, re.I))


def _clip(text: str, limit: int = 90) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"
