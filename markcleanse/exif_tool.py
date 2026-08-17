"""Optional exiftool bridge.

exiftool understands far more containers than we ever will (HEIC, AVIF, TIFF,
PSD, RAW, DNG, plus dozens of XMP namespaces). When it is on the box we use it
as an enrichment layer, batched so a 10k-file scan doesn't spawn 10k processes.

Everything still works without it — the pure-Python parsers cover
JPEG/PNG/WebP/PDF/OOXML, which is the overwhelming majority of real traffic.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

BATCH = 150
TIMEOUT = 120

_PATH: str | None | bool = False   # False = not yet probed


def available() -> str | None:
    global _PATH
    if _PATH is False:
        _PATH = shutil.which("exiftool")
    return _PATH  # type: ignore[return-value]


def batch_extract(paths: list[str]) -> dict[str, dict[str, Any]]:
    """Return {path: {tag: value}} for as many files as exiftool can read."""
    exe = available()
    if not exe or not paths:
        return {}

    out: dict[str, dict[str, Any]] = {}
    for i in range(0, len(paths), BATCH):
        chunk = paths[i:i + BATCH]
        try:
            proc = subprocess.run(
                [exe, "-json", "-a", "-u", "-G1", "-n", "-charset", "filename=utf8",
                 "-fast2", "--printConv", *chunk],
                capture_output=True, timeout=TIMEOUT,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        if not proc.stdout:
            continue
        try:
            records = json.loads(proc.stdout.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            continue
        for rec in records:
            src = rec.get("SourceFile")
            if src:
                out[src] = rec
    return out


#: Groups describing the file on *this* disk, not its content. A file called
#: `CLAUDE.md` sitting in `~/projects/gemini-work/` must never be evidence of
#: anything — the name is chosen by whoever saved it, not by the generator.
_FILESYSTEM_GROUPS = ("File:", "System:", "ExifTool:", "Composite:FileName")
_FILESYSTEM_TAGS = {"SourceFile", "FileName", "Directory", "BaseName",
                    "FilePath", "OriginalFileName"}


def flat_strings(tags: dict[str, Any]) -> list[tuple[str, str]]:
    """Flatten exiftool output to [(tag, string value)] for signature matching."""
    pairs: list[tuple[str, str]] = []
    for key, value in tags.items():
        if key.startswith(_FILESYSTEM_GROUPS) or key.split(":")[-1] in _FILESYSTEM_TAGS:
            continue
        if isinstance(value, str):
            if 1 <= len(value) <= 8000:
                pairs.append((key, value))
        elif isinstance(value, (int, float, bool)):
            pairs.append((key, str(value)))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and 1 <= len(item) <= 8000:
                    pairs.append((key, item))
        elif isinstance(value, dict):
            for sub, item in value.items():
                if isinstance(item, str) and 1 <= len(item) <= 8000:
                    pairs.append((f"{key}.{sub}", item))
    return pairs
