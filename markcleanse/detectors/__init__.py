"""Detector registry.

Order matters: `documents` populates ``ctx.text``, which `unicode_wm` and
`stylometry` then consume.
"""

from __future__ import annotations

from typing import Callable

from ..context import FileCtx
from ..result import Finding
from . import (c2pa, documents, image_meta, png_text, stealth_png, stylometry,
               unicode_wm, whitespace_wm)

Detector = Callable[[FileCtx], list[Finding]]


def _bytes_detector(module) -> Detector:
    def run(ctx: FileCtx) -> list[Finding]:
        return module.detect(ctx.data, ctx.fmt)
    return run


#: (name, callable, is_heuristic)
REGISTRY: list[tuple[str, Detector, bool]] = [
    ("c2pa",       c2pa.detect,               False),
    ("png_text",   _bytes_detector(png_text), False),
    ("image_meta", image_meta.detect,         False),
    ("stealth_png", stealth_png.detect,       False),
    ("documents",  documents.detect,          False),
    ("unicode_wm", unicode_wm.detect,         False),
    # Can produce Tier A (a decoded payload), so it is not a heuristic and
    # must survive --no-heuristics.
    ("whitespace_wm", whitespace_wm.detect,   False),
    ("stylometry", stylometry.detect,         True),
]

ALL_NAMES = [name for name, _fn, _h in REGISTRY]
