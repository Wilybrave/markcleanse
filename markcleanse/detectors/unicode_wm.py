"""Invisible-character watermark detector for text and documents.

This is where real, decodable text watermarking actually lives. Three carriers
matter, and we decode all three rather than just flagging them:

* **Unicode Tags block** (U+E0000–U+E007F) — each codepoint maps to an ASCII
  character by subtracting 0xE0000. Renders as nothing anywhere. The classic
  hidden-payload channel.
* **Variation selectors** (U+FE00–FE0F and U+E0100–U+E01EF) — 256 selectors
  encode one byte each. Newer, increasingly common.
* **Zero-width binary** (ZWSP/ZWNJ as 0/1 bits, ZWJ or WJ as separators) —
  the oldest trick, still used by "AI content trackers" and leak-tracing tools.

Recovering readable text from any of them is Tier A: nothing puts a decodable
hidden message into a document by accident.

Note this catches *hidden payloads*, which is a superset of AI watermarking —
it will also catch leak-tracing beacons and prompt-injection payloads. That is
a feature; the finding says what was recovered so you can judge.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter

from ..context import FileCtx
from ..result import Finding, Tier

DETECTOR = "unicode_wm"

TAGS_START, TAGS_END = 0xE0000, 0xE007F
VS_LOW = range(0xFE00, 0xFE10)
VS_HIGH = range(0xE0100, 0xE01F0)

ZERO_WIDTH = {
    "​": "ZWSP",
    "‌": "ZWNJ",
    "‍": "ZWJ",
    "⁠": "WORD-JOINER",
    "﻿": "ZWNBSP",
    "­": "SOFT-HYPHEN",
    "᠎": "MONGOLIAN-VOWEL-SEP",
    "⁡": "FUNCTION-APPLICATION",
    "⁢": "INVISIBLE-TIMES",
    "⁣": "INVISIBLE-SEPARATOR",
    "⁤": "INVISIBLE-PLUS",
    # Renders as blank in virtually every font, so it hides text just as well
    # as the zero-width block and is not covered by "zero width" filters.
    "ㅤ": "HANGUL-FILLER",
    "ᅠ": "HANGUL-CHOSEONG-FILLER",
    "ᅟ": "HANGUL-JUNGSEONG-FILLER",
    "ﾠ": "HALFWIDTH-HANGUL-FILLER",
    "⠀": "BRAILLE-BLANK",
    "𝅲": "MUSICAL-NULL",
    "\u2064": "INVISIBLE-PLUS-2",
    "\u17b4": "KHMER-INHERENT-AQ",
    "\u17b5": "KHMER-INHERENT-AA",
}

#: Only the *override* controls are worth flagging. LRM/RLM and the isolates
#: (FSI/PDI/LRI/RLI) are emitted routinely by GTK, Qt, browsers and every
#: localisation pipeline to wrap UI labels — scanning a real machine, they are
#: the single largest source of false positives. LRE/RLE/PDF sit in between:
#: legitimate in genuine bidi documents, so they only count in bulk.
BIDI_OVERRIDES = {"‭": "LRO", "‮": "RLO"}
BIDI_EMBEDDINGS = {"‪": "LRE", "‫": "RLE", "‬": "PDF"}
BIDI_BENIGN = {"⁦": "LRI", "⁧": "RLI", "⁨": "FSI", "⁩": "PDI",
               "‎": "LRM", "‏": "RLM"}
BIDI_CONTROLS = {**BIDI_OVERRIDES, **BIDI_EMBEDDINGS, **BIDI_BENIGN}

#: NBSP, the ideographic space and the en/em spaces are emitted by Word,
#: PowerPoint, LaTeX, every CMS and most CJK text. They carry no signal on
#: their own — they are reported as context but never trigger a finding.
COMMON_SPACES = {
    "\u00a0": "NBSP", "\u3000": "IDEOGRAPHIC-SPACE",
    "\u2002": "EN-SPACE", "\u2003": "EM-SPACE",
}

#: Rare enough in ordinary documents that a cluster is worth a look — this is
#: the classic whitespace-steganography alphabet.
RARE_SPACES = {
    "\u2007": "FIGURE-SPACE", "\u2008": "PUNCTUATION-SPACE",
    "\u2009": "THIN-SPACE", "\u200a": "HAIR-SPACE", "\u202f": "NARROW-NBSP",
    "\u205f": "MEDIUM-MATH-SPACE", "\u2004": "THREE-PER-EM-SPACE",
    "\u2005": "FOUR-PER-EM-SPACE", "\u2006": "SIX-PER-EM-SPACE",
}

EXOTIC_SPACES = {**COMMON_SPACES, **RARE_SPACES}

#: Non-Latin letters that render identically to a Latin one.
HOMOGLYPHS = {
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ј": "J",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "ο": "o", "ν": "v", "ι": "i",
}


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

def decode_tags(text: str) -> str:
    """U+E0000..U+E007F -> ASCII."""
    return "".join(
        chr(ord(ch) - TAGS_START)
        for ch in text
        if TAGS_START <= ord(ch) <= TAGS_END
    ).replace("\x00", "")


def decode_variation_selectors(text: str) -> bytes:
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if cp in VS_LOW:
            out.append(cp - 0xFE00)
        elif cp in VS_HIGH:
            out.append(cp - 0xE0100 + 16)
    return bytes(out)


def decode_zero_width_binary(text: str) -> list[str]:
    """Try the common ZW binary encodings and return any readable results."""
    runs = re.findall(r"[​‌‍⁠﻿]{8,}", text)
    results: list[str] = []
    schemes = [
        ("​", "‌"),   # ZWSP=0 ZWNJ=1  (most common)
        ("‌", "​"),
        ("​", "‍"),
        ("‍", "‌"),
    ]
    for run in runs[:20]:
        for zero, one in schemes:
            bits = "".join("0" if c == zero else "1" if c == one else "" for c in run)
            if len(bits) < 8:
                continue
            for width in (8, 7, 16):
                if len(bits) % width:
                    continue
                try:
                    chars = [chr(int(bits[i:i + width], 2)) for i in range(0, len(bits), width)]
                except ValueError:
                    continue
                candidate = "".join(chars)
                if _is_meaningful(candidate):
                    results.append(candidate)
                    break
            if results and results[-1]:
                break
    return _dedupe(results)


# ---------------------------------------------------------------------------
# Functional (non-suspicious) uses of the invisible characters.
#
# Scanning a real machine, these dominate the raw counts: ZWJ is how every
# multi-person and profession emoji is built (👨‍🍳 is man + ZWJ + chef hat),
# and ZWNJ is a required letter-joining control in Persian, Arabic and the
# Indic scripts. Counting them as watermarks makes the tool cry wolf on any
# codebase or multilingual document.
# ---------------------------------------------------------------------------

_JOINING_SCRIPTS = ("ARABIC", "PERSIAN", "DEVANAGARI", "BENGALI", "GUJARATI",
                    "GURMUKHI", "ORIYA", "TAMIL", "TELUGU", "KANNADA",
                    "MALAYALAM", "SINHALA", "THAI", "LAO", "TIBETAN",
                    "MYANMAR", "KHMER", "SYRIAC", "THAANA", "NKO")

_SKIN_TONES = range(0x1F3FB, 0x1F400)


def _neighbour(text: str, index: int, step: int) -> str | None:
    """Nearest neighbour, skipping emoji modifiers that are not the point."""
    i = index + step
    while 0 <= i < len(text):
        cp = ord(text[i])
        if cp == 0xFE0F or cp == 0xFE0E or cp in _SKIN_TONES:
            i += step
            continue
        return text[i]
    return None


def is_functional_zero_width(text: str, index: int) -> bool:
    ch = text[index]
    prev_c, next_c = _neighbour(text, index, -1), _neighbour(text, index, 1)

    if ch == "‍":                                    # ZWJ
        if prev_c is None or next_c is None:
            return False
        return (unicodedata.category(prev_c) in ("So", "Sk")
                and unicodedata.category(next_c) in ("So", "Sk"))

    if ch == "‌":                                    # ZWNJ
        for side in (prev_c, next_c):
            if side and any(s in unicodedata.name(side, "") for s in _JOINING_SCRIPTS):
                return True
        return False

    if ch == "﻿":                                    # BOM
        return index == 0

    return False


def _is_meaningful(text: str) -> bool:
    if len(text) < 4:
        return False
    printable = sum(1 for c in text if c.isprintable() and ord(c) < 0x3000)
    return printable / len(text) >= 0.85 and any(c.isalnum() for c in text)


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def detect(ctx: FileCtx) -> list[Finding]:
    text = ctx.text
    if not text or len(text) < 8:
        return []

    findings: list[Finding] = []
    words = max(len(text.split()), 1)

    # --- Unicode Tags block ------------------------------------------------
    tag_chars = [c for c in text if TAGS_START <= ord(c) <= TAGS_END]
    if tag_chars:
        payload = decode_tags(text)
        readable = _is_meaningful(payload)
        findings.append(Finding(
            tier=Tier.A if readable else Tier.B,
            detector=DETECTOR,
            signal="unicode.tags_block",
            summary=(f"{len(tag_chars)} Unicode Tag characters (U+E0000 block) hidden in "
                     f"the text" + (f"; decodes to: \"{_clip(payload)}\"" if readable
                                    else " (payload did not decode to readable ASCII)")),
            evidence={"count": len(tag_chars), "decoded": payload[:2000],
                      "readable": readable},
        ))

    # --- Variation selector payload ---------------------------------------
    vs_chars = [c for c in text if ord(c) in VS_LOW or ord(c) in VS_HIGH]
    if len(vs_chars) >= 4:
        raw = decode_variation_selectors(text)
        decoded = raw.decode("utf-8", "replace")
        readable = _is_meaningful(decoded)
        # Emoji legitimately use FE0F; only flag when it is not emoji-adjacent.
        emoji_like = _emoji_adjacent_ratio(text)
        if readable or emoji_like < 0.5:
            findings.append(Finding(
                tier=Tier.A if readable else Tier.C,
                detector=DETECTOR,
                signal="unicode.variation_selectors",
                summary=(f"{len(vs_chars)} variation selectors carrying a byte payload"
                         + (f"; decodes to: \"{_clip(decoded)}\"" if readable else "")),
                evidence={"count": len(vs_chars), "decoded": decoded[:2000],
                          "readable": readable, "emoji_adjacent": round(emoji_like, 2)},
            ))

    # --- Zero-width characters --------------------------------------------
    zw = Counter(
        c for i, c in enumerate(text)
        if c in ZERO_WIDTH and not is_functional_zero_width(text, i)
    )
    if zw:
        decoded = decode_zero_width_binary(text)
        names = ", ".join(f"{ZERO_WIDTH[c]}×{n}" for c, n in zw.most_common(5))
        total = sum(zw.values())
        if decoded:
            findings.append(Finding(
                tier=Tier.A, detector=DETECTOR,
                signal="unicode.zero_width_payload",
                summary=f"Zero-width characters decode to a hidden message: "
                        f"\"{_clip(decoded[0])}\"",
                evidence={"counts": names, "decoded": decoded[:5]},
            ))
        elif total >= 3:
            per_kw = total / words * 1000
            findings.append(Finding(
                tier=Tier.B if per_kw > 2 else Tier.C,
                detector=DETECTOR,
                signal="unicode.zero_width",
                summary=f"{total} zero-width/invisible characters embedded "
                        f"({names}) — {per_kw:.1f} per 1000 words",
                evidence={"counts": names, "total": total,
                          "per_1000_words": round(per_kw, 2),
                          "note": "No decodable payload; consistent with a "
                                  "watermark, a tracking beacon, or sloppy "
                                  "copy-paste from a web editor."},
            ))

    # --- Bidi overrides ----------------------------------------------------
    overrides = Counter(c for c in text if c in BIDI_OVERRIDES)
    embeddings = Counter(c for c in text if c in BIDI_EMBEDDINGS)
    rtl = _has_rtl(text)
    if overrides or (embeddings and sum(embeddings.values()) >= 20 and not rtl):
        active = overrides or embeddings
        findings.append(Finding(
            tier=Tier.C, detector=DETECTOR,
            signal="unicode.bidi_overrides",
            summary=f"{sum(active.values())} bidirectional override characters "
                    f"({', '.join(BIDI_CONTROLS[c] for c in active)}) in text with "
                    f"{'no ' if not rtl else ''}right-to-left script — text-reversal "
                    f"or display-spoofing technique",
            evidence={"counts": {BIDI_CONTROLS[c]: n for c, n in active.items()},
                      "note": "LRM/RLM and isolate marks were ignored: UI toolkits "
                              "and localisation pipelines emit them constantly."},
        ))

    # --- Homoglyph substitution -------------------------------------------
    # The signal is a lookalike letter *embedded in a Latin word* ("rаte" =
    # Latin r + Cyrillic а + Latin te). A genuine Cyrillic or Greek word has
    # same-script neighbours, so a gazetteer of place names stays clean —
    # which a bare "contains Cyrillic" test does not.
    homo = Counter(c for i, c in enumerate(text)
                   if c in HOMOGLYPHS and _has_latin_neighbour(text, i))
    if sum(homo.values()) >= 2:
        samples = _homoglyph_words(text)
        findings.append(Finding(
            tier=Tier.C, detector=DETECTOR,
            signal="unicode.homoglyphs",
            summary=f"{sum(homo.values())} Cyrillic/Greek homoglyphs substituted "
                    f"inside Latin words "
                    f"({', '.join(f'{c}→{HOMOGLYPHS[c]}' for c in list(homo)[:5])})"
                    + (f" e.g. {', '.join(samples[:3])}" if samples else ""),
            evidence={"counts": {c: n for c, n in homo.most_common(10)},
                      "affected_words": samples[:12]},
        ))

    # --- Exotic whitespace -------------------------------------------------
    rare = Counter(c for c in text if c in RARE_SPACES)
    common = Counter(c for c in text if c in COMMON_SPACES)
    rare_total = sum(rare.values())
    if rare_total >= 12 and rare_total / words * 1000 > 8:
        findings.append(Finding(
            tier=Tier.C, detector=DETECTOR,
            signal="unicode.exotic_whitespace",
            summary=f"{rare_total} rare space characters "
                    f"({', '.join(RARE_SPACES[c] for c in list(rare)[:4])}) at "
                    f"{rare_total / words * 1000:.0f} per 1000 words — whitespace "
                    f"steganography or a typesetting export",
            evidence={"rare": {RARE_SPACES[c]: n for c, n in rare.most_common(8)},
                      "common_context": {COMMON_SPACES[c]: n
                                         for c, n in common.most_common(4)},
                      "note": "NBSP and en/em spaces are excluded from the trigger: "
                              "Word, PowerPoint and LaTeX emit them constantly."},
        ))

    return findings


def _emoji_adjacent_ratio(text: str) -> float:
    """Fraction of variation selectors that directly follow a symbol/emoji."""
    total = adjacent = 0
    for i, ch in enumerate(text):
        if ord(ch) in VS_LOW or ord(ch) in VS_HIGH:
            total += 1
            if i and unicodedata.category(text[i - 1]) in ("So", "Sk", "Sm"):
                adjacent += 1
    return adjacent / total if total else 0.0


def _has_rtl(text: str) -> bool:
    return any(unicodedata.bidirectional(c) in ("R", "AL") for c in text[:20000])


def _is_latin_letter(ch: str | None) -> bool:
    return bool(ch) and ch.isalpha() and "LATIN" in unicodedata.name(ch, "")


def _has_latin_neighbour(text: str, index: int) -> bool:
    before = text[index - 1] if index > 0 else None
    after = text[index + 1] if index + 1 < len(text) else None
    return _is_latin_letter(before) or _is_latin_letter(after)


_WORDISH = re.compile(r"[^\s\"',;:{}\[\]()]+")


def _homoglyph_words(text: str, limit: int = 12) -> list[str]:
    """The actual mixed-script words, so a reviewer can eyeball them."""
    out: list[str] = []
    for m in _WORDISH.finditer(text[:200000]):
        word = m.group(0)
        if len(word) > 40 or not any(c in HOMOGLYPHS for c in word):
            continue
        if any(_is_latin_letter(c) for c in word) and word not in out:
            out.append(word)
            if len(out) >= limit:
                break
    return out


def _clip(text: str, limit: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"
