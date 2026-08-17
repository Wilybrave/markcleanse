"""ASCII whitespace steganography detector.

The Unicode detector catches invisible *characters*. This one catches payloads
hidden in ordinary ASCII spacing, which survives copy-paste through plain-text
fields where zero-width characters get stripped. Three channels:

* **inter-word** — one space = 0, two spaces = 1, between words on a line;
* **inter-sentence** — one vs two spaces after ``.``/``!``/``?``;
* **trailing** — spaces and tabs at end of line (the classic `snow` encoding,
  space = 0 / tab = 1, or run length 1 vs 2 when there are no tabs).

The discriminator that makes this usable
----------------------------------------

Every one of these patterns is also an ordinary human habit. Typewriter-trained
writers double-space after every period. Markdown uses two trailing spaces as a
hard line break. Editors leave trailing whitespace everywhere.

A *habit* is uniform, and uniform data carries no information — all ones is not
a message. A *payload* is mixed. So the test is not "are there double spaces"
but "does the spacing pattern carry entropy", and the strongest outcome is a
payload that actually decodes to text.

That yields two honest outcomes:

* bits decode to readable text  -> Tier A, and we print the recovered string;
* bits are high-entropy but do not decode -> Tier C, "spacing carries roughly
  one bit per gap, which a consistent writing habit would not".

A writer who always double-spaces produces ~0.0 entropy and is never flagged.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..context import FileCtx
from ..result import Finding, Tier

DETECTOR = "whitespace_wm"

#: Enough gaps to be talking about a pattern rather than an accident.
MIN_BITS_DECODE = 16
MIN_BITS_ENTROPY = 40

#: Shannon entropy of the bit string, in bits per bit. A habit sits near 0;
#: an even payload sits near 1. 0.9 ~= a 68/32 split or better.
MIN_ENTROPY = 0.90

_WORD_CHAR = re.compile(r"[A-Za-z0-9)\]\"'’,;:]")
_LETTER = re.compile(r"[A-Za-z]")


# ---------------------------------------------------------------------------
# Bit extraction
# ---------------------------------------------------------------------------

def inter_word_bits(text: str) -> str:
    """Runs of one or two spaces between two letters. 1 space = 0, 2 = 1.

    Both sides must be letters, which excludes code (`x = 1`, PEP 8's two
    spaces before an inline comment) and column alignment.
    """
    bits: list[str] = []
    for line in text.splitlines():
        for m in re.finditer(r"(?<=[A-Za-z,;:’'\)])( {1,3})(?=[A-Za-z\"'“(])", line):
            run = len(m.group(1))
            if run == 1:
                bits.append("0")
            elif run == 2:
                bits.append("1")
            # 3+ is alignment, not signal — drop it entirely.
    return "".join(bits)


def inter_sentence_bits(text: str) -> str:
    """One vs two spaces after terminal punctuation."""
    bits: list[str] = []
    for m in re.finditer(r"[.!?][\"'’”]?( {1,3})(?=[A-Z])", text):
        run = len(m.group(1))
        if run == 1:
            bits.append("0")
        elif run == 2:
            bits.append("1")
    return "".join(bits)


def trailing_bits(text: str) -> tuple[str, str]:
    """Trailing whitespace. Returns (bits, encoding used)."""
    runs: list[str] = []
    for line in text.splitlines():
        stripped = line.rstrip(" \t")
        if len(stripped) == len(line) or not stripped.strip():
            continue                      # no trailing run, or a blank line
        runs.append(line[len(stripped):])

    if len(runs) < MIN_BITS_DECODE:
        return "", ""

    if any("\t" in run for run in runs):
        # snow-style: every trailing character is one bit.
        return "".join("1" if ch == "\t" else "0"
                       for run in runs for ch in run), "space=0 tab=1"

    bits = "".join("0" if len(run) == 1 else "1" if len(run) == 2 else ""
                   for run in runs)
    return bits, "1 space=0, 2 spaces=1"


# ---------------------------------------------------------------------------
# Decoding and entropy
# ---------------------------------------------------------------------------

def entropy(bits: str) -> float:
    if not bits:
        return 0.0
    counts = Counter(bits)
    total = len(bits)
    return -sum((n / total) * math.log2(n / total) for n in counts.values() if n)


def decode_bits(bits: str) -> str | None:
    """Try the usual framings and return the first readable result."""
    for width in (8, 7):
        for offset in (0, 1):
            window = bits[offset:]
            usable = len(window) - (len(window) % width)
            if usable < width * 3:
                continue
            for reverse in (False, True):
                chars = []
                for i in range(0, usable, width):
                    chunk = window[i:i + width]
                    if reverse:
                        chunk = chunk[::-1]
                    chars.append(chr(int(chunk, 2)))
                # Trailing NULs are padding: the carrier has more gaps than the
                # payload needed. Strip before judging readability, or a short
                # message in a long document never passes.
                candidate = "".join(chars).rstrip("\x00")
                if _is_readable(candidate):
                    return candidate.strip()
    return None


def _is_readable(text: str) -> bool:
    """Deliberately strict — a false 'decoded payload' is the worst output."""
    if len(text) < 4:
        return False
    printable = sum(1 for c in text if 0x20 <= ord(c) < 0x7F)
    if printable / len(text) < 0.9:
        return False
    alnum = sum(1 for c in text if c.isalnum())
    return alnum / len(text) >= 0.5


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

CHANNELS = [
    ("inter_word", "spacing between words", inter_word_bits),
    ("inter_sentence", "spacing after sentences", inter_sentence_bits),
]


def detect(ctx: FileCtx) -> list[Finding]:
    text = ctx.text
    if not text or len(text) < 64:
        return []

    # Only the file's own bytes carry this signal. PDF text comes out of a
    # content stream where spacing is a rendering artefact, and OOXML/HTML text
    # is reassembled by us with spaces we invented — every one of those sources
    # produces convincing-looking high-entropy spacing that means nothing.
    if ctx.text_source != "plain":
        if ctx.text_source:
            ctx.notes.append(f"whitespace-skipped:{ctx.text_source}")
        return []

    findings: list[Finding] = []
    channels: list[tuple[str, str, str, str]] = []   # key, label, bits, encoding

    for key, label, extractor in CHANNELS:
        bits = extractor(text)
        if bits:
            channels.append((key, label, bits, "1 space=0, 2 spaces=1"))

    tbits, tencoding = trailing_bits(text)
    if tbits:
        channels.append(("trailing", "trailing whitespace", tbits, tencoding))

    for key, label, bits, encoding in channels:
        ones = bits.count("1")
        if len(bits) < MIN_BITS_DECODE or ones == 0 or ones == len(bits):
            continue                       # nothing, or a pure habit

        payload = decode_bits(bits)
        if payload:
            findings.append(Finding(
                tier=Tier.A, detector=DETECTOR,
                signal=f"whitespace.payload.{key}",
                summary=f"Hidden payload encoded in {label} decodes to: "
                        f"\"{_clip(payload)}\"",
                evidence={"channel": key, "encoding": encoding,
                          "bits": len(bits), "decoded": payload[:2000],
                          "bit_string": bits[:512]},
            ))
            continue

        ent = entropy(bits)
        if len(bits) >= MIN_BITS_ENTROPY and ent >= MIN_ENTROPY:
            findings.append(Finding(
                tier=Tier.C, detector=DETECTOR,
                signal=f"whitespace.entropy.{key}",
                summary=(f"{label.capitalize()} varies at {ent:.2f} bits per gap "
                         f"over {len(bits)} gaps ({ones} wide / {len(bits) - ones} "
                         f"narrow) — carries information a consistent writing "
                         f"habit would not, but no readable payload decoded"),
                evidence={"channel": key, "encoding": encoding,
                          "bits": len(bits), "entropy": round(ent, 3),
                          "wide": ones, "narrow": len(bits) - ones,
                          "bit_string": bits[:512],
                          "note": "A uniform habit (always one space, always two) "
                                  "scores ~0.0 here and is never reported. This "
                                  "pattern is mixed, which is what a payload looks "
                                  "like — but it may also be inconsistent editing."},
            ))

    return findings


def _clip(text: str, limit: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"
