"""Measure the stylometry detector: true-positive and false-positive rates.

Every other test in this repo asks "does the code do what I meant?". This one
asks the only question a user cares about: **how often is it wrong?**

    python3 tests/benchmark_stylometry.py <human-dir> <ai-dir>

Both directories are read recursively; every text file is chunked into
comparable ~400-word documents so length does not confound the comparison.

Building the corpus
-------------------

*Human* must be provably pre-LLM or provably hand-written. Text published
before mid-2020 is safe: old RFCs, Project Gutenberg, tagged pre-2020 README
files. Anything scraped from the modern web is not usable — you cannot label it.

*AI* must be output you know the provenance of, not output this tool flagged.
Labelling positives with the detector under test measures nothing.

Reading the result
------------------

FPR is the number that matters. A false positive is an accusation against a
real person, and at any realistic volume a 1% rate means you will make one.
For scale, Binoculars (ICML 2024) reports >90% TPR at 0.01% FPR — roughly two
orders of magnitude better than a regex approach can reach.

Both figures produced here are optimistic: the human corpus is stylistically
distant from LLM prose (technical specs, Victorian novels), and the AI corpus
is whatever model you generated it with, which is the one this module's
patterns were written against.
"""

from __future__ import annotations

import os
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from markcleanse.detectors.stylometry import (  # noqa: E402
    MIN_LEXICAL_SCORE, analyse, strip_non_prose)

CHUNK_WORDS = 400
MIN_CHUNK_WORDS = 250
TEXT_EXTS = {".txt", ".md", ".markdown", ".rst", ".text", ""}
THRESHOLDS = (25, 30, 35, 40, 50, 60, 70)


def chunks(text: str, limit: int = 20) -> list[str]:
    tokens = re.sub(r"\r", "", text).split()
    out = []
    for i in range(0, len(tokens), CHUNK_WORDS):
        piece = " ".join(tokens[i:i + CHUNK_WORDS])
        if len(piece.split()) >= MIN_CHUNK_WORDS:
            out.append(piece)
        if len(out) >= limit:
            break
    return out


def load(root: str, limit_per_file: int = 12) -> list[str]:
    samples: list[str] = []
    for base, _dirs, files in os.walk(root):
        for name in sorted(files):
            if os.path.splitext(name)[1].lower() not in TEXT_EXTS:
                continue
            path = os.path.join(base, name)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    samples.extend(chunks(fh.read(), limit_per_file))
            except OSError:
                continue
    return samples


def score(text: str) -> float:
    """The score the tool would actually report, gate included."""
    stats = analyse(strip_non_prose(text))
    if (stats["lexical_score"] < MIN_LEXICAL_SCORE
            or stats["lexical_features"] < 2):
        return 0.0
    return stats["score"]


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    human = [score(t) for t in load(sys.argv[1])]
    ai = [score(t) for t in load(sys.argv[2])]
    if not human or not ai:
        print("need samples in both directories", file=sys.stderr)
        return 2

    print(f"human n={len(human):4}  mean={statistics.fmean(human):5.1f}  "
          f"max={max(human):5.1f}")
    print(f"ai    n={len(ai):4}  mean={statistics.fmean(ai):5.1f}  "
          f"max={max(ai):5.1f}\n")
    print(f"{'thresh':>7} {'TPR':>8} {'FPR':>8}  {'1 false accusation per':>24}")
    for th in THRESHOLDS:
        tpr = sum(x >= th for x in ai) / len(ai)
        fpr = sum(x >= th for x in human) / len(human)
        per = f"{1 / fpr:,.0f} documents" if fpr else "none observed"
        print(f"{th:7} {tpr * 100:7.1f}% {fpr * 100:7.1f}%  {per:>24}")

    print("\nreference: Binoculars (ICML 2024) reports >90% TPR at 0.01% FPR "
          "on its own benchmark;\nthese corpora differ, so treat it as a scale, "
          "not a like-for-like comparison.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
