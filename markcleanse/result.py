"""Core data model: evidence tiers, findings, per-file reports.

The whole design principle of markcleanse is that we never emit a fake percentage.
Every claim is anchored to an evidence *tier* that says how much you can lean
on it in front of a client.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Tier(str, Enum):
    #: Cryptographically signed or literally embedded generation record.
    #: A C2PA manifest, or a PNG chunk containing the prompt and model hash.
    #: If this fires, the file was made by an AI. Full stop.
    A = "A"

    #: Self-declared metadata naming a known generator ("Software: Midjourney").
    #: Explicit and near-always true, but trivially forged or stripped.
    B = "B"

    #: Heuristic. Dimensions, missing EXIF, unicode anomalies, stylometry.
    #: Suggestive only. Never present this alone as proof.
    C = "C"

    #: A watermark is indicated but is NOT verifiable by any third-party tool.
    #: Google SynthID is the main case: the detector is Google's, not ours.
    U = "U"


TIER_WEIGHT = {Tier.A: 4, Tier.B: 3, Tier.U: 2, Tier.C: 1}

TIER_MEANING = {
    Tier.A: "embedded generation record (signed manifest or generation parameters)",
    Tier.B: "self-declared metadata naming a generator",
    Tier.C: "heuristic signal only",
    Tier.U: "watermark indicated, not locally verifiable",
}


class Verdict(str, Enum):
    #: The file carries provenance that does not describe it — a manifest
    #: transplanted from another asset, edited after signing, or forged. This
    #: outranks everything else: whatever the manifest claims, the fact that it
    #: is not honest about this file is the more important finding.
    PROVENANCE_INVALID = "PROVENANCE-FORGED"
    CONFIRMED_AI = "AI-GENERATED"
    DECLARED_AI = "AI-DECLARED"
    WATERMARK_INDICATED = "WATERMARK?"
    SUSPECT = "SUSPECT"
    SIGNED_CAPTURE = "SIGNED-CAPTURE"
    NO_EVIDENCE = "NO-EVIDENCE"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"


VERDICT_ORDER = [
    Verdict.PROVENANCE_INVALID,
    Verdict.CONFIRMED_AI,
    Verdict.DECLARED_AI,
    Verdict.WATERMARK_INDICATED,
    Verdict.SUSPECT,
    Verdict.SIGNED_CAPTURE,
    Verdict.NO_EVIDENCE,
    Verdict.UNSUPPORTED,
    Verdict.ERROR,
]


@dataclass
class Finding:
    """One piece of evidence found in one file."""

    tier: Tier
    detector: str          # module that produced it, e.g. "png_text"
    signal: str            # stable machine code, e.g. "png.parameters.a1111"
    summary: str           # one human-readable line
    source: str | None = None      # attributed generator, if we can name one
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "detector": self.detector,
            "signal": self.signal,
            "summary": self.summary,
            "source": self.source,
            "evidence": _truncate(self.evidence),
        }


def _prefer_specific(sources: set[str]) -> set[str]:
    """Collapse vague attributions when a precise one names the same family.

    Two detectors reading the same PNG can yield "Stable Diffusion (A1111-family
    WebUI)" and "Stable Diffusion (unspecified UI)". Reporting both as peers is
    noise, not nuance — keep the one that actually says something.
    """
    if len(sources) < 2:
        return sources
    kept = set(sources)
    for vague in list(kept):
        if "unspecified" not in vague.lower():
            continue
        family = vague.split("(")[0].strip().lower()
        if any(other is not vague and other.lower().startswith(family)
               and "unspecified" not in other.lower() for other in kept):
            kept.discard(vague)
    return kept or set(sources)


def _truncate(obj: Any, limit: int = 4000) -> Any:
    """Keep evidence blobs (prompts, workflow JSON) from bloating reports."""
    if isinstance(obj, str):
        return obj if len(obj) <= limit else obj[:limit] + f"... [+{len(obj) - limit} chars]"
    if isinstance(obj, dict):
        return {k: _truncate(v, limit) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_truncate(v, limit) for v in obj[:50]]
    return obj


@dataclass
class FileReport:
    path: str
    size: int = 0
    kind: str = "unknown"           # image / document / text / unsupported
    fmt: str = ""                   # jpeg, png, pdf, docx ...
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    # ---- derived --------------------------------------------------------

    #: Signal prefixes that are not evidence of AI generation:
    #: ``capture.`` asserts a human/camera origin, ``info.`` records what the
    #: scan could not examine, and ``c2pa.verified`` states that a manifest is
    #: internally consistent — which is equally true of a signed photograph.
    #: Letting that one count as AI evidence labelled every verified camera
    #: capture AI-GENERATED.
    NON_EVIDENCE = ("capture.", "info.", "c2pa.verified")

    @property
    def best_tier(self) -> Tier | None:
        ai = [f for f in self.findings if not f.signal.startswith(self.NON_EVIDENCE)]
        if not ai:
            return None
        return max((f.tier for f in ai), key=lambda t: TIER_WEIGHT[t])

    @property
    def verdict(self) -> Verdict:
        if self.errors and not self.findings:
            return Verdict.ERROR
        # Only claim "unsupported" when we genuinely found nothing. A format we
        # do not fully parse can still yield a C2PA manifest, and reporting
        # UNSUPPORTED over a Tier A finding buries it.
        if self.kind == "unsupported" and not self.findings:
            return Verdict.UNSUPPORTED
        if any(f.signal.startswith("integrity.") for f in self.findings):
            return Verdict.PROVENANCE_INVALID
        if any(f.signal.startswith("capture.signed") for f in self.findings):
            if not any(f.tier in (Tier.A, Tier.B) for f in self.findings
                       if not f.signal.startswith(self.NON_EVIDENCE)):
                return Verdict.SIGNED_CAPTURE
        tier = self.best_tier
        if tier is Tier.A:
            return Verdict.CONFIRMED_AI
        if tier is Tier.B:
            return Verdict.DECLARED_AI
        if tier is Tier.U:
            return Verdict.WATERMARK_INDICATED
        if tier is Tier.C:
            return Verdict.SUSPECT
        return Verdict.NO_EVIDENCE

    @property
    def source(self) -> str | None:
        """Best attribution: prefer the strongest tier that named a generator."""
        named = [f for f in self.findings if f.source]
        if not named:
            return None
        named.sort(key=lambda f: TIER_WEIGHT[f.tier], reverse=True)
        top = named[0]
        peers = {f.source for f in named if TIER_WEIGHT[f.tier] == TIER_WEIGHT[top.tier]}
        peers = _prefer_specific(peers)
        if len(peers) > 1:
            return " / ".join(sorted(peers))
        return next(iter(peers), top.source)

    @property
    def basis(self) -> str:
        tier = self.best_tier
        if tier is None:
            return self.findings[0].summary if self.findings else ""
        top = max((f for f in self.findings if f.tier is tier),
                  key=lambda f: len(f.summary))
        return top.summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": os.path.basename(self.path),
            "size": self.size,
            "kind": self.kind,
            "format": self.fmt,
            "verdict": self.verdict.value,
            "tier": self.best_tier.value if self.best_tier else None,
            "tier_meaning": TIER_MEANING[self.best_tier] if self.best_tier else None,
            "source": self.source,
            "basis": self.basis,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
