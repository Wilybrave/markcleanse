"""Build `samples/` and regenerate `DETECTION.md` from what the tool actually says.

One small file per detection type, then the catalogue is written by *scanning
those files* — so the documentation cannot drift from the behaviour. If a
detector changes, re-run this and the numbers in the doc change with it.

    python3 tools/build_samples.py

Samples are committed (unlike `tests/fixtures/`, which is generated per-run)
so anyone reading the docs can try the exact file being described.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from markcleanse import ScanOptions, scan_file          # noqa: E402
from markcleanse.result import TIER_MEANING, Tier       # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")

#: (fixture name, sample name, detector, what it demonstrates)
CATALOGUE: list[tuple[str, str, str, str, str]] = [
    # --- C2PA / Content Credentials -----------------------------------
    ("c2pa_signed.png", "c2pa-verified.png", "C2PA", "c2pa",
     "A correctly signed manifest: signature, assertion hashes and the "
     "`hash.data` binding all check out."),
    ("c2pa_transplant.png", "c2pa-transplanted.png", "C2PA", "c2pa",
     "The manifest from the file above, pasted onto a different image. The "
     "signature is still perfect — the binding is what catches it."),
    ("c2pa_edited.png", "c2pa-edited-after-signing.png", "C2PA", "c2pa",
     "Valid manifest, image bytes altered afterwards."),
    ("c2pa_forged.png", "c2pa-forged-assertion.png", "C2PA", "c2pa",
     "An assertion rewritten inside a signed manifest to claim a different "
     "generator."),
    ("c2pa_ocsp_good.png", "c2pa-revocation-good.png", "C2PA", "c2pa",
     "Manifest with a stapled OCSP response proving the credential was not "
     "revoked. Checked offline."),
    ("c2pa_ocsp_revoked.png", "c2pa-revocation-revoked.png", "C2PA", "c2pa",
     "Stapled OCSP says the signing certificate was revoked for key "
     "compromise."),
    ("c2pa_boxhash.png", "c2pa-boxhash.png", "C2PA", "c2pa",
     "Bound with `hash.boxes`, which names PNG chunks instead of byte ranges "
     "— so inserting a chunk breaks it even if no original byte changes."),
    ("c2pa_boxhash_edited.png", "c2pa-boxhash-edited.png", "C2PA", "c2pa",
     "The same file with one byte of image data flipped."),
    ("c2pa_bmff.avif", "c2pa-avif.avif", "C2PA", "c2pa",
     "AVIF bound with `hash.bmff.v3`, whose digest folds each top-level "
     "box's own offset into the hash."),
    ("c2pa_bmff_transplant.avif", "c2pa-avif-transplanted.avif", "C2PA", "c2pa",
     "That AVIF manifest appended to a different image."),
    ("c2pa_bmff.mp4", "c2pa-video.mp4", "C2PA", "c2pa",
     "A real MP4 with a container-level manifest. Provenance is verified; the "
     "video **frames are never examined**."),
    ("camera_c2pa.jpg", "c2pa-camera-capture.jpg", "C2PA", "c2pa",
     "A manifest asserting `digitalCapture` — positive evidence of a camera "
     "origin, and it must never be reported as AI."),

    # --- Embedded generation records -----------------------------------
    ("sd_a1111.png", "sd-generation-parameters.png", "Generation record", "png_text",
     "Stable Diffusion WebUI writes the entire prompt, sampler, seed and "
     "model hash into a PNG text chunk."),
    ("comfyui.png", "comfyui-workflow.png", "Generation record", "png_text",
     "ComfyUI embeds the whole node graph, including checkpoint filenames."),
    ("novelai.png", "novelai-metadata.png", "Generation record", "png_text",
     "NovelAI stamps `Software`/`Source` plus a generation comment."),
    ("stealth_novelai.png", "stealth-pnginfo.png", "Pixel payload", "stealth_png",
     "Generation data hidden in the alpha channel's least-significant bits. "
     "Survives every metadata strip."),

    # --- Declared metadata ----------------------------------------------
    ("midjourney_xmp.png", "midjourney-xmp.png", "Metadata", "image_meta",
     "XMP `CreatorTool` naming the generator."),
    ("google_synthid_hint.png", "google-synthid-indicated.png", "Metadata", "image_meta",
     "Google-family metadata, which also means SynthID is present in the "
     "pixels — and unverifiable by anyone but Google."),
    ("gamma_export.pdf", "gamma-export.pdf", "Metadata", "documents",
     "A PDF whose `/Producer` names an AI presentation tool."),
    ("ai_doc.docx", "ai-document.docx", "Metadata", "documents",
     "DOCX with AI application metadata and a hidden payload in the body."),

    # --- Hidden payloads -------------------------------------------------
    ("hidden_tags.txt", "hidden-unicode-tags.txt", "Hidden payload", "unicode_wm",
     "Unicode Tags block (U+E0000). Invisible everywhere; decodes to ASCII."),
    ("hidden_zerowidth.txt", "hidden-zero-width.txt", "Hidden payload", "unicode_wm",
     "Zero-width characters encoding a message in binary."),
    ("hidden_varsel.txt", "hidden-variation-selectors.txt", "Hidden payload", "unicode_wm",
     "Variation selectors, one byte each."),
    ("homoglyph.txt", "homoglyph-substitution.txt", "Hidden payload", "unicode_wm",
     "Cyrillic lookalikes swapped into Latin words."),
    ("hidden_interword.txt", "whitespace-interword.txt", "Hidden payload", "whitespace_wm",
     "A payload in the gaps between words: one space = 0, two = 1."),
    ("hidden_trailing.txt", "whitespace-trailing.txt", "Hidden payload", "whitespace_wm",
     "A payload in end-of-line whitespace."),

    # --- Source code ------------------------------------------------------
    ("code_hidden_payload.py", "code-hidden-instructions.py", "Code", "unicode_wm",
     "Invisible instructions hidden in a source comment — a live prompt-injection "
     "technique. An assistant reading the file obeys them; a reviewer sees nothing. "
     "The decoded string is shown in the evidence."),
    ("code_clean.ts", "code-clean.ts", "Code", "—",
     "Ordinary TypeScript with emoji and dense punctuation. Proves stylometry is "
     "skipped on source rather than scoring type annotations as “AI prose”, and that "
     "emoji joiners are not read as hidden characters."),

    # --- Text heuristics --------------------------------------------------
    ("leakage.txt", "assistant-leakage.txt", "Text", "stylometry",
     "Chat-assistant phrasing pasted verbatim."),
    ("llm_prose.md", "llm-stylometry.md", "Text", "stylometry",
     "Prose scored on word choice, punctuation and rhythm. **Heuristic "
     "only** — see the measured error rates below."),

    # --- Clean controls ---------------------------------------------------
    ("clean.png", "clean-image.png", "Control", "—",
     "An ordinary PNG with no markers of any kind."),
    ("clean.avif", "clean-image.avif", "Control", "—",
     "An ordinary AVIF."),
    ("clean_rgba.png", "clean-rgba-random-lsb.png", "Control", "—",
     "RGBA image whose alpha low bits vary randomly — proves the stealth "
     "detector needs the magic header, not merely an alpha channel."),
    ("human_prose.md", "clean-human-prose.md", "Control", "—",
     "Human-written prose."),
    ("habit_twospace.txt", "clean-two-space-habit.txt", "Control", "—",
     "Consistent two-space-after-period typing. A habit carries no "
     "information, so it is never flagged."),
]

CATEGORY_ORDER = ["C2PA", "Generation record", "Pixel payload", "Metadata",
                  "Hidden payload", "Code", "Text", "Control"]

#: Media type, for the Docs filter. Derived from the extension so a new sample
#: classifies itself.
KINDS = {
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".avif": "image",
    ".webp": "image", ".gif": "image", ".heic": "image",
    ".mp4": "video", ".mov": "video",
    ".pdf": "document", ".docx": "document", ".pptx": "document",
    ".xlsx": "document", ".odt": "document",
    ".py": "code", ".ts": "code", ".js": "code", ".tsx": "code", ".json": "code",
    ".txt": "text", ".md": "text",
}


def kind_of(name: str) -> str:
    return KINDS.get(os.path.splitext(name)[1].lower(), "other")


def build_fixtures(tmp: str) -> None:
    for script in ("make_fixtures.py",):
        subprocess.run([sys.executable, os.path.join(ROOT, "tests", script), tmp],
                       check=True, capture_output=True)


def copy_samples(tmp: str) -> list[tuple]:
    os.makedirs(SAMPLES, exist_ok=True)
    for stale in os.listdir(SAMPLES):
        os.remove(os.path.join(SAMPLES, stale))

    present = []
    for fixture, sample, category, detector, blurb in CATALOGUE:
        src = os.path.join(tmp, fixture)
        if not os.path.exists(src):
            continue
        shutil.copy2(src, os.path.join(SAMPLES, sample))
        present.append((fixture, sample, category, detector, blurb))
    return present


def scan(sample: str) -> tuple[str, str, str, str]:
    """Return (verdict, tier, headline evidence, signals fired)."""
    opts = ScanOptions(use_exiftool=False, include_heuristics=True)
    report = scan_file(os.path.join(SAMPLES, sample), opts)
    tier = report.best_tier.value if report.best_tier else "—"
    signals = ", ".join(f"`{f.signal}`" for f in report.findings) or "—"
    return report.verdict.value, tier, report.basis, signals


def clip(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[:width - 1] + "…"


def write_index(rows: list[tuple]) -> None:
    """Emit `samples/index.json` so the web UI can render the catalogue.

    The same table that produces DETECTION.md drives the in-app Docs page —
    one source of truth for what each example demonstrates.
    """
    import json

    entries = []
    for _fixture, sample, category, detector, blurb in rows:
        verdict, tier, basis, _signals = scan(sample)
        report = scan_file(os.path.join(SAMPLES, sample),
                           ScanOptions(use_exiftool=False, include_heuristics=True))
        entries.append({
            "file": sample,
            "kind": kind_of(sample),
            "category": category,
            "detector": detector,
            "blurb": blurb,
            "expected_verdict": verdict,
            "expected_tier": tier,
            "basis": basis,
            "signals": [f.signal for f in report.findings],
            "size": os.path.getsize(os.path.join(SAMPLES, sample)),
        })
    payload = {"categories": CATEGORY_ORDER, "samples": entries}
    with open(os.path.join(SAMPLES, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_docs(rows: list[tuple]) -> None:
    out: list[str] = []
    w = out.append
    w("# What markcleanse detects\n")
    w("Every row below is a real file in [`samples/`](samples/), and every")
    w("verdict is the tool's actual output — this page is generated by")
    w("`tools/build_samples.py`, so it cannot drift from the code.\n")
    w("```bash")
    w("markcleanse samples/            # scan them all")
    w("markcleanse samples/c2pa-transplanted.png -v   # full evidence for one")
    w("```\n")
    w("## Evidence tiers\n")
    for tier in (Tier.A, Tier.B, Tier.U, Tier.C):
        w(f"- **{tier.value}** — {TIER_MEANING[tier]}")
    w("\n> Tier C is suggestive only. It must never be presented as proof.\n")

    for category in CATEGORY_ORDER:
        subset = [r for r in rows if r[2] == category]
        if not subset:
            continue
        w(f"\n## {category}\n")
        w("| Sample | Verdict | Tier | Signals | What it demonstrates |")
        w("|---|---|---|---|---|")
        for _fixture, sample, _cat, detector, blurb in subset:
            verdict, tier, _basis, signals = scan(sample)
            w(f"| [`{sample}`](samples/{sample}) | `{verdict}` | {tier} | "
              f"{signals} | {blurb} |")
        w("")
        detectors = sorted({r[3] for r in subset} - {"—"})
        if detectors:
            w(f"Detector: {', '.join('`' + d + '`' for d in detectors)}\n")

    w("\n## Actual output\n")
    w("```")
    w("$ markcleanse samples/")
    w("")
    w(f"{'FILE':38} {'VERDICT':18} {'T':2} EVIDENCE")
    w("─" * 100)
    for _fixture, sample, _cat, _det, _blurb in rows:
        verdict, tier, basis, _signals = scan(sample)
        w(f"{clip(sample, 38):38} {verdict:18} {tier:2} {clip(basis, 40)}")
    w("```\n")
    w(NOT_COVERED)

    with open(os.path.join(ROOT, "DETECTION.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))


NOT_COVERED = """
## What this does *not* detect

The honest half of the catalogue. These are not gaps to be closed by more code —
most of them cannot be closed by anyone without the vendor's cooperation.

### Vendor watermarks — structurally undetectable here

| Watermark | Where | Why we cannot read it |
|---|---|---|
| **Google SynthID** | Gemini, Imagen, Veo images/audio/video | Invisible pixel-space signal, decodable only with Google's key. The SynthID Detector portal is waitlisted and has **no public specification**, so no third party can implement detection. |
| **Claude text watermark** | Claude output from 2 Aug 2026 | SynthID-Text: the key biases word choice between equally good options. **No character is inserted and no artefact lands in the file** — there is nothing for a scanner to find. Anthropic's detection API is announced but not yet released. |
| **Gemini text** | Gemini output | SynthID-Text, same structure, Google's key. |
| **Meta Stable Signature** | Meta AI images | No public detector; independent work finds watermarks of this class brittle. |

When metadata indicates one of these origins, markcleanse reports it as tier **U** —
*origin indicated, watermark unchecked* — rather than pretending to have read
anything.

### Detection approaches we deliberately do not use

Other "AI image detector" tools classify the **pixels**: error-level analysis,
noise residual and PRNU inspection, frequency-domain artefacts, or a CNN trained
to spot GAN/diffusion fingerprints. None of that is here, on purpose. Those
methods produce a probability with an error rate that shifts every time a new
model ships, they are defeated by resizing and re-compression, and they cannot
tell you *which* tool made the file. This project reports evidence you can point
at in an argument instead.

The same reasoning applies to text: a perplexity-based classifier such as
Binoculars is far stronger than the stylometry here (>90% detection at 0.01%
false positives, versus roughly 28% at 0.8% measured on our own corpus — see
`tests/benchmark_stylometry.py`), but it needs two local LLMs and a GPU. The
stylometry in this repo is triage, not evidence.

### Formats and checks not implemented

- **Video frames** — container-level C2PA in MP4 is read and verified; the
  picture content is never examined.
- **Audio** — not examined at all.
- **CRL revocation** — OCSP is implemented (stapled by default, live opt-in);
  a CA that publishes revocation only by CRL reports as "no OCSP response".
- **RFC 3161 timestamps** are parsed and displayed but their own signatures are
  not validated — so "signed before the certificate expired" cannot be
  distinguished from a backdated claim.
- **`c2pa.hash.collection`** bindings report `unsupported`. `hash.data`,
  `hash.bmff` v1–v3 and `hash.boxes` are all implemented.
- **Encrypted PDFs** are not decrypted.
- Nested containers are followed **one level deep**.

### The rule that outranks everything above

> **Absence of evidence is not evidence of human authorship.**

A screenshot, a re-save, a social-media upload or `exiftool -all=` removes every
signal in the catalogue while changing nothing a viewer can see. A clean result
means *no markers survived* — never *a human made this*.
"""


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        build_fixtures(tmp)
        rows = copy_samples(tmp)
    write_docs(rows)
    write_index(rows)
    total = sum(os.path.getsize(os.path.join(SAMPLES, f))
                for f in os.listdir(SAMPLES))
    print(f"samples/: {len(rows)} files, {total:,} bytes")
    print("DETECTION.md regenerated from live scan output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
