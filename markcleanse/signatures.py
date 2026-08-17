"""Knowledge base of generator signatures.

Everything that maps an observed string / structure to a named AI generator
lives here so the detectors stay dumb and this file stays auditable.

Keep entries ordered most-specific first; matching is first-hit-wins.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Generator name signatures. Matched (case-insensitively) against any metadata
# string: EXIF Software, XMP CreatorTool, PDF /Producer, C2PA claim_generator,
# DOCX Application, PNG text values, etc.
# ---------------------------------------------------------------------------

#: (compiled pattern, canonical source name)
NAME_SIGNATURES: list[tuple[re.Pattern[str], str]] = [
    # --- OpenAI ---------------------------------------------------------
    (re.compile(r"\bgpt-?image(-1)?\b", re.I),            "OpenAI GPT-Image"),
    (re.compile(r"\bdall[\s·∙•.\-]?e\s*3\b", re.I), "OpenAI DALL·E 3"),
    (re.compile(r"\bdall[\s·∙•.\-]?e\b", re.I),     "OpenAI DALL·E"),
    (re.compile(r"\bsora\b", re.I),                       "OpenAI Sora"),
    (re.compile(r"\bchatgpt\b", re.I),                    "OpenAI ChatGPT"),
    (re.compile(r"\bopenai\b", re.I),                     "OpenAI (unspecified)"),

    # --- Google ---------------------------------------------------------
    (re.compile(r"\bimagen\s*\d*\b", re.I),               "Google Imagen"),
    (re.compile(r"\bnano[\s\-]?banana\b", re.I),          "Google Gemini (Nano Banana)"),
    (re.compile(r"\bgemini\b", re.I),                     "Google Gemini"),
    (re.compile(r"\bveo\s*\d*\b", re.I),                  "Google Veo"),
    (re.compile(r"\bmade with google ai\b", re.I),        "Google AI"),
    (re.compile(r"\bgoogle\s+(ai|deepmind|labs)\b", re.I), "Google AI"),
    # Google signs Gemini/Imagen output with its own C2PA stack; the claim
    # generator string never mentions the model. Observed on real files:
    # "Google C2PA Core Generator Library", signed by "Google C2PA Media
    # Services 1P ICA G3". Deliberately not a bare \bgoogle\b — that would
    # match Chrome, Docs and Picasa exports.
    (re.compile(r"\bgoogle\s+c2pa\b|\bgoogle\s+media\s+(processing|services)\b", re.I),
     "Google AI"),
    (re.compile(r"\bwhisk\b", re.I),                      "Google Whisk"),
    (re.compile(r"\bimagefx\b", re.I),                    "Google ImageFX"),

    # --- Adobe ----------------------------------------------------------
    (re.compile(r"\bfirefly\b", re.I),                    "Adobe Firefly"),
    (re.compile(r"adobe\s+generative", re.I),             "Adobe Generative Fill"),

    # --- Midjourney -----------------------------------------------------
    (re.compile(r"\bmidjourney\b", re.I),                 "Midjourney"),
    (re.compile(r"\bniji\s*journey\b", re.I),             "NijiJourney"),

    # --- Stability / local SD stack --------------------------------------
    (re.compile(r"\bstable\s*diffusion\s*(xl|3(\.\d)?)\b", re.I), "Stable Diffusion (SDXL/SD3)"),
    (re.compile(r"\bstable\s*diffusion\b", re.I),         "Stable Diffusion"),
    (re.compile(r"\bstability\s*ai\b", re.I),             "Stability AI"),
    (re.compile(r"\bautomatic1111\b|\bsd[\-\s]?webui\b", re.I), "Stable Diffusion (A1111 WebUI)"),
    (re.compile(r"\bcomfyui\b", re.I),                    "ComfyUI"),
    (re.compile(r"\bforge\b(?=.*\bsd\b)", re.I),          "Stable Diffusion (Forge)"),
    (re.compile(r"\binvokeai\b|\binvoke\s*ai\b", re.I),   "InvokeAI"),
    (re.compile(r"\bfooocus\b", re.I),                    "Fooocus"),
    (re.compile(r"\bdraw\s*things\b", re.I),              "Draw Things"),
    (re.compile(r"\beasy\s*diffusion\b", re.I),           "Easy Diffusion"),
    (re.compile(r"\bnovel\s*ai\b", re.I),                 "NovelAI"),
    (re.compile(r"\bflux(\.\d)?(\s*\[?(dev|schnell|pro)\]?)?\b", re.I), "Black Forest Labs FLUX"),

    # --- Other image services --------------------------------------------
    (re.compile(r"\bleonardo(\.ai)?\b", re.I),            "Leonardo.Ai"),
    (re.compile(r"\bideogram\b", re.I),                   "Ideogram"),
    (re.compile(r"\brecraft\b", re.I),                    "Recraft"),
    (re.compile(r"\bplayground\s*(ai|v\d)\b", re.I),      "Playground AI"),
    (re.compile(r"\bkrea(\.ai)?\b", re.I),                "Krea"),
    (re.compile(r"\bfreepik\s*(ai|pikaso)\b", re.I),      "Freepik AI"),
    (re.compile(r"\bcanva\b.*\b(magic|ai)\b", re.I),      "Canva Magic Media"),
    (re.compile(r"\bmicrosoft\s+designer\b", re.I),       "Microsoft Designer"),
    (re.compile(r"\bbing\s+image\s+creator\b", re.I),     "Bing Image Creator"),
    (re.compile(r"\bcopilot\b", re.I),                    "Microsoft Copilot"),
    (re.compile(r"\bgrok\b|\baurora\b(?=.*x\.ai)", re.I), "xAI Grok"),
    (re.compile(r"\bx\.ai\b", re.I),                      "xAI"),
    (re.compile(r"\bmeta\s*ai\b|\bemu\b(?=.*meta)", re.I), "Meta AI"),
    (re.compile(r"\bstarry\s*ai\b", re.I),                "StarryAI"),
    (re.compile(r"\bnight\s*cafe\b", re.I),               "NightCafe"),
    (re.compile(r"\bdream\s*studio\b", re.I),             "DreamStudio"),
    (re.compile(r"\bartbreeder\b", re.I),                 "Artbreeder"),
    (re.compile(r"\brunway(ml)?\b", re.I),                "Runway"),
    (re.compile(r"\bpika\s*labs\b", re.I),                "Pika"),
    (re.compile(r"\bluma\s*(ai|labs)\b", re.I),           "Luma AI"),
    (re.compile(r"\bkling\b", re.I),                      "Kling AI"),
    (re.compile(r"\bhailuo\b|\bminimax\b", re.I),         "MiniMax Hailuo"),
    (re.compile(r"\bseedream\b|\bdoubao\b", re.I),        "ByteDance Seedream"),
    (re.compile(r"\bqwen[\s\-]?image\b", re.I),           "Alibaba Qwen-Image"),
    (re.compile(r"\bhunyuan\b", re.I),                    "Tencent Hunyuan"),

    # --- Text-side / document producers ----------------------------------
    (re.compile(r"\bclaude\b", re.I),                     "Anthropic Claude"),
    (re.compile(r"\banthropic\b", re.I),                  "Anthropic"),
    (re.compile(r"\bnotebooklm\b", re.I),                 "Google NotebookLM"),
    (re.compile(r"\bperplexity\b", re.I),                 "Perplexity"),
    (re.compile(r"\bjasper(\.ai)?\b", re.I),              "Jasper"),
    (re.compile(r"\bcopy\.ai\b", re.I),                   "Copy.ai"),
    (re.compile(r"\bwriter\.com\b|\bwordtune\b", re.I),   "AI writing assistant"),
    (re.compile(r"\bquillbot\b", re.I),                   "QuillBot"),
    (re.compile(r"\bgamma(\.app)?\b", re.I),              "Gamma"),
    (re.compile(r"\btome(\.app)?\b", re.I),               "Tome"),
    (re.compile(r"\bbeautiful\.ai\b", re.I),              "Beautiful.ai"),
]


def identify(text: str | None) -> str | None:
    """Return a canonical generator name for a metadata string, if recognised."""
    if not text:
        return None
    for pattern, name in NAME_SIGNATURES:
        if pattern.search(text):
            return name
    return None


def identify_all(text: str | None) -> list[str]:
    """Every generator name matching a string (order = signature specificity)."""
    if not text:
        return []
    out: list[str] = []
    for pattern, name in NAME_SIGNATURES:
        if pattern.search(text) and name not in out:
            out.append(name)
    return out


# ---------------------------------------------------------------------------
# Generators known to embed a watermark we cannot verify locally.
# If we see their fingerprint we say so honestly rather than pretending
# we decoded anything.
# ---------------------------------------------------------------------------

UNVERIFIABLE_WATERMARKS: dict[str, str] = {
    # EU AI Act Article 50 took effect 2026-08-02 and the major labs shipped
    # text watermarking to comply. None of it is locally verifiable.
    "Anthropic Claude": "Claude text watermark (SynthID-Text)",
    "Anthropic": "Claude text watermark (SynthID-Text)",
    "Google Gemini": "SynthID",
    "Google Gemini (Nano Banana)": "SynthID",
    "Google Imagen": "SynthID",
    "Google Veo": "SynthID",
    "Google AI": "SynthID",
    "Google Whisk": "SynthID",
    "Google ImageFX": "SynthID",
    "Google NotebookLM": "SynthID-Text",
    "Google Gemini (text)": "SynthID-Text",
    "Meta AI": "Meta Stable Signature",
    "OpenAI Sora": "OpenAI internal watermark",
}

#: Vendor families whose *entire* generative output carries the scheme, matched
#: by prefix so an unrecognised product name still gets the honesty note.
_WATERMARK_FAMILIES = [
    ("Google", "SynthID"),
    ("Meta", "Meta Stable Signature"),
    ("Anthropic", "Claude text watermark (SynthID-Text)"),
]


def watermark_for(source: str | None) -> str | None:
    """The unverifiable watermark scheme a named generator embeds, if any."""
    if not source:
        return None
    if source in UNVERIFIABLE_WATERMARKS:
        return UNVERIFIABLE_WATERMARKS[source]
    for prefix, scheme in _WATERMARK_FAMILIES:
        if source.startswith(prefix):
            return scheme
    return None


WATERMARK_NOTE = {
    "Claude text watermark (SynthID-Text)": (
        "Anthropic watermarks Claude's text output (announced 2026-08-14, "
        "applied to models released from 2026-08-02, older models being "
        "retrofitted). It is a SynthID-Text scheme: the key biases word choice "
        "among equally good options, so there are NO hidden characters to find "
        "and nothing here can detect it. Verification needs Anthropic's "
        "detection API, which was announced but is not yet publicly released. "
        "Anthropic's own stated limits: weak on short samples, sparse on "
        "factual text, negligible in code, and it cannot distinguish "
        "'Claude wrote this' from 'Claude heavily edited this'."),
    "SynthID": (
        "Google embeds SynthID, an invisible pixel-space watermark. It is decodable "
        "ONLY by Google (SynthID Detector portal / Vertex AI). No third-party tool "
        "can verify or refute it. Treat this as 'Google-family origin indicated'."
    ),
    "SynthID-Text": (
        "Google applies SynthID-Text token watermarking to some text output. "
        "Verification requires Google's key; not checkable locally."
    ),
    "Meta Stable Signature": (
        "Meta applies an invisible watermark to AI images. No public detector exists."
    ),
    "OpenAI internal watermark": (
        "OpenAI has stated it watermarks some generated media. No public detector exists; "
        "only the C2PA manifest is third-party verifiable."
    ),
}


# ---------------------------------------------------------------------------
# IPTC / XMP standard provenance vocabulary.
# ---------------------------------------------------------------------------

IPTC_DIGITAL_SOURCE_AI = {
    "trainedalgorithmicmedia": "fully AI-generated (IPTC: trainedAlgorithmicMedia)",
    "compositewithtrainedalgorithmicmedia": "composite containing AI-generated content",
    "algorithmicmedia": "algorithmically generated media",
    "algorithmicallyenhanced": "algorithmically enhanced (AI edit applied)",
    # The rest of the IPTC digital source vocabulary that implies synthesis.
    "digitalart": "digital art (IPTC: digitalArt)",
    "compositesynthetic": "composite including synthetic elements",
    "virtualrecording": "recording of a virtual/synthetic scene",
    "softwareimage": "software-generated image (screenshot or render)",
    "trainedalgorithmicdata": "algorithmically generated data",
}

IPTC_DIGITAL_SOURCE_CAPTURE = {
    "digitalcapture": "camera capture",
    "originalphotograph": "original photograph",
    "capturedaudio": "captured audio",
    "negativefilm": "film scan",
    "positivefilm": "film scan",
    "print": "print scan",
}


# ---------------------------------------------------------------------------
# Native output dimensions. Tier C only — these overlap with each other and
# with hand-made canvases, so they only ever corroborate.
# ---------------------------------------------------------------------------

DIMENSION_FINGERPRINTS: dict[tuple[int, int], list[str]] = {}


def _reg(names: list[str], sizes: list[tuple[int, int]], both_ways: bool = True) -> None:
    for w, h in sizes:
        for dims in ({(w, h), (h, w)} if both_ways else {(w, h)}):
            DIMENSION_FINGERPRINTS.setdefault(dims, [])
            for n in names:
                if n not in DIMENSION_FINGERPRINTS[dims]:
                    DIMENSION_FINGERPRINTS[dims].append(n)


_reg(["OpenAI DALL·E 3"], [(1024, 1024), (1792, 1024)])
_reg(["OpenAI GPT-Image"], [(1024, 1024), (1536, 1024)])
_reg(["Stable Diffusion 1.x"], [(512, 512), (768, 512), (640, 512)])
_reg(["SDXL / FLUX class"], [(1024, 1024), (1152, 896), (1216, 832),
                             (1344, 768), (1536, 640)])
_reg(["Midjourney (upscaled)"], [(1024, 1024), (1456, 816), (1232, 928),
                                 (2048, 2048), (1792, 1024), (2912, 1632),
                                 (2464, 1856)])
_reg(["Ideogram"], [(1024, 1024), (1312, 736), (1152, 864)])
_reg(["Leonardo.Ai"], [(1024, 1024), (1360, 768), (1472, 832)])

#: Sizes so generic (icons, screenshots, thumbnails) that reporting them is noise.
DIMENSION_IGNORE = {(512, 512), (1024, 1024), (256, 256), (128, 128), (64, 64)}


def dimension_candidates(width: int, height: int) -> list[str]:
    if (width, height) in DIMENSION_IGNORE:
        return []
    return DIMENSION_FINGERPRINTS.get((width, height), [])


# ---------------------------------------------------------------------------
# PNG text-chunk keys that carry generation parameters outright (Tier A).
# ---------------------------------------------------------------------------

PNG_PARAM_KEYS: dict[str, tuple[str, str]] = {
    # key (lowercased)      -> (signal suffix, default attribution)
    "parameters":           ("a1111", "Stable Diffusion (A1111-family WebUI)"),
    "prompt":               ("comfy", "ComfyUI"),
    "workflow":             ("comfy_workflow", "ComfyUI"),
    "sd-metadata":          ("invoke_legacy", "InvokeAI"),
    "invokeai_metadata":    ("invoke", "InvokeAI"),
    "invokeai_graph":       ("invoke_graph", "InvokeAI"),
    "dream":                ("invoke_dream", "InvokeAI"),
    "fooocus_scheme":       ("fooocus", "Fooocus"),
    "fooocus_v2_expansion": ("fooocus", "Fooocus"),
    "aigenerated":          ("declared", None),
    "generation_data":      ("generic", None),
    "comment":              ("comment", None),
    "description":          ("description", None),
    "software":             ("software", None),
    "source":               ("source", None),
    "title":                ("title", None),
    "author":               ("author", None),
    "creator":              ("creator", None),
    "usercomment":          ("usercomment", None),
}

#: Substrings inside a generation-parameter blob that confirm the SD stack.
SD_PARAM_MARKERS = [
    "negative prompt:", "steps:", "sampler:", "cfg scale:", "model hash:",
    "denoising strength:", "clip skip:", "seed:", "scheduler:",
]


# ---------------------------------------------------------------------------
# PDF / OOXML producers that are *not* AI but are commonly mistaken for it,
# so we can suppress noise.
# ---------------------------------------------------------------------------

BENIGN_PRODUCERS = re.compile(
    r"\b(ghostscript|pdftex|latex|libreoffice|openoffice|quartz|skia|"
    r"microsoft.{0,20}word|microsoft.{0,20}excel|microsoft.{0,20}powerpoint|"
    r"acrobat|distiller|itext|reportlab|wkhtmltopdf|chromium|cairo|fpdf|tcpdf)\b",
    re.I,
)
