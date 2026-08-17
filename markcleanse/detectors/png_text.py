"""PNG textual-chunk detector.

Local generation stacks are extraordinarily talkative. AUTOMATIC1111 and its
forks write the entire prompt, sampler, seed and model hash into a `parameters`
tEXt chunk. ComfyUI writes the whole node graph as JSON. NovelAI, InvokeAI and
Fooocus all stamp themselves.

When one of these fires you are not guessing — you are reading the generation
record, which is why it is Tier A.
"""

from __future__ import annotations

import json
import re
import struct
import zlib

from ..result import Finding, Tier
from .. import signatures as sig
from .c2pa import iter_png_chunks

DETECTOR = "png_text"

_MODEL_HASH = re.compile(r"model hash:\s*([0-9a-f]{6,64})", re.I)
_MODEL_NAME = re.compile(r"\bmodel:\s*([^,\n]{2,80})", re.I)
_SEED = re.compile(r"\bseed:\s*(\d{1,20})", re.I)
_STEPS = re.compile(r"\bsteps:\s*(\d{1,4})", re.I)
_SAMPLER = re.compile(r"\bsampler:\s*([^,\n]{2,60})", re.I)


def read_text_chunks(data: bytes) -> list[tuple[str, str]]:
    """Return [(keyword, value)] for tEXt / zTXt / iTXt chunks."""
    out: list[tuple[str, str]] = []
    for ctype, payload in iter_png_chunks(data):
        try:
            if ctype == b"tEXt":
                key, _, val = payload.partition(b"\x00")
                out.append((key.decode("latin-1"), val.decode("latin-1")))
            elif ctype == b"zTXt":
                key, _, rest = payload.partition(b"\x00")
                if rest[:1] == b"\x00":
                    val = zlib.decompress(rest[1:])
                    out.append((key.decode("latin-1"), val.decode("utf-8", "replace")))
            elif ctype == b"iTXt":
                key, _, rest = payload.partition(b"\x00")
                if len(rest) < 2:
                    continue
                compressed, method = rest[0], rest[1]
                rest = rest[2:]
                _lang, _, rest = rest.partition(b"\x00")
                _trans, _, val = rest.partition(b"\x00")
                if compressed and method == 0:
                    val = zlib.decompress(val)
                out.append((key.decode("latin-1"), val.decode("utf-8", "replace")))
        except Exception:
            continue
    return out


def dimensions(data: bytes) -> tuple[int, int] | None:
    if data[:8] != b"\x89PNG\r\n\x1a\n" or len(data) < 24:
        return None
    if data[12:16] != b"IHDR":
        return None
    w, h = struct.unpack(">II", data[16:24])
    return w, h


def _looks_like_sd_params(value: str) -> bool:
    low = value.lower()
    return sum(marker in low for marker in sig.SD_PARAM_MARKERS) >= 2


def _summarise_params(value: str) -> dict[str, str]:
    facts: dict[str, str] = {}
    for name, pattern in (("model_hash", _MODEL_HASH), ("model", _MODEL_NAME),
                          ("seed", _SEED), ("steps", _STEPS), ("sampler", _SAMPLER)):
        m = pattern.search(value)
        if m:
            facts[name] = m.group(1).strip()
    prompt = value.split("Negative prompt:")[0].strip()
    if prompt:
        facts["prompt"] = prompt[:600]
    return facts


def _comfy_models(value: str) -> list[str]:
    """Pull checkpoint / LoRA filenames out of a ComfyUI graph."""
    models: list[str] = []
    try:
        graph = json.loads(value)
    except Exception:
        return models

    def walk(node: object, depth: int = 0) -> None:
        if depth > 12 or len(models) >= 12:
            return
        if isinstance(node, dict):
            for val in node.values():
                walk(val, depth + 1)
        elif isinstance(node, list):
            for val in node:
                walk(val, depth + 1)
        elif isinstance(node, str) and re.search(
            r"\.(safetensors|ckpt|pt|gguf|sft)$", node, re.I
        ):
            if node not in models:
                models.append(node)

    walk(graph)
    return models


def detect(data: bytes, fmt: str) -> list[Finding]:
    if fmt != "png":
        return []

    findings: list[Finding] = []
    chunks = read_text_chunks(data)
    if not chunks:
        return findings

    keys = {k.lower() for k, _ in chunks}
    lookup = {k.lower(): v for k, v in chunks}

    for key, value in chunks:
        low = key.lower()
        if low not in sig.PNG_PARAM_KEYS:
            # Unknown key: still worth checking the value for a generator name.
            named = sig.identify(value)
            if named:
                findings.append(Finding(
                    tier=Tier.B, detector=DETECTOR,
                    signal=f"png.text.{low or 'unnamed'}",
                    summary=f"PNG text chunk '{key}' names {named}",
                    source=named,
                    evidence={"key": key, "value": value[:800]},
                ))
            continue

        suffix, default_source = sig.PNG_PARAM_KEYS[low]

        # --- ComfyUI graphs -------------------------------------------
        if suffix.startswith("comfy") and value.lstrip().startswith("{"):
            models = _comfy_models(value)
            findings.append(Finding(
                tier=Tier.A, detector=DETECTOR,
                signal=f"png.{suffix}",
                summary=("PNG carries a ComfyUI generation graph"
                         + (f" (checkpoint: {models[0]})" if models else "")),
                source="ComfyUI",
                evidence={"key": key, "models": models, "graph": value[:2000]},
            ))
            continue

        # --- A1111-family parameter blob ------------------------------
        if _looks_like_sd_params(value):
            facts = _summarise_params(value)
            source = default_source or "Stable Diffusion (A1111-family WebUI)"
            for candidate in (lookup.get("software"), lookup.get("source"), value):
                named = sig.identify(candidate)
                if named:
                    source = named
                    break
            bits = [f"{k}={v}" for k, v in facts.items() if k != "prompt"][:3]
            findings.append(Finding(
                tier=Tier.A, detector=DETECTOR,
                signal=f"png.params.{suffix}",
                summary=("PNG embeds full generation parameters"
                         + (f" ({', '.join(bits)})" if bits else "")),
                source=source,
                evidence={"key": key, **facts, "raw": value[:2000]},
            ))
            continue

        # --- Explicit generator name in a known key -------------------
        named = sig.identify(value) or (sig.identify(default_source) if default_source else None)
        if named:
            tier = Tier.A if low in ("software", "source") and "novelai" in value.lower() else Tier.B
            findings.append(Finding(
                tier=tier, detector=DETECTOR,
                signal=f"png.text.{suffix}",
                summary=f"PNG text chunk '{key}' names {named}",
                source=named,
                evidence={"key": key, "value": value[:800]},
            ))

    # NovelAI writes Software=NovelAI plus a Comment JSON blob with the seed.
    if "novelai" in lookup.get("software", "").lower():
        comment = lookup.get("comment", "")
        findings.append(Finding(
            tier=Tier.A, detector=DETECTOR,
            signal="png.novelai",
            summary="PNG stamped Software=NovelAI with generation comment block",
            source="NovelAI",
            evidence={"source_model": lookup.get("source", ""), "comment": comment[:1000]},
        ))

    if "fooocus_scheme" in keys or "fooocus_v2_expansion" in keys:
        findings.append(Finding(
            tier=Tier.A, detector=DETECTOR,
            signal="png.fooocus",
            summary="PNG carries Fooocus generation metadata",
            source="Fooocus",
            evidence={"keys": sorted(keys)},
        ))

    return findings
