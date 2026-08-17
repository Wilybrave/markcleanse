"""Scanner: walk paths, build contexts, run detectors, collect reports."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from . import exif_tool
from .context import FileCtx, sniff
from .detectors import REGISTRY
from .result import FileReport, Finding, Tier, Verdict
from .signatures import WATERMARK_NOTE, watermark_for

DEFAULT_MAX_BYTES = 64 * 1024 * 1024

#: Detectors that read ``ctx.text``, which the `documents` stage fills in.
TEXT_CONSUMERS = {"unicode_wm", "whitespace_wm", "stylometry"}

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv",
             "venv", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
             ".next", ".cache", "site-packages"}

SKIP_EXTS = {".pyc", ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a",
             ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".iso",
             ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac",
             ".mp4", ".mov", ".mkv", ".avi", ".webm", ".wmv", ".m4v",
             ".ttf", ".otf", ".woff", ".woff2", ".eot",
             ".db", ".sqlite", ".lock", ".map"}


@dataclass
class ScanOptions:
    max_bytes: int = DEFAULT_MAX_BYTES
    recursive: bool = True
    follow_symlinks: bool = False
    use_exiftool: bool = True
    #: Tier C prose stylometry. Off by default: it is a list of hand-written
    #: tics, it is the one detector here that can be wrong about a human, and
    #: a scan that mixes guesses into a report of cryptographic evidence is
    #: worth less than one that does not. Ask for it explicitly, or name it in
    #: `only`, and read the caveats in DETECTION.md before you rely on it.
    include_heuristics: bool = False
    only: set[str] | None = None            # detector names
    workers: int = min(8, (os.cpu_count() or 4))
    include_hidden: bool = False
    verify_c2pa: bool = True
    trust_store: object | None = None
    revocation: str = "stapled"        # off | stapled | online
    skip_dirs: set[str] = field(default_factory=lambda: set(SKIP_DIRS))
    skip_exts: set[str] = field(default_factory=lambda: set(SKIP_EXTS))


@dataclass
class ScanResult:
    reports: list[FileReport] = field(default_factory=list)
    skipped: int = 0
    scanned: int = 0
    exiftool_used: bool = False

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.reports:
            out[r.verdict.value] = out.get(r.verdict.value, 0) + 1
        return out

    def flagged(self) -> list[FileReport]:
        interesting = {Verdict.PROVENANCE_INVALID, Verdict.CONFIRMED_AI,
                       Verdict.DECLARED_AI, Verdict.WATERMARK_INDICATED,
                       Verdict.SUSPECT}
        return [r for r in self.reports if r.verdict in interesting]

    def to_dict(self) -> dict:
        return {
            "summary": {
                "scanned": self.scanned,
                "skipped": self.skipped,
                "flagged": len(self.flagged()),
                "verdicts": self.counts(),
                "exiftool": self.exiftool_used,
            },
            "files": [r.to_dict() for r in self.reports],
        }


# ---------------------------------------------------------------------------
# Walking
# ---------------------------------------------------------------------------

def iter_files(paths: Iterable[str], opts: ScanOptions) -> Iterator[str]:
    for raw in paths:
        # An empty argument would expand to the current directory and silently
        # scan the whole tree. Almost always a shell-quoting accident.
        if not raw or not raw.strip():
            continue
        path = os.path.abspath(os.path.expanduser(raw))
        if os.path.isfile(path):
            yield path
            continue
        if not os.path.isdir(path):
            continue
        if not opts.recursive:
            for name in sorted(os.listdir(path)):
                full = os.path.join(path, name)
                if os.path.isfile(full) and _wanted(full, name, opts):
                    yield full
            continue
        for root, dirs, files in os.walk(path, followlinks=opts.follow_symlinks):
            dirs[:] = [
                d for d in sorted(dirs)
                if d not in opts.skip_dirs and (opts.include_hidden or not d.startswith("."))
            ]
            for name in sorted(files):
                full = os.path.join(root, name)
                if _wanted(full, name, opts):
                    yield full


#: Artifacts this tool writes itself. Walking a directory must not pick them
#: up: a backup holds the pre-clean bytes, so scanning it re-reports markers
#: that were already removed, and cleaning it writes a backup of the backup.
#: That is an endless clean/rescan loop, not a finding. Named files given
#: explicitly on the command line are still scanned — this only filters walks.
MARKCLEANSE_ARTIFACTS = (".markcleanse-backup", ".markcleanse-tmp")


def is_markcleanse_artifact(name: str) -> bool:
    return any(part in name for part in MARKCLEANSE_ARTIFACTS)


def _wanted(full: str, name: str, opts: ScanOptions) -> bool:
    if not opts.include_hidden and name.startswith("."):
        return False
    if is_markcleanse_artifact(name):
        return False
    if os.path.splitext(name)[1].lower() in opts.skip_exts:
        return False
    if not opts.follow_symlinks and os.path.islink(full):
        return False
    return True


# ---------------------------------------------------------------------------
# Single file
# ---------------------------------------------------------------------------

def build_ctx(path: str, opts: ScanOptions,
              exif: dict | None = None) -> FileCtx | None:
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(opts.max_bytes)
    except OSError:
        return None
    fmt, kind = sniff(path, data)
    return FileCtx(path=path, data=data, size=size, fmt=fmt, kind=kind,
                   complete=size <= opts.max_bytes, exif=exif or {},
                   verify_c2pa=opts.verify_c2pa, trust_store=opts.trust_store,
                   revocation=opts.revocation)


def scan_ctx(ctx: FileCtx, opts: ScanOptions) -> FileReport:
    report = FileReport(path=ctx.path, size=ctx.size, kind=ctx.kind, fmt=ctx.fmt)
    if not ctx.complete:
        report.errors.append(
            f"only the first {opts.max_bytes // (1024 * 1024)}MB were examined"
        )
    for name, fn, heuristic in REGISTRY:
        # `documents` is not just a detector, it is the text-extraction stage
        # the text-based detectors consume. Excluding it via --only would make
        # them silently return nothing, so run it and drop its findings instead.
        suppress = False
        if opts.only and name not in opts.only:
            if name == "documents" and opts.only & TEXT_CONSUMERS:
                suppress = True
            else:
                continue
        # Naming a heuristic in --only is itself the opt-in; requiring both
        # flags to see the one detector you asked for by name is a trap.
        #
        # Note this drops the heuristic's Tier C *findings*, rather than
        # skipping the detector: `stylometry` also produces the Tier B
        # assistant-leakage signal, which is verbatim chat output and not a
        # guess about anyone's writing. Switching off the opinion must not
        # switch off the evidence sitting next to it.
        drop_heuristic = (heuristic and not opts.include_heuristics
                          and not (opts.only and name in opts.only))
        try:
            for finding in fn(ctx):
                if drop_heuristic and finding.tier is Tier.C:
                    continue
                if not suppress:
                    report.add(finding)
        except Exception as exc:                      # a bad file must not kill a scan
            report.errors.append(f"{name}: {type(exc).__name__}: {exc}")
    _scan_embedded(ctx, report, opts)
    report.findings = _dedupe_findings(report.findings)
    _suppress_weak_when_capture_asserted(report)
    _annotate_unverifiable_watermarks(report)
    return report


def _suppress_weak_when_capture_asserted(report: FileReport) -> None:
    """Drop the dimension heuristic when the file asserts a camera origin.

    A signed `digitalCapture` assertion is far stronger evidence than "this is
    a size some generator also emits". Reporting both makes the tool argue with
    itself inside one report.
    """
    if not any(f.signal.startswith("capture.") for f in report.findings):
        return
    report.findings = [f for f in report.findings
                       if f.signal != "heuristic.native_dimensions"]


#: Containers that are really archives of other files.
ZIP_CONTAINERS = {"docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "zip"}

#: Members worth opening. Office stores images under word/media/, ppt/media/,
#: Pictures/ and so on.
EMBEDDED_EXTS = (".png", ".jpg", ".jpeg", ".jpe", ".webp", ".gif", ".tif",
                 ".tiff", ".avif", ".heic", ".emf", ".wmf", ".svg", ".pdf")

MAX_EMBEDDED = 200
MAX_EMBEDDED_BYTES = 32 * 1024 * 1024


def _scan_embedded(ctx: FileCtx, report: FileReport, opts: ScanOptions) -> None:
    """Scan files carried *inside* a container.

    A DALL·E image with a full C2PA manifest, pasted into a .docx, was
    previously invisible: the document detectors read docProps and the text
    body and never opened word/media/. For a tool whose job is vetting
    deliverables, that was the widest hole in it.
    """
    if ctx.fmt in ZIP_CONTAINERS:
        members = _zip_members(ctx)
    elif ctx.fmt == "pdf":
        members = _pdf_images(ctx)
    else:
        return

    for name, blob in members[:MAX_EMBEDDED]:
        fmt, kind = sniff(name, blob)
        if kind not in ("image", "document"):
            continue
        sub = FileCtx(path=f"{ctx.path}!{name}", data=blob, size=len(blob),
                      fmt=fmt, kind=kind, verify_c2pa=ctx.verify_c2pa,
                      trust_store=ctx.trust_store)
        for det_name, fn, heuristic in REGISTRY:
            if heuristic:
                continue          # stylometry on an embedded image is nonsense
            if opts.only and det_name not in opts.only:
                continue
            try:
                for finding in fn(sub):
                    finding.summary = f"[embedded: {name}] {finding.summary}"
                    finding.evidence = {**finding.evidence, "embedded_in": ctx.path,
                                        "member": name}
                    report.add(finding)
            except Exception as exc:
                report.errors.append(f"{det_name}[{name}]: {type(exc).__name__}: {exc}")


def _zip_members(ctx: FileCtx) -> list[tuple[str, bytes]]:
    import io
    import zipfile
    out: list[tuple[str, bytes]] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(ctx.data))
        infos = zf.infolist()
    except Exception:
        return out
    for info in infos:
        if info.is_dir() or info.file_size > MAX_EMBEDDED_BYTES:
            continue
        if not info.filename.lower().endswith(EMBEDDED_EXTS):
            continue
        try:
            out.append((info.filename, zf.read(info)))
        except Exception:
            continue
        if len(out) >= MAX_EMBEDDED:
            break
    return out


def _pdf_images(ctx: FileCtx) -> list[tuple[str, bytes]]:
    """Pull DCTDecode (JPEG) image streams out of a PDF.

    Only JPEG: those are stored as complete JPEG files and keep their APP
    segments, so an embedded generated image still carries its manifest.
    Flate-encoded images are raw samples with no metadata to find.
    """
    import re as _re
    out: list[tuple[str, bytes]] = []
    for i, m in enumerate(_re.finditer(rb"/DCTDecode", ctx.data)):
        start = ctx.data.find(b"stream", m.end())
        if start < 0:
            continue
        start += 6
        while start < len(ctx.data) and ctx.data[start] in (13, 10):
            start += 1
        end = ctx.data.find(b"endstream", start)
        if end < 0:
            continue
        blob = ctx.data[start:end]
        if blob[:3] == b"\xff\xd8\xff" and len(blob) < MAX_EMBEDDED_BYTES:
            out.append((f"image{i}.jpg", blob))
        if len(out) >= MAX_EMBEDDED:
            break
    return out


def _annotate_unverifiable_watermarks(report: FileReport) -> None:
    """Flag vendors whose watermark exists but is only theirs to verify.

    This runs at report level, not inside a detector: whichever detector
    happened to name the generator — a PNG chunk, an XMP field, a C2PA claim —
    the honesty note is owed to the user just the same.
    """
    for finding in list(report.findings):
        if finding.tier is Tier.C:
            # A stylometric family *lean* is not an identification. Attaching a
            # watermark notice to it would promote a guess to WATERMARK?.
            continue
        scheme = watermark_for(finding.source)
        if not scheme:
            continue
        report.add(Finding(
            tier=Tier.U,
            detector="watermark_registry",
            signal=f"watermark.unverifiable.{scheme.lower().replace(' ', '_')}",
            summary=f"{finding.source} embeds {scheme}, which no third-party tool "
                    f"can verify — origin indicated, watermark unchecked",
            source=finding.source,
            evidence={"scheme": scheme, "note": WATERMARK_NOTE.get(scheme, ""),
                      "verify_via": _VERIFY_ROUTE.get(scheme, "")},
        ))
        return


_VERIFY_ROUTE = {
    "Claude text watermark (SynthID-Text)":
        "Anthropic's watermark detection API — announced 2026-08-14, not yet "
        "publicly released",
    "SynthID": ("Google SynthID Detector portal — waitlisted access for "
                "journalists, researchers and media professionals — or Vertex AI"),
    "SynthID-Text": "Google SynthID Detector portal (Google accounts only)",
    "Meta Stable Signature": "no public detector exists",
    "OpenAI internal watermark": "no public detector; only the C2PA manifest is "
                                 "third-party verifiable",
}


#: Signals that are all "some metadata field named a generator". When two
#: detectors read the same field through different paths (our PNG parser and
#: exiftool, say), one finding is informative and the second is noise.
_NAME_SIGNALS = ("png.text.", "meta.generator_name", "doc.producer")


def _dedupe_findings(findings: list) -> list:
    seen: set[tuple] = set()
    out = []
    for f in findings:
        family = "name" if f.signal.startswith(_NAME_SIGNALS) else f.signal
        key = (family, f.tier, f.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan_file(path: str, opts: ScanOptions | None = None,
              exif: dict | None = None) -> FileReport:
    opts = opts or ScanOptions()
    ctx = build_ctx(path, opts, exif)
    if ctx is None:
        r = FileReport(path=path)
        r.errors.append("unreadable")
        return r
    return scan_ctx(ctx, opts)


def scan_bytes(name: str, data: bytes, opts: ScanOptions | None = None) -> FileReport:
    """Scan an in-memory upload (used by the web UI)."""
    opts = opts or ScanOptions(use_exiftool=False)
    fmt, kind = sniff(name, data)
    ctx = FileCtx(path=name, data=data, size=len(data), fmt=fmt, kind=kind,
                  verify_c2pa=opts.verify_c2pa, trust_store=opts.trust_store,
                  revocation=opts.revocation)
    return scan_ctx(ctx, opts)


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------

def scan_paths(paths: Iterable[str], opts: ScanOptions | None = None,
               progress: Callable[[int, int], None] | None = None) -> ScanResult:
    opts = opts or ScanOptions()
    files = list(iter_files(paths, opts))
    result = ScanResult()

    exif_map: dict[str, dict] = {}
    if opts.use_exiftool and exif_tool.available():
        exif_map = exif_tool.batch_extract(files)
        result.exiftool_used = bool(exif_map)

    total = len(files)
    done = 0

    def work(path: str) -> FileReport | None:
        ctx = build_ctx(path, opts, exif_map.get(path))
        if ctx is None:
            return None
        if ctx.kind == "unsupported" and ctx.fmt in ("binary", "unknown"):
            return None
        return scan_ctx(ctx, opts)

    with ThreadPoolExecutor(max_workers=max(1, opts.workers)) as pool:
        for report in pool.map(work, files):
            done += 1
            if progress and (done % 25 == 0 or done == total):
                progress(done, total)
            if report is None:
                result.skipped += 1
                continue
            result.scanned += 1
            result.reports.append(report)

    order = {v: i for i, v in enumerate(
        [Verdict.PROVENANCE_INVALID,
         Verdict.CONFIRMED_AI, Verdict.DECLARED_AI, Verdict.WATERMARK_INDICATED,
         Verdict.SUSPECT, Verdict.SIGNED_CAPTURE, Verdict.NO_EVIDENCE,
         Verdict.UNSUPPORTED, Verdict.ERROR])}
    result.reports.sort(key=lambda r: (order.get(r.verdict, 99), r.path))
    return result
