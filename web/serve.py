"""Local web UI for markcleanse.

Deliberately stdlib-only: no FastAPI, no uvicorn, no pip install. It is a
localhost drop zone, and the moment it needs a dependency it stops being
something you can hand to someone and say "just run this".

    python3 web/serve.py [--port 8420] [--open]

Uploads are scanned in memory and never written to disk. The path-scan
endpoint reads the local filesystem, so bind to localhost only — which is
the default and is enforced below.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from markcleanse import __version__                                    # noqa: E402
from markcleanse.exif_tool import available as exiftool_available      # noqa: E402
from markcleanse.result import TIER_MEANING                            # noqa: E402
from markcleanse.sanitize import (CATEGORIES, DEFAULT_CATEGORIES,       # noqa: E402
                             sanitize_bytes)
from markcleanse.scan import (ScanOptions, is_markcleanse_artifact,          # noqa: E402
                         scan_bytes, scan_paths)

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "samples")
MAX_UPLOAD = 128 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = f"markcleanse/{__version__}"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args) -> None:
        if os.environ.get("MARKCLEANSE_VERBOSE"):
            super().log_message(fmt, *args)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # No validators were sent before this, which let browsers keep serving a
        # stale index.html after the tool was updated — a UI that silently lags
        # the code is worse than no UI. Scan results should not sit in a browser
        # cache either.
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, default=str).encode(), "application/json")

    # -- routes -----------------------------------------------------------

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            try:
                with open(os.path.join(STATIC, "index.html"), "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(500, b"index.html missing", "text/plain")
        elif self.path == "/api/samples":
            # The catalogue that drives the Docs page, written by
            # tools/build_samples.py alongside DETECTION.md.
            try:
                with open(os.path.join(SAMPLES, "index.json"), "rb") as fh:
                    self._send(200, fh.read(), "application/json")
            except OSError:
                self._json(200, {"categories": [], "samples": [],
                                 "error": "samples/index.json is missing — run "
                                          "python3 tools/build_samples.py"})

        elif self.path == "/api/info":
            # ui_build is a hash of the page being served: if the header stamp
            # does not change after an update, the browser is showing a cached
            # copy, which is exactly the confusion this is here to end.
            try:
                import hashlib
                with open(os.path.join(STATIC, "index.html"), "rb") as fh:
                    build = hashlib.sha256(fh.read()).hexdigest()[:7]
            except OSError:
                build = "unknown"
            self._json(200, {
                "version": __version__,
                "ui_build": build,
                # Which checkout is answering. Two copies of the project on one
                # machine will happily both bind a port in the launcher's range,
                # and then "the feature isn't there" really means "a different
                # install is serving this tab".
                "root": os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "exiftool": bool(exiftool_available()),
                "tiers": {k.value: v for k, v in TIER_MEANING.items()},
            })
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD:
            self._json(413, {"error": "file too large"})
            return
        body = self.rfile.read(length) if length else b""

        if self.path == "/api/scan":
            name = self.headers.get("X-Filename") or "upload.bin"
            name = os.path.basename(name)
            try:
                report = scan_bytes(name, body, ScanOptions(use_exiftool=False))
            except Exception as exc:
                self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
                return
            self._json(200, report.to_dict())

        elif self.path == "/api/report":
            # The browser already holds the reports it rendered, so it posts
            # them straight back rather than making the server rescan — the
            # report must describe exactly what was on screen.
            from markcleanse.report import render
            try:
                payload = json.loads(body or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "bad JSON"})
                return
            try:
                page = render(payload.get("result") or {},
                              title=payload.get("title") or "Content provenance report",
                              target=payload.get("target") or "")
            except Exception as exc:
                self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
                return
            self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")

        elif self.path in ("/api/scan-text", "/api/clean-text"):
            # Pasted prose. Same engine as a dropped .txt — the text tab must
            # never be a second, more flattering opinion.
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError:
                self._json(400, {"error": "text must be UTF-8"})
                return

            if self.path == "/api/clean-text":
                cats = {c.strip() for c in
                        (self.headers.get("X-Categories") or "hidden,privacy,generator"
                         ).split(",") if c.strip()} & set(CATEGORIES)
                result = sanitize_bytes("pasted.txt", body,
                                        cats or set(DEFAULT_CATEGORIES))
                cleaned = (result.data if result.changed else body).decode(
                    "utf-8", "replace")
                payload = result.to_dict()
                payload["text"] = cleaned
                payload["remaining"] = _text_report(cleaned)
                self._json(200, payload)
                return

            self._json(200, _text_report(text))

        elif self.path == "/api/scan-sample":
            # Deliberately name-only: the UI should not need to know where the
            # project lives, and this cannot be pointed at arbitrary paths.
            try:
                name = json.loads(body or b"{}").get("name", "")
            except json.JSONDecodeError:
                self._json(400, {"error": "bad JSON"})
                return
            name = os.path.basename(str(name))
            target = os.path.join(SAMPLES, name)
            if not name or name == "index.json" or not os.path.isfile(target):
                self._json(404, {"error": f"no such sample: {name}"})
                return
            try:
                with open(target, "rb") as fh:
                    data = fh.read()
                report = scan_bytes(name, data, ScanOptions(use_exiftool=False))
            except Exception as exc:
                self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
                return
            self._json(200, report.to_dict())

        elif self.path == "/api/sanitize":
            # Cleans an uploaded file in memory and hands the result straight
            # back for download. Nothing is written to disk, so the browser
            # cannot be used to modify anything on this machine.
            import base64
            name = os.path.basename(self.headers.get("X-Filename") or "upload.bin")
            wanted = (self.headers.get("X-Categories") or
                      ",".join(DEFAULT_CATEGORIES))
            cats = {c.strip() for c in wanted.split(",") if c.strip()} & set(CATEGORIES)
            try:
                result = sanitize_bytes(name, body, cats or set(DEFAULT_CATEGORIES))
            except Exception as exc:
                self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
                return

            payload = result.to_dict()
            payload["categories"] = sorted(cats)
            if result.changed:
                payload["data"] = base64.b64encode(result.data).decode()

            # Re-scan the bytes that would be handed back — including when
            # nothing was removed. "No markers to remove" and "there is a marker
            # but metadata stripping cannot reach it" are very different
            # answers, and a pixel-embedded payload is the second one.
            final = result.data if result.changed else body
            after = scan_bytes(name, final, ScanOptions(use_exiftool=False))
            payload["remaining"] = [
                {"tier": f.tier.value, "signal": f.signal, "summary": f.summary}
                for f in after.findings if not f.signal.startswith("info.")]
            payload["remaining_verdict"] = after.verdict.value
            self._json(200, payload)

        elif self.path == "/api/sanitize-path":
            # Cleans a file that was scanned from disk. The browser never held
            # these bytes, so a download is not an option — this writes.
            # Default is a sibling copy; overwriting the original is explicit,
            # and is done atomically through a temp file in the same directory
            # so a crash mid-write cannot leave a truncated original.
            try:
                req = json.loads(body or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "bad JSON"})
                return
            target = os.path.abspath(os.path.expanduser(str(req.get("path", "")).strip()))
            replace = bool(req.get("replace"))
            cats = {str(c).strip() for c in (req.get("categories") or [])} & set(CATEGORIES)
            if not os.path.isfile(target):
                self._json(404, {"error": f"not a file: {target}"})
                return
            if is_markcleanse_artifact(os.path.basename(target)):
                self._json(400, {"error": "that is an markcleanse backup — cleaning it "
                                          "would just back up the backup"})
                return
            try:
                with open(target, "rb") as fh:
                    data = fh.read()
                result = sanitize_bytes(os.path.basename(target), data,
                                        cats or set(DEFAULT_CATEGORIES))
            except Exception as exc:
                self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
                return

            payload = result.to_dict()
            payload["categories"] = sorted(cats)
            final = result.data if result.changed else data

            if result.changed:
                try:
                    payload["written"] = _write_clean(target, final, replace)
                except OSError as exc:
                    self._json(500, {"error": f"could not write: {exc}"})
                    return
                payload["replaced"] = replace

            after = scan_bytes(os.path.basename(target), final,
                               ScanOptions(use_exiftool=False))
            payload["remaining"] = [
                {"tier": f.tier.value, "signal": f.signal, "summary": f.summary}
                for f in after.findings if not f.signal.startswith("info.")]
            payload["remaining_verdict"] = after.verdict.value
            self._json(200, payload)

        elif self.path == "/api/scan-path":
            try:
                target = json.loads(body or b"{}").get("path", "")
            except json.JSONDecodeError:
                self._json(400, {"error": "bad JSON"})
                return
            target = os.path.abspath(os.path.expanduser(target.strip()))
            if not os.path.exists(target):
                self._json(404, {"error": f"no such path: {target}"})
                return
            result = scan_paths([target], ScanOptions())
            self._json(200, result.to_dict())

        else:
            self._json(404, {"error": "not found"})


#: What a stylometry score means, stated as measured behaviour rather than as a
#: probability. The operating point is the one benchmarked for this engine:
#: ~28% of AI text is caught at ~0.8% false positives. Turning that into "87%
#: AI" would be inventing precision the measurement does not support, and it is
#: exactly the number that gets students accused of cheating.
SCORE_BANDS = [
    (65, "strong", "Several independent LLM-register habits at once. On the "
                   "benchmark corpus this band is where most machine-written "
                   "text lands — but so does heavily edited human writing."),
    (35, "moderate", "Enough register markers to flag, not enough to conclude. "
                     "House styles and careful technical writers land here."),
    (15, "weak", "A few common constructions. Ordinary careful prose scores "
                 "in this range."),
    (0, "none", "No meaningful stylistic markers."),
]


def _text_report(text: str) -> dict:
    """Scan pasted prose and return everything the text page needs."""
    from markcleanse.detectors.stylometry import MIN_WORDS, analyse, spans

    # The text page IS the stylometry view — it exists to show the score and
    # the spans that produced it — so it opts in where the file scanner, like
    # the CLI, leaves the heuristic off.
    report = scan_bytes("pasted.txt", text.encode("utf-8"),
                        ScanOptions(use_exiftool=False, include_heuristics=True))
    stats = analyse(text)
    score = stats.get("score", 0.0)
    band, band_note = next((b, n) for cut, b, n in SCORE_BANDS if score >= cut)

    return {
        **report.to_dict(),
        "style": {
            "score": score,
            "band": band,
            "band_note": band_note,
            "words": stats.get("words", 0),
            "enough_words": stats.get("words", 0) >= MIN_WORDS,
            "min_words": MIN_WORDS,
            "family": stats.get("family"),
            "hits": stats.get("hits", [])[:12],
            "burstiness": stats.get("burstiness"),
            "em_dash_per_1000": stats.get("em_dash_per_1000"),
            "leakage": stats.get("leakage", []),
            # Measured, not guessed. See tests/benchmark_stylometry.py.
            "measured_tpr": 0.28,
            "measured_fpr": 0.008,
        },
        "spans": spans(text),
    }


def _write_clean(target: str, data: bytes, replace: bool) -> str:
    """Write cleaned bytes for a path-scanned file; return the path written.

    Never clobbers an existing file by accident: a sibling copy picks the next
    free `.clean`, `.clean-2`, ... name, and an in-place replacement goes
    through os.replace so the original is either the old file or the new one,
    never a half-written mix. In-place also keeps a backup — bulk-cleaning a
    folder from a web page needs an undo — named `.markcleanse-backup` so that
    scanning the folder again skips it. A plain `.bak` gets walked like any
    other file, and since it holds the pre-clean bytes the next scan reports
    the very markers that were just removed, forever.
    """
    stem, ext = os.path.splitext(target)
    tmp = f"{stem}.markcleanse-tmp{ext}"
    with open(tmp, "wb") as fh:
        fh.write(data)
    if replace:
        backup = target + ".markcleanse-backup"
        n = 2
        while os.path.exists(backup):
            backup = f"{target}.markcleanse-backup-{n}"
            n += 1
        os.replace(target, backup)
        os.replace(tmp, target)
        return target
    out = f"{stem}.clean{ext}"
    n = 2
    while os.path.exists(out):
        out = f"{stem}.clean-{n}{ext}"
        n += 1
    os.replace(tmp, out)
    return out


def _bind(preferred: int, tries: int = 20):
    """Bind the preferred port, or the next free one.

    Clicking the launcher twice should open a second browser tab, not print a
    stack trace about the address being in use.
    """
    import errno
    for port in range(preferred, preferred + tries):
        try:
            return ThreadingHTTPServer(("127.0.0.1", port), Handler), port
        except OSError as exc:
            if exc.errno not in (errno.EADDRINUSE, errno.EACCES):
                raise
    return None, 0


def main() -> int:
    ap = argparse.ArgumentParser(description="markcleanse local web UI")
    ap.add_argument("--port", type=int, default=8420)
    ap.add_argument("--open", action="store_true", help="open a browser window")
    args = ap.parse_args()

    # Bound to loopback on purpose: /api/scan-path can read any file the user
    # can read, so this must never be reachable off the machine.
    server, port = _bind(args.port)
    if server is None:
        print(f"markcleanse: could not bind a port near {args.port}", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{port}/"
    print(f"markcleanse {__version__} — {url}")
    print(f"  exiftool: {'yes' if exiftool_available() else 'no (built-in parsers only)'}")
    print("  Ctrl-C to stop")
    if args.open:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
