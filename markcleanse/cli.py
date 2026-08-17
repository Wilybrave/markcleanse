"""markcleanse command line interface."""

from __future__ import annotations

import argparse
import os
import sys

from . import console as rpt
from .c2pa_verify import TrustStore
from .detectors import ALL_NAMES
from .exif_tool import available as exiftool_available
from .result import Verdict
from .scan import DEFAULT_MAX_BYTES, ScanOptions, scan_paths

EPILOG = """\
evidence tiers
  A  embedded generation record — C2PA manifest, PNG generation parameters,
     IPTC digitalSourceType, decoded hidden-unicode payload.  Treat as proof.
  B  self-declared metadata naming a generator, or verbatim assistant phrasing.
     Almost always true; trivially stripped or forged.
  U  a watermark is indicated but is not verifiable by anyone but the vendor
     (Google SynthID, Meta Stable Signature).  Origin indicated, not confirmed.

  C  heuristic only — output dimensions, unusual whitespace, and prose
     stylometry if you asked for it with --stylometry.  Suggestive.  Never
     report alone as proof.

prose stylometry is opt-in
  --stylometry scores text against a hand-written list of LLM tics.  It is the
  only detector here that can be wrong about a human, so it does not run
  unless you ask.  There is also a better local method than this one, and it
  is named in DETECTION.md.

c2pa verification
  Manifests are checked four ways: the asset hash binding (does this manifest
  belong to THIS file), the assertion hashes, the COSE signature, and the
  certificate chain.  A manifest that fails any check is reported as an
  integrity failure and its claim is demoted to tier C.  A valid chain proves
  who signed, not that they were entitled to — pass --trust to make that a
  decision instead of an assumption.

what this tool cannot do
  Decode Google SynthID, Meta's watermark, or the statistical TEXT watermarks
  now carried by Claude and Gemini output (SynthID-Text, per EU AI Act Art. 50).
  Those bias word choice with a private key — there is nothing local to find,
  and verification needs the vendor's own detection API.  Absence of evidence
  here is never evidence of human authorship — a screenshot or a re-save
  strips everything.

removing what was found
  markcleanse cleanse <paths>   strips hidden payloads, privacy metadata and
                            generator names; --help for categories.  Pixel
                            watermarks (SynthID) cannot be removed by anything.

examples
  markcleanse ~/Downloads
  markcleanse report.pdf --verbose
  markcleanse ~/client-assets --json out.json --md report.md
  markcleanse drafts/ --stylometry
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="markcleanse",
        description="Detect AI provenance markers in images and documents.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="+", help="files and/or directories to scan")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="print full evidence for every flagged file")
    p.add_argument("-a", "--all", action="store_true", dest="show_all",
                   help="list clean files too, not just flagged ones")
    p.add_argument("--json", metavar="FILE",
                   help="write the full report as JSON ('-' for stdout)")
    p.add_argument("--csv", metavar="FILE", help="write a CSV summary")
    p.add_argument("--md", metavar="FILE", help="write a Markdown report")
    p.add_argument("--no-recursive", action="store_true",
                   help="do not descend into subdirectories")
    p.add_argument("--hidden", action="store_true", help="include dotfiles and dotdirs")
    p.add_argument("--follow-symlinks", action="store_true")
    p.add_argument("--stylometry", action="store_true",
                   help="also score prose style for LLM tics (Tier C). Off by "
                        "default: it is a heuristic that can be wrong about a "
                        "human, and mixing guesses into a report of "
                        "cryptographic evidence devalues the evidence")
    # Accepted and ignored: this is now the default, and scripts written
    # against the old behaviour should keep working rather than exit 2.
    p.add_argument("--no-heuristics", action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("--no-exiftool", action="store_true",
                   help="skip the exiftool enrichment pass")
    p.add_argument("--no-verify", action="store_true",
                   help="skip cryptographic verification of C2PA manifests")
    p.add_argument("--trust", metavar="FILE|c2pa",
                   help="trust anchors: a PEM bundle, or a file of SHA-256 "
                        "certificate fingerprints, or the word 'c2pa' to use "
                        "the official C2PA trust list fetched by "
                        "tools/update-trust-list.sh. Without it, a valid chain "
                        "is reported but the signer's identity is unconfirmed")
    p.add_argument("--revocation", choices=["off", "stapled", "online"],
                   default="stapled",
                   help="check whether the signing certificate was revoked. "
                        "'stapled' (default) reads the OCSP response carried "
                        "in the manifest — offline and private. 'online' "
                        "queries the CA, which discloses to them which "
                        "certificate you are examining and when")
    p.add_argument("--only", metavar="NAMES",
                   help=f"run only these detectors ({', '.join(ALL_NAMES)})")
    p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                   help="per-file read cap in bytes (default 64MB)")
    p.add_argument("-j", "--workers", type=int, default=None)
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress")
    p.add_argument("--fail-on", choices=["none", "any", "confirmed"], default="none",
                   help="exit non-zero when matching files are found "
                        "(for CI / pre-delivery gates)")
    return p


#: `sanitize` is kept as an undocumented alias for `cleanse` so anything
#: scripted against the older verb keeps working.
SUBCOMMANDS = {"scan", "cleanse", "sanitize", "report"}


def _report_main(argv: list[str]) -> int:
    """`markcleanse report <paths> [-o out.html]` — a scan you can hand to someone."""
    import argparse

    from .report import render

    ap = argparse.ArgumentParser(prog="markcleanse report",
                                 description="write a standalone HTML report")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-o", "--out", default="markcleanse-report.html",
                    help="output file (default: markcleanse-report.html)")
    ap.add_argument("--title", default="Content provenance report")
    ap.add_argument("--trust", default=None)
    ap.add_argument("--open", action="store_true", help="open it when done")
    args = ap.parse_args(argv)

    opts = ScanOptions()
    if args.trust:
        from .trust import load_trust_store
        opts.trust_store = load_trust_store(args.trust)

    result = scan_paths(args.paths, opts)
    target = args.paths[0] if len(args.paths) == 1 else f"{len(args.paths)} paths"
    html_out = render(result.to_dict(), title=args.title, target=target)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html_out)

    counts = result.counts()
    flagged = len(result.flagged())
    print(f"{args.out}  —  {result.scanned} file(s), {flagged} flagged")
    for verdict, n in sorted(counts.items()):
        print(f"  {n:4}  {verdict}")
    print("  Open it in a browser; Ctrl-P saves it as PDF.")
    if args.open:
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(args.out))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # `markcleanse <path>` stays the default so existing usage keeps working; a
    # leading subcommand word switches mode.
    if argv and argv[0] in SUBCOMMANDS:
        command, argv = argv[0], argv[1:]
    else:
        command = "scan"

    if command in ("cleanse", "sanitize"):
        from .sanitize_cli import main as cleanse_main
        return cleanse_main(argv)

    if command == "report":
        return _report_main(argv)

    args = build_parser().parse_args(argv)

    opts = ScanOptions(
        max_bytes=args.max_bytes,
        recursive=not args.no_recursive,
        follow_symlinks=args.follow_symlinks,
        use_exiftool=not args.no_exiftool,
        include_heuristics=args.stylometry and not args.no_heuristics,
        only=set(args.only.split(",")) if args.only else None,
        include_hidden=args.hidden,
        verify_c2pa=not args.no_verify,
        revocation=args.revocation,
    )
    if args.trust:
        if args.trust == "c2pa":
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            opts.trust_store = TrustStore.official(root)
            if opts.trust_store is None:
                print("markcleanse: official C2PA trust list not present — run "
                      "`bash tools/update-trust-list.sh` first", file=sys.stderr)
                return 2
        else:
            try:
                opts.trust_store = TrustStore.from_file(args.trust)
            except OSError as exc:
                print(f"markcleanse: cannot read trust anchors: {exc}", file=sys.stderr)
                return 2
            if not opts.trust_store:
                print(f"markcleanse: {args.trust} contains no anchors", file=sys.stderr)
    if args.workers:
        opts.workers = args.workers

    if opts.only:
        unknown = opts.only - set(ALL_NAMES)
        if unknown:
            print(f"markcleanse: unknown detector(s): {', '.join(sorted(unknown))}",
                  file=sys.stderr)
            return 2

    if opts.use_exiftool and not exiftool_available() and not args.quiet:
        print("markcleanse: exiftool not found — using built-in parsers only "
              "(HEIC/AVIF/TIFF/RAW coverage reduced)", file=sys.stderr)

    def progress(done: int, total: int) -> None:
        if not args.quiet and sys.stderr.isatty():
            print(f"\r  scanning {done}/{total}…", end="", file=sys.stderr)

    result = scan_paths(args.paths, opts, progress=progress)
    if not args.quiet and sys.stderr.isatty():
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

    root = args.paths[0] if os.path.isdir(args.paths[0]) else os.path.dirname(
        os.path.abspath(args.paths[0]))

    rpt.table(result, root=root, show_all=args.show_all)

    if args.verbose:
        targets = result.reports if args.show_all else result.flagged()
        for r in targets:
            rpt.detail(r, root=root)

    if args.json:
        _write(args.json, rpt.to_json(result))
    if args.csv:
        _write(args.csv, rpt.to_csv(result))
    if args.md:
        _write(args.md, rpt.to_markdown(result, root=root))

    if args.fail_on == "any" and result.flagged():
        return 1
    if args.fail_on == "confirmed" and any(
        r.verdict is Verdict.CONFIRMED_AI for r in result.reports
    ):
        return 1
    return 0


def _write(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"  written: {path}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
