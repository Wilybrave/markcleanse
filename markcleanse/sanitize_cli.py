"""`markcleanse cleanse` — remove hidden payloads and provenance metadata."""

from __future__ import annotations

import argparse
import os
import shutil
import sys

from .console import _use_color
from .sanitize import CATEGORIES, DEFAULT_CATEGORIES, sanitize_bytes
from .scan import ScanOptions, iter_files, scan_bytes

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
RED, YELLOW, GREEN = "\033[31m", "\033[33m", "\033[32m"

EPILOG = """\
categories
  hidden      invisible-character payloads and whitespace steganography.
              Removing these is the defensive move: the same channel carries
              watermarks, leak-tracing beacons and prompt-injection payloads.
  privacy     GPS, camera serial numbers, owner/author names, timestamps.
  generator   metadata naming the tool: PNG generation parameters, Software,
              CreatorTool.
  provenance  C2PA manifests.  NOT included by default — unlike the others
              this destroys a signed, verifiable record, including one that
              may attest a file is a genuine camera capture.

default: hidden,privacy,generator

what cannot be removed
  Pixel-space watermarks (Google SynthID, Meta's Stable Signature) are part of
  the image content, not its metadata.  Nothing here touches them, and neither
  does re-encoding, cropping or resizing.  A stripped Gemini image is still
  detectable by Google.  Any tool claiming otherwise is selling you a feeling.

examples
  markcleanse cleanse report.docx --dry-run
  markcleanse cleanse ~/outgoing --out ~/outgoing-clean
  markcleanse cleanse notes.md --in-place
  markcleanse cleanse img.png --categories hidden,privacy,generator,provenance
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="markcleanse cleanse",
        description="Remove hidden payloads, privacy metadata and provenance "
                    "markers from files.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="+", help="files and/or directories")
    p.add_argument("--categories", default=",".join(DEFAULT_CATEGORIES),
                   help=f"comma-separated: {', '.join(CATEGORIES)}")
    p.add_argument("-n", "--dry-run", action="store_true",
                   help="report what would be removed, write nothing")
    p.add_argument("--out", metavar="DIR",
                   help="write cleaned copies into DIR, mirroring the tree")
    p.add_argument("--in-place", action="store_true",
                   help="overwrite the originals (keeps a .markcleanse-backup copy "
                        "unless --no-backup)")
    p.add_argument("--no-backup", action="store_true",
                   help="with --in-place, do not keep a backup copy")
    p.add_argument("--suffix", default=".clean",
                   help="suffix for cleaned copies when neither --out nor "
                        "--in-place is given (default: .clean)")
    p.add_argument("--no-recheck", action="store_true",
                   help="skip re-scanning the output to report what survived")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    color = _use_color(sys.stdout)

    cats = {c.strip() for c in args.categories.split(",") if c.strip()}
    unknown = cats - set(CATEGORIES)
    if unknown:
        print(f"markcleanse: unknown category: {', '.join(sorted(unknown))}. "
              f"Valid: {', '.join(CATEGORIES)}", file=sys.stderr)
        return 2
    if not cats:
        print("markcleanse: no categories selected", file=sys.stderr)
        return 2

    if args.in_place and args.out:
        print("markcleanse: --in-place and --out are mutually exclusive", file=sys.stderr)
        return 2

    scan_opts = ScanOptions(use_exiftool=False)
    files = list(iter_files(args.paths, ScanOptions()))
    if not files:
        print("markcleanse: nothing to sanitize", file=sys.stderr)
        return 1

    changed = skipped = failed = 0
    warned: set[str] = set()

    for path in files:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(f"  ! {path}: {exc}", file=sys.stderr)
            failed += 1
            continue

        result = sanitize_bytes(path, data, cats)
        if not result.changed:
            skipped += 1
            if not args.quiet and (result.unsupported or result.warnings):
                print(f"\n{_rel(path)}")
                if result.unsupported:
                    print(f"  {_c('skipped', DIM, color)}: {result.unsupported}")
                for warning in result.warnings:
                    print(f"  {_c('!', YELLOW, color)} {_wrap(warning)}")
            continue

        changed += 1
        print(f"\n{_c(_rel(path), BOLD, color)}")
        for action in result.effective_actions:
            print(f"  {_c('-', RED, color)} [{action.category}] {action.detail}"
                  + (f"  ({action.bytes_removed:,} bytes)"
                     if action.bytes_removed > 32 else ""))

        # Re-scan the output: the only honest way to report what is left.
        residue: list[str] = []
        if not args.no_recheck:
            after = scan_bytes(os.path.basename(path), result.data, scan_opts)
            residue = [f.summary for f in after.findings
                       if not f.signal.startswith("info.")]

        if args.dry_run:
            print(f"  {_c('dry run', DIM, color)} — nothing written")
        else:
            try:
                target = _write(path, result.data, args)
                print(f"  {_c('→', GREEN, color)} {_rel(target)} "
                      f"({result.bytes_removed:,} bytes removed)")
            except OSError as exc:
                print(f"  ! write failed: {exc}", file=sys.stderr)
                failed += 1
                continue

        if residue:
            print(f"  {_c('still detectable:', YELLOW, color)}")
            for line in residue[:4]:
                print(f"      {_trim(line)}")
        elif not args.no_recheck:
            print(f"  {_c('re-scan: no markers remain', DIM, color)}")

        for warning in result.warnings:
            if warning not in warned:
                warned.add(warning)
                print(f"  {_c('!', YELLOW, color)} {_wrap(warning)}")

    print(f"\n{changed} changed, {skipped} unchanged"
          + (f", {failed} failed" if failed else "")
          + (" (dry run)" if args.dry_run else ""))
    return 1 if failed else 0


def _write(path: str, data: bytes, args) -> str:
    if args.in_place:
        if not args.no_backup:
            # Suffix matters: directory walks skip .markcleanse-backup, so a
            # rescan does not re-report markers out of the backup and
            # send you round the clean/rescan loop again.
            shutil.copy2(path, path + ".markcleanse-backup")
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    if args.out:
        # Mirror relative to the directory the user named, so
        # `--out clean` on `photos/` yields `clean/a.png`, not `clean/photos/a.png`.
        first = os.path.abspath(args.paths[0])
        base = first if os.path.isdir(first) else os.path.dirname(first)
        try:
            rel = os.path.relpath(path, base)
            if rel.startswith(".."):
                rel = os.path.basename(path)
        except ValueError:
            rel = os.path.basename(path)
        target = os.path.join(os.path.abspath(args.out), rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
    else:
        stem, ext = os.path.splitext(path)
        target = f"{stem}{args.suffix}{ext}"

    with open(target, "wb") as fh:
        fh.write(data)
    return target


def _rel(path: str) -> str:
    try:
        rel = os.path.relpath(path)
        return rel if not rel.startswith("../..") else path
    except ValueError:
        return path


def _trim(text: str, width: int = 92) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[:width - 1] + "…"


def _wrap(text: str, width: int = 76) -> str:
    import textwrap
    return "\n      ".join(textwrap.wrap(text, width))


def _c(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text
