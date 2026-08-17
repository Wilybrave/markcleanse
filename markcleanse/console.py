"""Terminal rendering — the scan table, the ``-v`` detail view, and exports.

Deliberately separate from `report.py`, which builds the standalone HTML
document: one writes for an 80-column terminal, the other for a browser and a
printer. They share only the evidence vocabulary (``CHECKS``, ``_PROSE``,
``_SKIP``), imported below so the two views can never disagree about what a
verification block contains.

The layout rule throughout: evidence is the part worth reading, so the evidence
column is the one that grows on a wide terminal. Everything else is sized to
its content.
"""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import sys
import textwrap
from typing import TYPE_CHECKING, Any, TextIO

from .report import CHECKS, _PROSE, _SKIP
from .result import VERDICT_ORDER, FileReport, Verdict

if TYPE_CHECKING:                                   # avoids an import cycle
    from .scan import ScanResult

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
RED, YELLOW, GREEN, CYAN = "\033[31m", "\033[33m", "\033[32m", "\033[36m"

#: Colour carries the same ranking as `VERDICT_ORDER`: red is a finding you can
#: stand behind, yellow is one you have to qualify, dim is the absence of one.
_VCOLOR = {
    "PROVENANCE-FORGED": BOLD + RED,
    "AI-GENERATED": RED,
    "AI-DECLARED": YELLOW,
    "WATERMARK?": YELLOW,
    "SUSPECT": DIM + YELLOW,
    "SIGNED-CAPTURE": GREEN,
    "NO-EVIDENCE": DIM,
    "UNSUPPORTED": DIM,
    "ERROR": DIM + RED,
}

_TCOLOR = {"A": RED, "B": YELLOW, "U": CYAN, "C": DIM}

#: Order findings the way the report reads: hard evidence first, opinion last.
_TIER_RANK = {"A": 0, "B": 1, "U": 2, "C": 3}

#: Printed instead of a verdict count of zero — "clean" is what people say.
_CLEAN = Verdict.NO_EVIDENCE.value


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _use_color(stream: TextIO | None = None) -> bool:
    """Colour only when a human is looking at it.

    Honours the NO_COLOR convention, and FORCE_COLOR for pipelines that do want
    escapes (CI logs that render them, `less -R`).
    """
    stream = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _paint(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled and color else text


def _rel(path: str, root: str) -> str:
    """Shorten a path against the scan root, never into a `../..` chain."""
    if root:
        try:
            rel = os.path.relpath(path, root)
        except ValueError:                          # different drives, Windows
            return path
        if not rel.startswith(".."):
            return rel
    return path


def _one_line(value: Any) -> str:
    """Collapse a summary to a single line — several of them wrap in source."""
    return " ".join(str(value if value is not None else "").split())


def _ell(text: str, width: int) -> str:
    text = _one_line(text)
    if width <= 1 or len(text) <= width:
        return text
    return text[:width - 1] + "…"


def _fit(values: list[str], low: int, high: int) -> int:
    return max(low, min(high, max((len(v) for v in values), default=low)))


def _bytes(n: int) -> str:
    return f"{n:,} bytes"


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------

def summary_line(result: "ScanResult") -> str:
    """`42 scanned  3 AI-GENERATED  1 SUSPECT  35 clean`"""
    counts = result.counts()
    parts = [f"{result.scanned} scanned"]
    for verdict in VERDICT_ORDER:
        n = counts.get(verdict.value, 0)
        if n:
            parts.append(f"{n} {'clean' if verdict.value == _CLEAN else verdict.value}")
    if result.skipped:
        parts.append(f"{result.skipped} skipped")
    return "  ".join(parts)


def table(result: "ScanResult", root: str = "", show_all: bool = False,
          stream: TextIO | None = None) -> None:
    """Print the one-line-per-file summary table."""
    stream = stream if stream is not None else sys.stdout
    color = _use_color(stream)
    rows = result.reports if show_all else result.flagged()

    if rows:
        term = shutil.get_terminal_size((100, 24)).columns
        width = max(72, min(term, 200))
        names = [_rel(r.path, root) for r in rows]

        w_name = _fit(names, 20, 44)
        w_verdict = _fit([r.verdict.value for r in rows] + ["VERDICT"], 8, 18)
        w_source = _fit([r.source or "—" for r in rows] + ["ATTRIBUTED TO"], 6, 30)
        gaps = 9                      # three 2-space gaps + the 1-char tier column
        floor_ev = 24

        # On a narrow terminal something has to give. Attribution yields first,
        # then the path — a clipped filename is recoverable, a clipped reason
        # for the verdict is not.
        over = w_name + w_verdict + w_source + gaps + floor_ev - width
        if over > 0:
            shed = max(0, min(over, w_source - 12))
            w_source -= shed
            over -= shed
        if over > 0:
            w_name -= max(0, min(over, w_name - 16))

        fixed = w_name + w_verdict + w_source + gaps
        w_ev = max(floor_ev, width - fixed)

        head = (f"{'FILE':<{w_name}}  {'VERDICT':<{w_verdict}}  "
                f"{'ATTRIBUTED TO':<{w_source}}  T  EVIDENCE")
        print(_paint(head, DIM, color), file=stream)
        print(_paint("─" * min(width, fixed + w_ev), DIM, color), file=stream)

        for report, name in zip(rows, names):
            verdict = report.verdict.value
            tier = report.best_tier.value if report.best_tier else "-"
            print(
                f"{_ell(name, w_name):<{w_name}}  "
                f"{_paint(f'{_ell(verdict, w_verdict):<{w_verdict}}', _VCOLOR.get(verdict, ''), color)}  "
                f"{_ell(report.source or '—', w_source):<{w_source}}  "
                f"{_paint(tier, _TCOLOR.get(tier, ''), color)}  "
                f"{_ell(report.basis, w_ev)}".rstrip(),
                file=stream,
            )
        print(file=stream)

    print(summary_line(result), file=stream)

    # The whole point of the tool is that this sentence is true, so it is said
    # exactly when someone is most likely to conclude the opposite.
    if not result.flagged() and result.scanned:
        print(_paint("nothing flagged — which means no markers survived, "
                     "not that a human made these", DIM, color), file=stream)


# ---------------------------------------------------------------------------
# The -v detail view
# ---------------------------------------------------------------------------

def _wrap(text: str, indent: int, width: int) -> list[str]:
    pad = " " * indent
    return textwrap.wrap(_one_line(text), width=max(40, width - indent),
                         initial_indent=pad, subsequent_indent=pad) or [pad.rstrip()]


#: Keys the check block owns. `_evidence_lines` skips them so a C2PA finding
#: does not print `signature: valid` twice in two different shapes.
VERIFICATION_KEYS = ({key for key, _label, _states in CHECKS}
                     | {f"{key}_detail" for key, _label, _states in CHECKS}
                     | {"verification", "chain_subjects", "algorithm",
                        "profile_problems", "expired", "revocation"})


def _is_verification(evidence: dict) -> bool:
    """True for a flat evidence dict that is really a verification result.

    The `integrity.*` findings carry the check fields at the top level rather
    than nested under `verification`, and printing those as loose key/values
    buries the one thing the reader is looking for.
    """
    return "verification" not in evidence and any(
        key in evidence for key, _label, _states in CHECKS)


def _verification_lines(verification: dict, indent: int, width: int,
                        color: bool) -> list[str]:
    """The C2PA check block: `signature: valid`, `binding: mismatched — …`."""
    pad = " " * indent
    states = {key: allowed for key, _label, allowed in CHECKS}
    # (key, plain value, painted value, trailing detail) — the plain copy is
    # kept because ANSI escapes make len() lie about the printed width.
    rows: list[tuple[str, str, str, str]] = []

    signer = (verification.get("chain_subjects") or [None])[0]
    head = []
    if signer:
        head.append(f"{pad}signed by {signer}"
                    + (f" · {verification['algorithm']}"
                       if verification.get("algorithm") else ""))

    for key, _label, _allowed in CHECKS:
        value = verification.get(key)
        if value is None:
            continue
        tint = {"ok": GREEN, "no": RED}.get(states[key].get(str(value)), YELLOW)
        rows.append((key, str(value), _paint(str(value), tint, color),
                     _one_line(verification.get(f"{key}_detail"))))

    if verification.get("expired"):
        rows.append(("validity", "expired", _paint("expired", YELLOW, color), ""))
    for problem in verification.get("profile_problems") or []:
        text = _one_line(problem)
        rows.append(("profile", text, _paint(text, RED, color), ""))

    revocation = verification.get("revocation")
    if isinstance(revocation, dict) and revocation.get("state"):
        state = revocation["state"]
        tint = {"revoked": RED, "good": GREEN}.get(state, YELLOW)
        rows.append(("revocation", state, _paint(state, tint, color),
                     _one_line(revocation.get("detail"))))

    if not rows:
        return head

    keyw = max(len(key) for key, *_rest in rows) + 1
    col = indent + keyw + 1
    out = list(head)
    for key, plain, painted, detail_text in rows:
        first = f"{pad}{key + ':':<{keyw}} {painted}"
        if not detail_text:
            out.append(first)
        elif col + len(plain) + 3 + len(detail_text) <= width:
            out.append(f"{first} — {detail_text}")
        else:
            # The detail is the explanation of the state; hang it under the
            # value rather than letting it run off a terminal.
            out.append(first)
            out.extend(textwrap.wrap(detail_text, width=max(40, width - col),
                                     initial_indent=" " * col,
                                     subsequent_indent=" " * col))
    return out


def _evidence_lines(evidence: dict, indent: int, width: int) -> list[str]:
    """Key/value evidence, minus what the summary and check block already said."""
    pad = " " * indent
    out: list[str] = []
    for key, value in (evidence or {}).items():
        if key in _SKIP or key in VERIFICATION_KEYS:
            continue
        # `assertions_failed: []` is not evidence of anything; an empty
        # container only tells the reader the field exists.
        if value is None or (isinstance(value, (list, dict, str)) and not value):
            continue
        text = _one_line(value)
        if not text:
            continue
        if key in _PROSE:
            # Decoded payloads and caveats are the finding; never clip them.
            out.append(f"{pad}{key}:")
            out.extend(_wrap(text, indent + 2, width))
        else:
            out.append(f"{pad}{key}: {_ell(text, max(20, width - indent - len(key) - 2))}")
    return out


def detail(report: FileReport, root: str = "", stream: TextIO | None = None) -> None:
    """Print every finding for one file, with its evidence."""
    stream = stream if stream is not None else sys.stdout
    color = _use_color(stream)
    width = max(72, min(shutil.get_terminal_size((100, 24)).columns, 110))
    verdict = report.verdict.value

    print(file=stream)
    print(_paint(_rel(report.path, root), BOLD, color), file=stream)
    print(f"  {report.fmt or report.kind} · {_bytes(report.size)} · "
          f"{_paint(verdict, _VCOLOR.get(verdict, ''), color)}", file=stream)

    findings = sorted(report.findings,
                      key=lambda f: _TIER_RANK.get(f.tier.value, 4))
    for finding in findings:
        tier = finding.tier.value
        print(f"  [{_paint(tier, _TCOLOR.get(tier, ''), color)}] "
              f"{_paint(finding.signal, DIM, color)}", file=stream)
        for line in _wrap(finding.summary, 6, width):
            print(line, file=stream)
        evidence = finding.evidence or {}
        verification = evidence.get("verification")
        if not isinstance(verification, dict) and _is_verification(evidence):
            verification = evidence
        if isinstance(verification, dict):
            for line in _verification_lines(verification, 6, width, color):
                print(line, file=stream)
        for line in _evidence_lines(evidence, 6, width):
            print(line, file=stream)

    for err in report.errors:
        print(f"  {_paint('error:', RED, color)} {_one_line(err)}", file=stream)
    if not findings and not report.errors:
        print("  no findings", file=stream)


# ---------------------------------------------------------------------------
# File exports
# ---------------------------------------------------------------------------

def to_json(result: "ScanResult") -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def to_csv(result: "ScanResult") -> str:
    """One row per scanned file. Findings are joined, not exploded — a CSV is
    for triage in a spreadsheet, and one row per file is what sorts usefully."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["path", "verdict", "tier", "attributed_to", "format",
                     "size", "basis", "signals"])
    for report in result.reports:
        writer.writerow([
            report.path,
            report.verdict.value,
            report.best_tier.value if report.best_tier else "",
            report.source or "",
            report.fmt,
            report.size,
            _one_line(report.basis),
            " ".join(f.signal for f in report.findings),
        ])
    return buf.getvalue()


def _md_cell(text: str) -> str:
    return _one_line(text).replace("|", "\\|")


def to_markdown(result: "ScanResult", root: str = "") -> str:
    """A report you can paste into a ticket or an email."""
    flagged = result.flagged()
    lines = ["# Content provenance report", "", summary_line(result), ""]

    if flagged:
        lines += ["| File | Verdict | Attributed to | Tier | Evidence |",
                  "|---|---|---|---|---|"]
        for report in flagged:
            lines.append(
                f"| `{_md_cell(_rel(report.path, root))}` "
                f"| {report.verdict.value} "
                f"| {_md_cell(report.source or '—')} "
                f"| {report.best_tier.value if report.best_tier else '—'} "
                f"| {_md_cell(report.basis)} |")
        lines += ["", "## Findings", ""]
        for report in flagged:
            lines += [f"### {_md_cell(_rel(report.path, root))}", "",
                      f"`{report.fmt or report.kind}` · {_bytes(report.size)} · "
                      f"**{report.verdict.value}**", ""]
            for finding in sorted(report.findings,
                                  key=lambda f: _TIER_RANK.get(f.tier.value, 4)):
                lines.append(f"- **[{finding.tier.value}]** `{finding.signal}` — "
                             f"{_md_cell(finding.summary)}")
            for err in report.errors:
                lines.append(f"- error: {_md_cell(err)}")
            lines.append("")
    else:
        lines += ["Nothing flagged.", ""]

    # Said in every export for the same reason it is said in the terminal.
    lines += ["---", "",
              "Evidence tiers: **A** embedded generation record · "
              "**B** self-declared metadata · **U** watermark indicated but "
              "vendor-verifiable only · **C** heuristic, never proof.", "",
              "A clean result means no markers survived — a screenshot, "
              "re-encode or metadata strip removes all of them. It is never "
              "evidence that a human made the file.", ""]
    return "\n".join(lines)
