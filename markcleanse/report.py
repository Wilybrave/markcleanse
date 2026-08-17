"""Standalone HTML report for a scan.

The point of this module is handing the result to somebody else. A terminal
table is fine while you are working; it is not something you can attach to an
email, keep on file, or put in front of a client who is disputing what a file
is.

Three rules shape what comes out:

* **Self-contained.** One HTML file, no network, no assets. It opens in any
  browser five years from now, and Ctrl-P produces a clean PDF.
* **Evidence before opinion.** Tier A and B findings — things actually present
  in the bytes — are laid out first and separately from tier C heuristics.
  A report that mixes "this file contains a signed manifest naming DALL·E" with
  "this prose feels machine-written" is worse than useless in an argument.
* **The caveats travel with it.** The limits are printed in the document, not
  left in the tool that produced it. Whoever reads this will not have markcleanse in
  front of them.

Rendering is plain string building on purpose: no template engine, nothing to
install, and the output is auditable by reading this file.
"""

from __future__ import annotations

import datetime
import html
import os
from typing import Any

from . import __version__
from .result import TIER_MEANING

#: Verdicts in the order a reader cares about them.
VERDICT_ORDER = ["PROVENANCE-FORGED", "AI-GENERATED", "AI-DECLARED",
                 "WATERMARK?", "SUSPECT", "SIGNED-CAPTURE", "NO-EVIDENCE",
                 "UNSUPPORTED", "ERROR"]

VERDICT_MEANING = {
    "PROVENANCE-FORGED": "Carries a provenance manifest that failed "
                         "verification — the credential does not match the "
                         "file it is attached to.",
    "AI-GENERATED": "Carries an embedded generation record: a verified "
                    "manifest, generation parameters, or a decoded hidden "
                    "payload.",
    "AI-DECLARED": "Metadata names an AI generator. Almost always true, but "
                   "self-declared and trivially forged or stripped.",
    "WATERMARK?": "Indicates a watermark that only the vendor can verify.",
    "SUSPECT": "Heuristic signals only. Suggestive, never proof.",
    "SIGNED-CAPTURE": "Carries a verified manifest asserting a camera capture.",
    "NO-EVIDENCE": "Nothing found. This is not evidence of human authorship.",
    "UNSUPPORTED": "Format not examined.",
    "ERROR": "Could not be read.",
}

CAVEATS = [
    ("Absence of evidence is not evidence of human authorship",
     "A screenshot, a re-save, or a copy-paste strips every marker in this "
     "report. A file with no findings may still be AI-generated."),
    ("Tier C is not proof",
     "Heuristics — prose style, output dimensions — describe a resemblance, "
     "not an origin. A careful human writer and a house style guide both score "
     "the same way. Never present tier C alone as a finding of AI authorship."),
    ("Some watermarks cannot be checked by anyone but the vendor",
     "Google SynthID, the Claude and Gemini text watermarks, and Meta's "
     "Stable Signature are detectable only with the vendor's key. Where this "
     "report says a watermark is indicated, it means the origin is indicated — "
     "the watermark itself was not verified."),
    ("Verification is not trust",
     "A cryptographically valid manifest proves the file matches what was "
     "signed. It says nothing about whether the signer is honest, unless a "
     "trust list was used — see the scan settings above."),
]

CSS = """
:root{--ink:#12151b;--mute:#5b6572;--line:#dfe4ea;--bg:#fff;--soft:#f6f8fa}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
     font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     -webkit-font-smoothing:antialiased}
.page{max-width:940px;margin:0 auto;padding:44px 34px 90px}
h1{font-size:25px;letter-spacing:-.02em;margin:0 0 4px}
h2{font-size:17px;letter-spacing:-.015em;margin:34px 0 12px;
   padding-bottom:7px;border-bottom:1px solid var(--line)}
h3{font-size:14.5px;margin:0}
.sub{color:var(--mute);font-size:13px;margin:0}
.meta{margin:18px 0 0;border:1px solid var(--line);border-radius:9px;
      background:var(--soft);padding:2px 0}
.meta div{display:flex;gap:14px;padding:7px 14px;font-size:12.5px;
          border-top:1px solid var(--line)}
.meta div:first-child{border-top:none}
.meta b{min-width:150px;color:var(--mute);font-weight:600}
.meta span{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
.tally{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 0}
.tally i{font-style:normal;border:1px solid var(--line);border-radius:999px;
         padding:5px 12px;font-size:12.5px;background:var(--soft)}
.tally i b{font-weight:700}
.file{border:1px solid var(--line);border-radius:10px;margin:14px 0;
      overflow:hidden;break-inside:avoid}
.fhead{display:flex;align-items:center;gap:12px;padding:12px 15px;
       background:var(--soft);border-bottom:1px solid var(--line)}
.fhead .nm{font-weight:650;word-break:break-all}
.fhead .vd{margin-left:auto;font-size:11.5px;font-weight:700;letter-spacing:.04em;
           border:1.5px solid currentColor;border-radius:5px;padding:2px 8px;
           white-space:nowrap}
.v-forged,.v-ai{color:#b3261e}.v-decl{color:#8a5a00}.v-susp{color:#7a6200}
.v-capt{color:#0b5f8a}.v-none{color:#3d6b4f}.v-other{color:#5b6572}
.fpath{padding:9px 15px;font:11.5px ui-monospace,Menlo,Consolas,monospace;
       color:var(--mute);border-bottom:1px solid var(--line);word-break:break-all}
.basis{padding:11px 15px;border-bottom:1px solid var(--line)}
.find{padding:11px 15px;border-bottom:1px solid var(--line)}
.find:last-child{border-bottom:none}
.tier{display:inline-block;min-width:19px;text-align:center;font-weight:700;
      font-size:11px;border-radius:4px;padding:1px 5px;margin-right:8px;
      border:1px solid var(--line);background:#fff}
.t-A{color:#b3261e;border-color:#b3261e}.t-B{color:#8a5a00;border-color:#8a5a00}
.t-U{color:#6b3fa0;border-color:#6b3fa0}.t-C{color:#7a6200;border-color:#7a6200}
.ev{margin:7px 0 0 27px;font-size:12.5px;color:var(--mute)}
.ev div{padding:2px 0;word-break:break-word}
.ev b{color:var(--ink);font-weight:600}
.ev code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px}
.chk{margin:7px 0 0 27px;font-size:12.5px}
.chk div{padding:2px 0}
.chk .ok::before{content:"PASS ";color:#3d6b4f;font-weight:700}
.chk .no::before{content:"FAIL ";color:#b3261e;font-weight:700}
.chk .wa::before{content:"NOTE ";color:#8a5a00;font-weight:700}
.note{border:1px solid var(--line);border-left:3px solid #8a5a00;border-radius:7px;
      padding:11px 14px;margin:11px 0;background:var(--soft);font-size:12.5px}
.note b{display:block;margin-bottom:2px}
.foot{margin-top:34px;padding-top:12px;border-top:1px solid var(--line);
      color:var(--mute);font-size:11.5px}
@media print{
  .page{max-width:none;padding:0 0 20px}
  .file,.note{break-inside:avoid}
  h2{break-after:avoid}
  body{font-size:11.5px}
}
"""

_VCLASS = {"PROVENANCE-FORGED": "v-forged", "AI-GENERATED": "v-ai",
           "AI-DECLARED": "v-decl", "WATERMARK?": "v-other",
           "SUSPECT": "v-susp", "SIGNED-CAPTURE": "v-capt",
           "NO-EVIDENCE": "v-none"}

#: Verification fields worth printing, and what a passing value looks like.
CHECKS = [
    ("signature", "Signature", {"valid": "ok", "invalid": "no"}),
    ("binding", "Bound to this file", {"matched": "ok", "mismatched": "no",
                                       "absent": "wa", "unsupported": "wa"}),
    ("assertions", "Assertions intact", {"matched": "ok", "mismatched": "no"}),
    ("chain", "Certificate chain", {"verified": "ok", "broken": "no",
                                    "incomplete": "wa"}),
    ("trust", "Signer trust", {"trusted": "ok", "untrusted-root": "no",
                               "no-trust-list": "wa"}),
]

#: Evidence keys that are prose rather than data, shown in full.
_PROSE = {"note", "caveat", "decoded", "payload", "prompt", "verify_via",
          "binding_detail", "chain_detail", "signature_detail"}

#: Evidence keys that only repeat what the summary already said.
_SKIP = {"verification", "punctuation_profile", "family_marker_counts",
         "top_features"}


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n} B"


def _evidence(evidence: dict) -> str:
    if not evidence:
        return ""
    rows = []
    for key, value in evidence.items():
        if key in _SKIP:
            continue
        if isinstance(value, (dict, list)):
            value = str(value)
        text = str(value)
        if key not in _PROSE and len(text) > 220:
            text = text[:220] + "…"
        rows.append(f"<div><b>{_esc(key)}</b> {_esc(text)}</div>")
    return f'<div class="ev">{"".join(rows)}</div>' if rows else ""


def _verification(evidence: dict) -> str:
    v = (evidence or {}).get("verification")
    if not isinstance(v, dict):
        return ""
    rows = []
    for key, label, states in CHECKS:
        value = v.get(key)
        if value is None:
            continue
        cls = states.get(value, "wa")
        extra = ""
        if key == "binding" and v.get("binding_detail"):
            extra = f" — {v['binding_detail']}"
        if key == "chain" and v.get("chain_detail"):
            extra = f" — {v['chain_detail']}"
        rows.append(f'<div class="{cls}">{_esc(label)}: '
                    f'<b>{_esc(value)}</b>{_esc(extra)}</div>')
    if v.get("expired"):
        rows.append('<div class="wa">Certificate validity: <b>expired</b></div>')
    for problem in v.get("profile_problems") or []:
        rows.append(f'<div class="no">Certificate profile: {_esc(problem)}</div>')
    rev = v.get("revocation")
    if isinstance(rev, dict) and rev.get("state"):
        cls = {"revoked": "no", "good": "ok"}.get(rev["state"], "wa")
        rows.append(f'<div class="{cls}">Revocation: <b>{_esc(rev["state"])}</b> '
                    f'{_esc(rev.get("detail") or "")}</div>')
    signer = (v.get("chain_subjects") or ["unknown signer"])[0]
    head = (f'<div class="ev"><div><b>signed by</b> {_esc(signer)}'
            f' &nbsp; <b>algorithm</b> {_esc(v.get("algorithm") or "?")}</div></div>')
    return head + f'<div class="chk">{"".join(rows)}</div>'


def _file_section(report: dict) -> str:
    verdict = report.get("verdict", "ERROR")
    findings = report.get("findings") or []
    # Evidence first, opinion second — within a file as well as across the
    # report, so a reader never meets a heuristic before a hard finding.
    order = {"A": 0, "B": 1, "U": 2, "C": 3}
    findings = sorted(findings, key=lambda f: order.get(f.get("tier") or "C", 4))

    blocks = []
    for finding in findings:
        tier = finding.get("tier") or ""
        blocks.append(
            f'<div class="find"><span class="tier t-{_esc(tier)}">{_esc(tier or "-")}</span>'
            f'{_esc(finding.get("summary") or "")}'
            f'<div style="margin:5px 0 0 27px;font:11.5px ui-monospace,Menlo,monospace;'
            f'color:#5b6572">{_esc(finding.get("signal") or "")}</div>'
            f'{_verification(finding.get("evidence") or {})}'
            f'{_evidence(finding.get("evidence") or {})}</div>')

    for err in report.get("errors") or []:
        blocks.append(f'<div class="find">Error: {_esc(err)}</div>')
    if not blocks:
        blocks.append('<div class="find">No findings.</div>')

    digest = report.get("sha256")
    ident = (f'<div class="fpath">{_esc(report.get("path") or "")}<br>'
             f'{_esc(report.get("format") or "?")} · {_bytes(report.get("size") or 0)}'
             + (f'<br>SHA-256 {_esc(digest)}' if digest else '') + '</div>')

    source = report.get("source")
    return (f'<div class="file"><div class="fhead">'
            f'<span class="nm">{_esc(report.get("name") or "")}</span>'
            + (f'<span class="sub">{_esc(source)}</span>' if source else '')
            + f'<span class="vd {_VCLASS.get(verdict, "v-other")}">{_esc(verdict)}</span>'
            f'</div>{ident}'
            + (f'<div class="basis">{_esc(report.get("basis") or "")}</div>'
               if report.get("basis") else '')
            + "".join(blocks) + '</div>')


def render(result: dict, title: str = "Content provenance report",
           target: str = "") -> str:
    """Build the full HTML document from a scan result dictionary."""
    files = result.get("files") or []
    summary = result.get("summary") or {}
    counts = summary.get("verdicts") or {}
    scan = result.get("scan") or {}

    when = scan.get("at") or datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Most serious first: a reader should not have to scroll past clean files.
    rank = {v: i for i, v in enumerate(VERDICT_ORDER)}
    files = sorted(files, key=lambda f: (rank.get(f.get("verdict"), 99),
                                         f.get("name") or ""))

    meta_rows = [
        ("Report generated", when),
        ("Tool", f"markcleanse {scan.get('version') or __version__}"),
        ("Files examined", str(summary.get("scanned", len(files)))),
    ]
    if target:
        meta_rows.insert(0, ("Target", target))
    if scan.get("trust_store"):
        meta_rows.append(("Trust list", scan["trust_store"]))
    else:
        meta_rows.append(("Trust list", "none — signer identity not checked "
                                        "against any authority"))
    if scan.get("revocation"):
        meta_rows.append(("Revocation checking", scan["revocation"]))
    meta_rows.append(("Metadata reader",
                      "exiftool + built-in parsers" if summary.get("exiftool")
                      else "built-in parsers only"))

    meta = "".join(f"<div><b>{_esc(k)}</b><span>{_esc(v)}</span></div>"
                   for k, v in meta_rows)

    tally = "".join(
        f"<i><b>{counts[v]}</b> {_esc(v)}</i>"
        for v in VERDICT_ORDER if counts.get(v))

    flagged = [f for f in files
               if f.get("verdict") not in ("NO-EVIDENCE", "UNSUPPORTED")]
    legend = "".join(
        f'<div class="note"><b>{_esc(v)}</b>{_esc(VERDICT_MEANING[v])}</div>'
        for v in VERDICT_ORDER
        if counts.get(v) and v in VERDICT_MEANING)

    # TIER_MEANING is keyed by the enum, whose str() is "Tier.A".
    tiers = "".join(f"<div><b>{_esc(getattr(k, 'value', k))}</b> {_esc(v)}</div>"
                    for k, v in TIER_MEANING.items())

    caveats = "".join(f'<div class="note"><b>{_esc(h)}</b>{_esc(body)}</div>'
                      for h, body in CAVEATS)

    body_files = "".join(_file_section(f) for f in files) or \
        '<p class="sub">No files were examined.</p>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title><style>{CSS}</style></head><body>
<div class="page">
  <h1>{_esc(title)}</h1>
  <p class="sub">Content provenance and AI-marker examination</p>
  <div class="meta">{meta}</div>
  <div class="tally">{tally}</div>

  <h2>What was found</h2>
  {legend or '<p class="sub">Nothing was flagged.</p>'}
  <p class="sub">{len(flagged)} of {len(files)} file(s) carry at least one
     finding. Every finding is listed in full below, with the evidence it was
     based on.</p>

  <h2>Evidence tiers</h2>
  <div class="ev">{tiers}</div>

  <h2>Files</h2>
  {body_files}

  <h2>Limits of this report</h2>
  {caveats}

  <div class="foot">Produced by markcleanse {_esc(scan.get('version') or __version__)}.
    Findings describe what is present in the files as examined at the time
    above. This document is a record of an examination, not a legal opinion.</div>
</div></body></html>
"""
