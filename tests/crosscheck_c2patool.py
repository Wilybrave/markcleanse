"""Differential test: markcleanse vs c2patool, the CAI reference implementation.

The point is disagreement. Passing my own tests only proves I am consistent with
myself; agreeing with Adobe's implementation on real files is the first
independent evidence that the JUMBF/COSE/CBOR/X.509 stack in here is right.

    python3 tests/crosscheck_c2patool.py <c2patool-binary> <files-or-dirs...>

Compared per file:

    signature   claimSignature.validated / .mismatch
    binding     assertion.dataHash.match / assertion.bmffHash.match (or .mismatch)
    assertions  assertion.hashedURI.match / .mismatch

Trust is deliberately excluded: c2patool ships the CAI trust list, markcleanse ships
none by default, so "untrusted" is an expected difference in policy rather than
a disagreement about the file.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from markcleanse import ScanOptions, scan_file          # noqa: E402
from markcleanse.scan import iter_files                 # noqa: E402

OPTS = ScanOptions(use_exiftool=False)


def c2patool_verdict(binary: str, path: str) -> dict:
    """Run c2patool and reduce its report to the three facts we compare."""
    try:
        proc = subprocess.run([binary, path], capture_output=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"present": None, "error": str(exc)}

    text = proc.stdout.decode("utf-8", "replace").strip()
    if not text:
        err = proc.stderr.decode("utf-8", "replace").strip()
        low = err.lower()
        if "no claim" in low or "jumbfnotfound" in low or "no manifest" in low:
            return {"present": False}
        return {"present": None, "error": err[:160]}

    try:
        report = json.loads(text)
    except json.JSONDecodeError:
        return {"present": None, "error": "unparsable JSON"}

    results = (report.get("validation_results") or {}).get("activeManifest") or {}
    codes = {entry.get("code") for group in ("success", "failure", "informational")
             for entry in results.get(group, [])}
    failures = {entry.get("code") for entry in results.get("failure", [])}

    def state(match: str, mismatch: str) -> str | None:
        # Failure wins. c2patool emits one code per assertion, so a manifest
        # with one good and one altered assertion reports both `match` and
        # `mismatch` — treating that as agreement would hide a real defect.
        if any(c and c.endswith(mismatch) for c in failures):
            return "mismatch"
        if any(c and c.endswith(match) for c in codes - failures):
            return "match"
        return None

    # Legacy reports expose a flat validation_status list instead.
    if not codes:
        for entry in report.get("validation_status") or []:
            codes.add(entry.get("code"))
            failures.add(entry.get("code"))

    return {
        "present": True,
        "state": report.get("validation_state"),
        "signature": ("valid" if "claimSignature.validated" in (codes - failures)
                      else "invalid" if any("claimSignature" in (c or "") for c in failures)
                      else None),
        "binding": state("Hash.match", "Hash.mismatch"),
        "assertions": state("hashedURI.match", "hashedURI.mismatch"),
        "codes": sorted(c for c in codes if c),
        "failures": sorted(c for c in failures if c),
    }


def markcleanse_verdict(path: str) -> dict:
    report = scan_file(path, OPTS)
    for finding in report.findings:
        v = finding.evidence.get("verification")
        if v:
            return {"present": True, "signature": v["signature"],
                    "binding": v["binding"], "assertions": v["assertions"],
                    "chain": v["chain"], "verdict": report.verdict.value}
    return {"present": False, "verdict": report.verdict.value}


#: markcleanse state -> c2patool state, for the fields both report.
EQUIV = {
    "binding": {"matched": "match", "mismatched": "mismatch"},
    "assertions": {"matched": "match", "mismatched": "mismatch"},
}


def compare(mine: dict, theirs: dict) -> tuple[list[str], list[str]]:
    """Return (wrong answers, declined answers).

    The distinction matters: saying "mismatch" when the reference says "match"
    is a defect, whereas saying "I could not check this" is a documented
    capability gap. Collapsing the two would hide real bugs among known limits.
    """
    problems: list[str] = []
    gaps: list[str] = []
    if theirs.get("present") is None:
        return ["c2patool error: " + str(theirs.get("error"))[:80]], gaps

    if bool(mine["present"]) != bool(theirs["present"]):
        problems.append(f"manifest presence: markcleanse={mine['present']} "
                        f"c2patool={theirs['present']}")
        return problems, gaps
    if not mine["present"]:
        return problems, gaps

    if theirs["signature"] and mine["signature"] != theirs["signature"]:
        problems.append(f"signature: markcleanse={mine['signature']} "
                        f"c2patool={theirs['signature']}")

    for field in ("binding", "assertions"):
        want = theirs.get(field)
        if want is None:
            continue                       # c2patool did not report on it
        got = EQUIV[field].get(mine[field])
        if got is None:
            gaps.append(f"{field}: markcleanse did not check it ({mine[field]}), "
                        f"c2patool={want}")
        elif got != want:
            problems.append(f"{field}: markcleanse={mine[field]} c2patool={want}")
    return problems, gaps


#: Fixtures that are deliberately non-conformant: hand-built minimal manifests
#: used to test "a manifest is present but unsigned/unverifiable". The
#: reference rightly refuses to parse them; that is the point of them.
EXPECTED_NONCONFORMANT = {"dalle3_c2pa.jpg", "camera_c2pa.jpg"}


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    binary, targets = sys.argv[1], sys.argv[2:]

    files = [p for p in iter_files(targets, ScanOptions())
             if os.path.splitext(p)[1].lower() in
             (".png", ".jpg", ".jpeg", ".webp", ".avif", ".heic", ".heif",
              ".gif", ".mp4", ".mov", ".tif", ".tiff", ".svg", ".pdf")]

    agreed = disagreed = skipped = gapped = 0
    for path in sorted(files):
        name = os.path.basename(path)[:52]
        if os.path.basename(path) in EXPECTED_NONCONFORMANT:
            skipped += 1
            print(f"  -  {name:54} deliberately non-conformant fixture, skipped")
            continue
        theirs = c2patool_verdict(binary, path)
        mine = markcleanse_verdict(path)
        problems, gaps = compare(mine, theirs)

        if theirs.get("present") is None:
            skipped += 1
            print(f"  ?  {name:54} {problems[0] if problems else ''}")
        elif problems:
            disagreed += 1
            print(f"  ✗  {name:54} " + "; ".join(problems))
        elif gaps:
            gapped += 1
            print(f"  ~  {name:54} " + "; ".join(gaps))
        else:
            agreed += 1
            if mine["present"]:
                print(f"  ✓  {name:54} sig={mine['signature']:8} "
                      f"binding={mine['binding']:10} "
                      f"c2patool={theirs.get('state')}")

    total = agreed + disagreed + gapped
    print(f"\n{agreed}/{total} agree, {disagreed} WRONG, {gapped} not checked "
          f"(known gap)" + (f", {skipped} inconclusive" if skipped else ""))
    return 1 if disagreed else 0


if __name__ == "__main__":
    raise SystemExit(main())
