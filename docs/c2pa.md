# C2PA verification in depth

[← README](../README.md)

How trust is decided, where the implementation came from, how it is
cross-checked against the reference tool, and why revocation is offline by
default.

## Trust is a separate question

A verified chain proves the manifest was signed by whoever holds that key. It
does **not** prove the key belongs to a legitimate signer — anyone can generate
a self-signed chain claiming to be anyone. So `trust` is reported separately,
and the default is `no-trust-list`, never `trusted`:

```bash
bash tools/update-trust-list.sh       # fetch the official C2PA trust list
markcleanse ~/assets --trust c2pa          # ...and make trust a real decision

markcleanse ~/assets --trust anchors.pem   # or any PEM bundle
markcleanse ~/assets --trust anchors.txt   # or SHA-256 fingerprints, one per line
```

The official list comes from the **C2PA Conformance Program**
([c2pa-org/conformance-public](https://github.com/c2pa-org/conformance-public)).
It is deliberately *not* vendored into this repo: a trust list is a security
decision with an expiry date, and a stale copy committed to git is how a
revoked CA stays trusted. Re-run the fetch periodically.

Worth knowing what it tells you: against the official list, Gemini images come
back `trusted`, while ChatGPT/Sora images come back `untrusted-root` — Truepic's
chain is not on it. c2patool reaches the same two conclusions.

Without `--trust` you still get "signed by *X*, chain verified" — which is
usually what you want for triage. With it, you get a yes/no on whether *X* is
someone you accept. Root fingerprints are printed in the evidence so you can
build the list from files you already trust.

Not implemented: RFC 3161 timestamp tokens are parsed and displayed but their
own signatures are not validated, and the `c2pa.hash.boxes` / `hash.collection`
bindings report as `unsupported` rather than guessing.

## Prior art this borrows from

- **[c2pa-rs](https://github.com/contentauth/c2pa-rs)** — the reference
  implementation. Reading `bmff_to_jumbf_exclusions` and `hash_utils.rs` is how
  the BMFF v2/v3 digest was recovered: each retained top-level box is preceded
  in the digest by its own 8-byte big-endian offset. The obvious reading of the
  spec (hash the surviving bytes) yields a different digest and marks valid
  files as forged.
- **[stable-diffusion-prompt-reader](https://github.com/receyuki/stable-diffusion-prompt-reader)**
  — where the *stealth pnginfo* channel came from. Worth reading for its
  per-tool metadata format coverage.
- **[AI_Provenance_Scanner](https://github.com/abrignoni/AI_Provenance_Scanner)**
  — a DFIR practitioner's exiftool+c2pa script; source of the wider IPTC
  `digitalSourceType` vocabulary (`digitalArt`, `compositeSynthetic`,
  `virtualRecording`, `softwareImage`) now recognised here.
- **[mat2](https://0xacab.org/jvoisin/mat2)** — the mature prior art for
  metadata removal. Its stated limitation is worth repeating: it removes
  metadata, *not* watermarking or steganography.
- **[Binoculars](https://github.com/ahans30/Binoculars)** — the honest state of
  the art for AI *text* detection, and a standing rebuke to the stylometry in
  this repo. See the text section.

## Cross-checked against the reference implementation

`tests/crosscheck_c2patool.py` runs both this tool and **c2patool** (the CAI
reference implementation) over the same files and compares signature, binding
and assertion verdicts field by field:

```bash
python3 tests/crosscheck_c2patool.py /path/to/c2patool ~/assets
```

On real production files: **106/106 agree, 0 wrong.** On BoxHash fixtures both
tools independently report `assertion.boxesHash.match` and `.mismatch`. On the
other tamper fixtures,
c2patool independently reports `assertion.dataHash.mismatch` for the transplant
and edited cases and `claimSignature.mismatch` for the forged one — the same
conclusions, derived separately.

Trust is excluded from the comparison on purpose: c2patool ships the CAI trust
list and this tool ships none, so "untrusted" is a policy difference, not a
disagreement about the file.

Verified against real files: **23 production manifests** from ChatGPT, Sora and
Google Gemini — signed by Truepic Lens and Google C2PA Media Services — all
verify signature, binding, assertions and chain. AVIF/HEIC/MP4 bindings are
tested against ffmpeg-encoded containers, including a transplant case that the
`hash.bmff` check catches and nothing else would.

---

## Revocation is checked offline by default

C2PA signers staple an OCSP response into the manifest (`rVals` → `ocspVals`),
so "was this credential revoked?" is usually answerable **from the file alone**.
The responder's signature over that response is verified against the responder
certificate embedded in it, or the issuing CA — an unsigned "good" is worth
nothing, since anyone assembling a forged manifest can staple whatever they
like.

```bash
markcleanse ~/assets                        # stapled only — offline, private
markcleanse ~/assets --revocation online    # also query the CA when nothing is stapled
markcleanse ~/assets --revocation off
```

`online` is opt-in for a reason that is not performance: **a live OCSP query
tells the certificate authority — and anyone on the network path — exactly
which certificate you are examining and when.** For a tool used to vet material
in a dispute, that is a disclosure about an investigation, so it is never a
silent fallback. A test asserts the default never reaches the network.

A revoked credential blocks an unqualified "verified" but is **not** reported as
tampering: the manifest may well predate the revocation, and without a validated
timestamp that cannot be established either way.
