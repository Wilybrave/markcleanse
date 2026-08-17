# Internals

[← README](../README.md)

Using it as a library, what lives where, how to run the tests, and how to
teach it a new generator.

## Library
```python
from markcleanse import scan_paths, scan_bytes, ScanOptions, Tier

result = scan_paths(["~/assets"], ScanOptions(include_heuristics=False))
for report in result.flagged():
    print(report.path, report.verdict.value, report.source, report.best_tier)

report = scan_bytes("upload.png", raw_bytes)
print(report.to_dict())
```

## Layout
```
markcleanse/
  result.py        tiers, findings, verdict logic
  bmff.py          ISOBMFF box walker (AVIF/HEIC/MP4) with xpath + iloc extents
  boxmap.py        named PNG chunk / JPEG segment map for the BoxHash binding
  cert_profile.py  the C2PA certificate profile (transcribed from c2pa-rs)
  ocsp.py          RFC 6960 revocation — stapled by default, live opt-in
  asn1.py          DER/X.509 reader (names, validity, keys, extensions)
  crypto_min.py    ECDSA/RSA/Ed25519 verify — cryptography, or pure-Python
  c2pa_verify.py   binding, assertion hashes, COSE signature, chain, trust
  signatures.py    generator knowledge base — start here to add a generator
  context.py       per-file context: bytes, format sniffing, extracted text
  cbor_min.py      dependency-free CBOR decoder (for C2PA claims)
  exif_tool.py     optional batched exiftool bridge
  scan.py          walker, threading, watermark-registry annotation
  console.py       terminal table, -v evidence view, JSON / CSV / Markdown
  report.py        standalone HTML report (`markcleanse report`)
  cli.py           argument parsing and subcommand dispatch
  sanitize.py      per-format removal of payloads and metadata
  sanitize_cli.py  `markcleanse cleanse`
  detectors/
    c2pa.py        JUMBF parsing, manifest interpretation, cert CN extraction
    png_text.py    tEXt/zTXt/iTXt, A1111 params, ComfyUI graphs, NovelAI
    image_meta.py  EXIF, XMP, IPTC, dimension fingerprints
    documents.py   PDF, OOXML, ODF, HTML metadata and text extraction
    stealth_png.py    alpha/RGB LSB payloads (NovelAI stealth pnginfo)
    unicode_wm.py  Tags block, variation selectors, zero-width, homoglyphs
    whitespace_wm.py  ASCII whitespace stego — entropy test + payload decode
    stylometry.py  word choice, punctuation profile, structure, family lean
web/
  serve.py         stdlib HTTP server
  static/index.html
samples/           one committed example per detection type (see DETECTION.md)
tools/
  build_samples.py   regenerates samples/ and DETECTION.md from live output
  make_icon.py       launcher icon
  update-trust-list.sh
tests/
  make_fixtures.py synthetic fixtures for every detector
  make_signed_fixtures.py  real signed C2PA fixtures + tampered variants
  make_bmff_fixtures.py    ffmpeg-encoded AVIF/HEIC/MP4 + transplant variant
  crosscheck_c2patool.py   differential test against the CAI reference tool
  test_markcleanse.py   detection + false-positive regression suite
```

## Tests

See [Tests in the README](../README.md#tests).

## Adding a generator

Add a `(pattern, canonical name)` row to `NAME_SIGNATURES` in
`markcleanse/signatures.py`. That one table feeds EXIF, XMP, PDF, DOCX, PNG chunks
and C2PA claims simultaneously. If the generator embeds a watermark nobody else
can verify, add it to `UNVERIFIABLE_WATERMARKS` too so the tool stays honest
about it.
