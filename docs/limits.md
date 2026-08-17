# Known gaps

[← README](../README.md)

Written down because a forensics tool you can't state the limits of is not
usable in an argument.

**Nobody can do these**
- Pixel watermarks (SynthID, Meta) — detection *and* removal both need the vendor.
- Statistical text watermarks — need the provider's secret key.
- A screenshot, re-encode or `exiftool -all=` destroys every metadata signal.
  Clean means "no markers survived", never "a human made this".

**Not implemented here**
- **Video content analysis** — out of scope by design. Container-level C2PA in
  MP4 *is* read and verified; frames are not examined.
- `c2pa.hash.collection` reports `unsupported`. The three hard bindings C2PA 2.4
  requires a validator to recognise — `hash.data`, `hash.bmff.v3` and
  `hash.boxes` — are all implemented and cross-checked against c2patool.
  `hash.boxes` is supported for PNG and JPEG; other containers report
  "no box map is defined for this format" rather than guessing.
- **Redacted assertions** are handled conservatively: an assertion referenced by
  the claim but absent from the store is reported as *absent (possibly
  redacted)*, never as tampering. Only a hash that disagrees counts as
  alteration.
- **Update manifests** (no hard binding by design) are reported as
  "asserts no hard binding", not as forged.
- BMFF hash **v4+** would be reported as *not checked* rather than guessed at.
  v1, v2 and v3 are implemented and validated against a file signed by
  c2patool itself.
- The **certificate profile** check covers the leaf only; intermediates are
  governed by the trust list rather than re-checked.

**Not implemented here (continued)**
- An **expired signing certificate with no validated timestamp** is reported
  and blocks an unqualified "verified", matching c2patool's `Invalid`. So does
  a certificate-profile violation — both are reported as *credential* problems,
  never as tampering, since they say the signer is out of policy rather than
  that the file was altered.
- **CRL is not implemented** — only OCSP. A CA that publishes revocation solely
  by CRL will report as "no OCSP response".
- **RFC 3161 timestamps are displayed, not validated** — so a manifest signed
  after its certificate expired cannot be distinguished from one signed before.
- **Only the active manifest is verified**; ingredient manifests are parsed but
  not checked.
- **Encrypted PDFs** are not decrypted; **PDF and TIFF are not rewritten** by
  `sanitize` (use `exiftool -all=`).
- BMFF metadata boxes that sit *before* media referenced by absolute file
  offsets are detected but not removed — rewriting `iloc`/`stco` tables is easy
  to get subtly wrong, so `sanitize` refuses and says so.
- The HEIC fixture is an AVIF container rebranded to `heic`: the box structure
  and C2PA path are genuinely exercised, but no real HEVC-in-HEIF file was
  available to test against.
- Nested containers are followed **one level deep**.
- RAW formats (CR2/NEF/ARW) only via `exiftool`.
- Files over 64MB are scanned to that cap (`--max-bytes`).

**Inherently partial**
- The generator name list is finite — a new tool won't be *named*, though C2PA
  and PNG-parameter detection are generic and still fire.
- The homoglyph table covers ~30 of several hundred Unicode confusables.
- Stylometry is English-only and trivially defeated by editing.
- No trust list ships by default, so `trust` is `no-trust-list` until you
  supply anchors. A self-signed chain naming itself "Leica" verifies
  *structurally* — the finding says `signer identity UNVERIFIED` for exactly
  this reason.
