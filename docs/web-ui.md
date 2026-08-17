# Web UI

[← README](../README.md)

**Click to start:** double-click `Start markcleanse.sh` and choose *Run in Terminal*.
That terminal window is also the stop button (Ctrl-C).

For a proper menu entry and a Desktop shortcut with an icon:

```bash
bash install-launcher.sh          # adds it to the applications menu
bash install-launcher.sh --remove # undo
```

Or from a terminal:

```bash
python3 web/serve.py --open
```

Clicking the launcher twice opens a second browser tab rather than failing —
the server takes the next free port if 8420 is busy.

Drag-and-drop at `http://127.0.0.1:8420/` — **whole folders work**, dropped
directories are walked recursively. Plus a path box for scanning somewhere on
disk directly.

The C2PA result is rendered as a pass/fail checklist rather than a JSON blob,
which is the point of the UI: signature, binding, assertions, chain, signer
trust, certificate validity and revocation each get their own line, so you can
see *which* check failed at a glance.

```
C2PA verification — signed by Truepic Lens CLI in ChatGPT   ES256 · cryptography
  ✓  Signature       valid
  ✕  Bound to file   mismatched — sha256 over the asset does not match the claim
  ✓  Assertions      matched
  ✓  Cert chain      verified — 1 link(s) verified
  !  Signer trust    no-trust-list
  ✓  Revocation      good — not revoked as of 2026-02-01
```

Verdict counts double as filter chips, there is a free-text filter over
filename / generator / signal, expand-all, and Copy JSON for pasting a result
into a report.

## Removing markers from the UI

Any dropped file with removable markers gets a **Remove markers & download**
button. The file is cleaned in memory and handed straight back as a download —
**nothing is written to disk**, so a web page can never modify anything on this
machine. C2PA removal is a separate opt-in checkbox, as on the CLI.

The result panel lists exactly what was removed, then re-scans the cleaned bytes
and reports what *survived*. That last part is the honest half: cleaning a
document usually leaves `text.stylometry`, and a stealth-pnginfo payload lives
in the pixels, so metadata stripping reports **"Nothing could be removed — but
these remain"** rather than implying success.

**Why a rescan still shows findings.** Four different reasons, and only the
first two are fixable by cleaning again:

* **C2PA manifests** — removable, but only with **also remove C2PA provenance**
  ticked. Left alone by default because destroying a signed record is a
  decision, not a default.
* **Tier C heuristics** — generator-native output dimensions, and prose
  stylometry when `--stylometry` is on. Nothing was embedded, so there is
  nothing to strip. These never go away.
* **PDFs** — document-info strings are now blanked **in place**, byte for byte,
  so xref offsets stay valid and nothing is re-rendered. Metadata living inside
  a compressed object stream cannot be reached that way and says so. (This tool
  will not shell out to ghostscript for you: measured on this machine, a gs
  rewrite turned a 596 KB PDF into a 2 KB stub that still passed a header
  check.)
* **Stealth pixel payloads** — removable, but only by clearing the low bit of
  every sample. That alters the image by 1/256 per channel, so it runs only
  when a payload was actually decoded, and the result is re-checked.

Backups are written as `<name>.markcleanse-backup`, and directory walks skip that
suffix on purpose: a backup holds the pre-clean bytes, so scanning it re-reports
markers that were already removed and cleaning it backs up the backup. That is
an endless clean/rescan loop rather than a finding. Naming a backup explicitly
on the command line still scans it.

**Cleaning a whole folder:** after a path scan, the toolbar shows
**Clean N files** — it walks every visible row with removable markers, one file
at a time, and respects the filter chips, so you can narrow to `AI-GENERATED`
first and clean only those. Ticking **replace originals** keeps a `.bak` next to
each file. The count only includes files the current settings can actually
change: a C2PA-only file is not a target until **also remove C2PA provenance**
is ticked, and a generator name read out of the manifest (a `CBOR:` tag) counts
as provenance, not metadata. Those backups still contain the markers, so delete them once you are
happy — or leave replace off and work from the `.clean` copies instead.

Files scanned **by path** clean differently, because the browser never held
their bytes: there the button writes to disk. By default it writes a sibling
`<name>.clean<ext>` (then `.clean-2`, ... — it never clobbers an earlier copy)
and leaves the original alone. Ticking **replace the original file** overwrites
in place through a temp file in the same directory, so the original is either
the old bytes or the new ones, never a half-written mix.

## Reports

The deliverable. A scan you can hand to someone who does not have this tool:

    markcleanse report ~/inbox -o report.html      # then open it; Ctrl-P saves a PDF
    markcleanse report photo.jpg --open

In the web UI, **Report** in the toolbar builds the same document from exactly
what is on screen — it honours the filter, so narrowing to `AI-GENERATED` and
pressing Report gives you a document about those files only.

Three rules shape it. It is **self-contained**: one HTML file, no network, no
assets, so it still renders years from now. **Evidence comes before opinion** —
tier A and B findings are laid out ahead of tier C heuristics, within each file
as well as across the report, and the most serious verdict sorts to the top.
And **the caveats travel with it**: the limits are printed inside the document,
including what a missing trust list means and the rule that absence of evidence
is not evidence of human authorship. Whoever reads it will not have markcleanse in
front of them.

C2PA files get the full verification checklist in the report — signature,
binding, assertions, chain, trust, revocation — with the failure detail spelled
out in English rather than a status word.

## Light and dark

The palette has always had both themes; the toggle in the masthead makes the
choice explicit. It cycles **system → light → dark** and remembers the setting.

`system` is the default and stays reachable on purpose — a laptop that switches
at sunset should keep doing that unless you decided otherwise. Choosing a theme
overrides the OS in *both* directions, which is why the dark tokens appear twice
in the stylesheet: once under `prefers-color-scheme` guarded by
`:root:not([data-theme="light"])`, and once under `:root[data-theme="dark"]`.
Nothing else changed — same tokens, same design.

## Text tab

Paste prose, press **Analyse text**. It answers two questions that are kept
deliberately apart:

* **Hidden characters** — invisible payloads, zero-width encodings, whitespace
  stego. This is *evidence*: those characters are physically in the text and do
  not arrive by accident. **Clean it** strips them and replaces the box contents
  with the cleaned version, ready to copy.
* **LLM-style score, 0–100** — a dial, the matched features with their weights,
  and the source text with every matched phrase highlighted (hover for the rule).

The score is **not** a probability and the page says so on every render. Nobody
can compute "87% AI" from prose. What is stated instead is the measured
operating point of this engine: it catches roughly **28% of AI-written text at
about 0.8% false positives**. A high score earns a second look; a low score
proves nothing, since a single editing pass removes the signal while the text
stays machine-written. Under 150 words the score is labelled as noise rather
than shown as a reading.

Cleaning never rewrites wording, so the style score barely moves after a clean.
That is the honest outcome: the hidden payload was a fact, the writing style is
not something to be laundered.

## Docs & examples tab

A second view inside the app documents every detection type — and each example
is **runnable in place**. Press *Run* on a sample and it is scanned live, with
the full evidence rendered underneath plus a note saying whether the result
matches what the documentation claims. *Run these* does a whole category;
*Run visible* runs whatever the filters currently show.

Examples filter by media type — **Pictures · Documents · Text · Code · Video** —
combinable with a free-text filter over filename, signal and description, so
“what does this do to source files?” is two clicks.

That makes the documentation self-verifying: if a detector regresses, the Docs
page says so the next time you press Run. The same catalogue drives
[`DETECTION.md`](DETECTION.md) and `samples/index.json`, so the CLI docs and the
in-app docs cannot disagree.

The tab also carries the honest half — the vendor watermarks nobody can read
locally, the pixel-classifier approaches this deliberately avoids, and what is
simply not implemented.

Uploads are scanned in memory and never written to disk. The server binds to
loopback only and refuses to do otherwise — the path-scan endpoint can read any
file you can read, so it must not be reachable off the machine.
