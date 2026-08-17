# Text analysis in depth

[← README](../README.md)

## Whitespace (`whitespace_wm`)

Three carrier channels, all decoded rather than merely flagged:

| Channel | Encoding |
|---|---|
| Inter-word | one space = 0, two spaces = 1, between two letters |
| Inter-sentence | one vs two spaces after `.` `!` `?` |
| Trailing | end-of-line spaces/tabs (`snow`-style, or run length 1 vs 2) |

The discriminator is **entropy**, not presence. Double-spacing after every
period is a typewriter-era habit; uniform data carries no information, scores
~0.0, and is never reported. A mixed pattern carries roughly one bit per gap,
which is what a payload looks like. Two outcomes:

- bits decode to readable text → **Tier A**, with the recovered string printed;
- bits are high-entropy but don't decode → **Tier C**, stated as such.

Only runs on plain-text files. Text extracted from PDF content streams or
reassembled from OOXML/HTML has spacing that *we* invented during extraction —
it produces convincing high-entropy nonsense, so those sources are skipped.

## Prose style (`stylometry`) — opt-in, `--stylometry`

This one does not run unless you ask for it. It is the only detector here that
can be wrong about a *human*, and a report that mixes a guess about someone's
writing into a page of cryptographic evidence is worth less than one that does
not. Everything else in this tool is something the file actually contains.

Assistant leakage (tier B, verbatim chat phrasing) ships in the same module but
is **not** gated — that is text the file demonstrably contains, not an opinion
about its rhythm.

| Dimension | What is measured |
|---|---|
| **Word choice** | ~24 lexical and construction patterns — `delve`, `tapestry`, corporate adjectives, and fixed sequences like *"not just X, but Y"*, *"it's not X — it's Y"*, *"here's the thing"* |
| **Punctuation** | em-dash density, comma / semicolon / colon / exclamation / parenthesis rates, Oxford-comma consistency |
| **Structure** | sentence-length burstiness (CV), sentence-opener repetition, subordinate-clause openers, paragraph-length uniformity |
| **Leakage** | verbatim chat phrasing — **Tier B**, the only text signal above heuristic |

Three rules keep this from crying wolf, each of them a regression test:

1. **Corroboration gate** — punctuation and rhythm may *raise* a score that word
   choice already earned, never create a finding alone. A semicolon habit plus
   even paragraphs is a writing style.
2. **Prose gate** — source code is skipped entirely (type annotations and object
   literals have enormous colon/comma density), and fenced code blocks, HTML
   tags and URLs are stripped from Markdown before scoring.
3. **Correlated features are capped jointly** — sentence uniformity, opener
   repetition and paragraph uniformity all measure rhythmic sameness, so they
   share one ceiling and can't stack. A changelog is not a suspect.

These are hand-written patterns, not a learned language model. They catch known
tics and miss novel ones; a model that changes its phrasing goes undetected
until the pattern is added to `FEATURES`.

**And the ground has shifted underneath it.** Since EU AI Act Article 50 took
effect (2 Aug 2026), Claude and Gemini text carries a SynthID-Text watermark
that only the vendor can read. The credible answer to "was this AI-written" is
becoming *call the vendor's detection API*, not *run a classifier* — which is
one more reason not to build a product on the module below.

**There is also a better local method and this is not it.**
[Binoculars](https://github.com/ahans30/Binoculars) (ICML 2024) scores text by
the ratio of its perplexity under two related models, reporting >90% detection
at a 0.01% false-positive rate, zero-shot. That is a principled measurement
where this module is a list of guesses. It needs two local LLMs and a GPU to be
practical, so it is out of scope here — but if the text side ever needs to
stand up in front of a client, replacing this module with a Binoculars-style
scorer is the upgrade, not adding more regexes.
