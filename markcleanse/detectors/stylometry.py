"""Stylometric detector for LLM-written text.

Read this before you trust a number it produces.

Major LLM text **is** watermarked now — and it makes no difference here.
Following EU AI Act Article 50 (in force 2026-08-02), Anthropic watermarks
Claude's text (SynthID-Text, announced 2026-08-14) and Google watermarks
Gemini's. Both bias token choice using a private key: there is no hidden
character to find, and detection requires the vendor's key. Anthropic's
detection API is announced but not yet released.

So the practical position is unchanged: for text, nobody outside the vendor —
this tool included — can give you cryptographic proof, and what follows is
still measurement of *style*, not of a watermark.

What this module does instead is measure *style*: em-dash density, antithesis
constructions, hedging phrases, list-of-three habits, and sentence-length
burstiness. These are genuine statistical signals, and they are also
reproducible by a competent human writer, a heavily-edited draft, or a house
style guide. Everything here is therefore Tier C and phrased as "consistent
with", never "proves".

The one exception is **assistant leakage** — phrases that only appear when a
chat response was pasted verbatim ("As an AI language model", "I hope this
helps!", "knowledge cutoff"). That is Tier B, because humans do not write it
by accident.

Model attribution here is a *lean*, not an identification. Families share
training data and RLHF conventions; the same phrase drifts between them
release to release. When the lean points at Claude, the finding says so and
points at the vendor API — it does not claim to have read a watermark.
"""

from __future__ import annotations

import math
import re
import statistics
from collections import Counter

from ..context import FileCtx
from ..result import Finding, Tier

DETECTOR = "stylometry"

MIN_WORDS = 150

#: Word choice and fixed constructions must carry this much on their own before
#: punctuation or rhythm are allowed to push a document over the threshold.
MIN_LEXICAL_SCORE = 18.0

# ---------------------------------------------------------------------------
# Verbatim assistant leakage — Tier B.
# ---------------------------------------------------------------------------

LEAKAGE = [
    (r"as an ai language model", "assistant self-reference"),
    (r"\bas an ai\b,", "assistant self-reference"),
    (r"i(?:'m| am) an ai\b", "assistant self-reference"),
    (r"i don'?t have (?:personal |real-time )?(?:opinions|feelings|beliefs|access)",
     "assistant disclaimer"),
    (r"my (?:last )?knowledge (?:cutoff|update)", "knowledge-cutoff disclaimer"),
    (r"as of my last (?:knowledge |training )?update", "knowledge-cutoff disclaimer"),
    (r"i hope this helps[!.]", "assistant sign-off"),
    (r"(?:feel free|let me know) if you (?:have any|need|'d like)", "assistant sign-off"),
    (r"i cannot (?:fulfill|comply with|assist with) (?:that|this|your) request",
     "assistant refusal"),
    (r"i'?m sorry,? but i (?:can'?t|cannot)", "assistant refusal"),
    (r"here(?:'s| is) (?:a |an )?(?:comprehensive |detailed |brief )?"
     r"(?:breakdown|overview|summary|guide) (?:of|for|on)", "assistant framing"),
    (r"certainly[!]", "assistant affirmation"),
    (r"\babsolutely[!]", "assistant affirmation"),
    (r"great question[!.]", "assistant affirmation"),
    (r"in this article,? we(?:'ll| will) (?:explore|delve|discuss)", "SEO-assistant framing"),
]

# ---------------------------------------------------------------------------
# Stylistic features — Tier C. (regex, weight, human-readable label)
# ---------------------------------------------------------------------------

FEATURES: list[tuple[str, float, str]] = [
    (r"\bnot (?:just|only|merely|simply) [^.;!?]{2,60}?(?:,? but|—|--|, it'?s)", 9,
     "\"not just X, but Y\" antithesis"),
    (r"\bit'?s not (?:about )?[^.;!?]{2,50}?[—-]{1,2} ?it'?s", 9,
     "\"it's not X — it's Y\" antithesis"),
    (r"\bisn'?t (?:about|just) [^.;!?]{2,50}?[—-]{1,2}", 6, "negation-pivot construction"),
    (r"\b(?:it'?s|that'?s) worth (?:noting|remembering|mentioning)\b", 6, "hedged aside"),
    (r"\bit'?s important to (?:note|remember|understand)\b", 7, "importance hedge"),
    (r"\bthat said\b|\bthat being said\b", 5, "\"that said\" pivot"),
    (r"\bhere'?s the (?:thing|kicker|catch|rub)\b", 6, "\"here's the thing\" framing"),
    (r"\bat the end of the day\b", 4, "closing cliché"),
    (r"\bin (?:conclusion|summary)\b|\bto sum up\b", 6, "essay-style conclusion"),
    (r"\b(?:delve|delving) into\b", 8, "\"delve\" register"),
    (r"\b(?:tapestry|testament to|treasure trove|crucible)\b", 7, "ornamental register"),
    (r"\b(?:navigating|navigate) the (?:complex|ever-|landscape|world|realm)", 6,
     "\"navigate the landscape\" register"),
    (r"\b(?:ever-(?:evolving|changing|growing))\b", 6, "\"ever-evolving\" register"),
    (r"\b(?:robust|seamless|comprehensive|holistic|multifaceted|nuanced)\b", 2,
     "corporate adjective"),
    (r"\b(?:leverage|utilize|facilitate|underscore|foster|showcase)\b", 2,
     "elevated verb substitution"),
    (r"\b(?:crucial|pivotal|paramount|vital) (?:role|to|for|in)\b", 4, "importance intensifier"),
    (r"\bwhether you'?re [^.;!?]{2,60}? or\b", 5, "audience-bracketing sentence"),
    (r"\blet'?s (?:dive|explore|take a look|break (?:this|it) down)\b", 6, "guided-tour framing"),
    (r"^#{1,4} ", 3, "markdown heading"),
    (r"^\s*[-*] \*\*[^*]{2,60}\*\*[:—-]", 5, "bolded bullet lead-in"),
    (r"^\s*\d+\.\s+\*\*", 5, "numbered bold list"),
    (r"\b(?:firstly|secondly|moreover|furthermore|additionally)\b", 3,
     "formal discourse marker"),
    (r"\bthink of it (?:like|as)\b", 4, "explanatory analogy frame"),
    (r"\bthe (?:short|honest|real) answer is\b", 4, "direct-answer frame"),
]

COMPILED = [(re.compile(p, re.I | re.M), w, label) for p, w, label in FEATURES]
COMPILED_LEAK = [(re.compile(p, re.I), label) for p, label in LEAKAGE]

# ---------------------------------------------------------------------------
# Family leanings. Weak by construction — see module docstring.
# ---------------------------------------------------------------------------

FAMILY_MARKERS: dict[str, list[str]] = {
    "OpenAI GPT-family": [
        r"\bdelve\b", r"\btapestry\b", r"\bit'?s important to note\b",
        r"\bcertainly[!]", r"\bin conclusion\b", r"\bi hope this helps\b",
        r"\bas an ai language model\b", r"\bever-evolving\b",
        r"\blet'?s dive (?:in|into)\b", r"\btestament to\b",
        r"^\s*[-*] \*\*[^*]+\*\*: ", r"\bunderscore(?:s|d)?\b",
    ],
    "Anthropic Claude-family": [
        r"\bhere'?s the thing\b", r"\bto be clear\b", r"\bworth noting\b",
        r"\bthat said\b", r"\bi should note\b", r"\bthe honest answer\b",
        r"\bthe short answer is\b", r"\ba few things\b",
        r"\bwhich is (?:kind of |kinda )?the point\b", r"\bfull stop\b",
        r"\bnot .{2,40}[—]\s?(?:it'?s|they'?re)\b", r"\bactually,\s",
        r"\bstraight with you\b", r"\bwhat this (?:means|buys you)\b",
    ],
    "Google Gemini-family": [
        r"\babsolutely[!]", r"\bhere'?s a (?:comprehensive )?breakdown\b",
        r"\bin short,", r"\bkey takeaway", r"\bat a glance\b",
        r"^\s*\*\*[^*]{2,40}:\*\*", r"\bgreat question[!]",
        r"\bthink of it like\b", r"\bthis is where .{2,40} comes in\b",
    ],
    "Meta Llama-family": [
        r"\bi'?d be happy to help\b", r"\bhere are some (?:key )?(?:points|takeaways)\b",
        r"\bnote that\b.*\bhowever\b",
    ],
}

COMPILED_FAMILY = {
    fam: [re.compile(p, re.I | re.M) for p in pats]
    for fam, pats in FAMILY_MARKERS.items()
}

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'“(])")
_WORD = re.compile(r"[A-Za-z][A-Za-z'’-]*")

# ---------------------------------------------------------------------------
# Prose gating.
#
# Every measure in this module assumes natural-language prose. Source code has
# enormous colon, comma and parenthesis density (type annotations, object
# literals, argument lists) and near-uniform line lengths, so scoring it
# produces a confident nonsense answer on every file in a repository.
# ---------------------------------------------------------------------------

CODE_EXTS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".rs",
    ".java", ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".php", ".swift", ".kt",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".css", ".scss", ".sass", ".less",
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".sql",
    ".lua", ".pl", ".pm", ".r", ".vue", ".svelte", ".scala", ".clj", ".ex",
    ".exs", ".erl", ".hs", ".ml", ".dart", ".gradle", ".tf", ".proto",
    ".geojson", ".ipynb", ".patch", ".diff", ".lock", ".svg",
}

_CODE_LINE = re.compile(
    r"^\s*(?:import\s|from\s+\S+\s+import|export\s|const\s|let\s|var\s|"
    r"function\s|def\s|class\s|public\s|private\s|package\s|use\s|fn\s|"
    r"#include|#!|//|/\*|\*/|@\w+|\}|\{|</|\.\w+\s*[:{]|\$\w+\s*=)"
    r"|[;{},]\s*$|=>|::|\)\s*\{\s*$"
)

#: Fenced and indented code blocks inside otherwise-prose Markdown.
_FENCE = re.compile(r"```.*?```|~~~.*?~~~", re.S)
_INLINE_CODE = re.compile(r"`[^`\n]{1,200}`")
_HTML_TAG = re.compile(r"<[^>\n]{1,300}>")
_URL = re.compile(r"https?://\S+|\b[\w.-]+@[\w.-]+\.\w+\b")


def strip_non_prose(text: str) -> str:
    """Remove code blocks, tags and URLs so the prose can be judged as prose."""
    text = _FENCE.sub(" ", text)
    text = _INLINE_CODE.sub(" ", text)
    text = _HTML_TAG.sub(" ", text)
    text = _URL.sub(" ", text)
    return text


def looks_like_code(text: str, ext: str) -> bool:
    if ext in CODE_EXTS:
        return True
    lines = [ln for ln in text.splitlines()[:600] if ln.strip()]
    if len(lines) < 8:
        return False
    codey = sum(1 for ln in lines if _CODE_LINE.search(ln))
    return codey / len(lines) > 0.20

# ---------------------------------------------------------------------------
# Punctuation and structure profile.
#
# Each entry is (key, threshold, weight, label). Rates are per 1000 words.
# Thresholds sit deliberately above ordinary English prose: the point is to
# corroborate a lexical signal, not to convict a writer who likes semicolons.
# Anyone can defeat any single one of these by find-and-replacing em dashes,
# which is exactly why no one of them is worth much alone.
# ---------------------------------------------------------------------------

PUNCT_RULES: list[tuple[str, float, float, str]] = [
    ("comma_per_1000",      88.0, 4, "high comma density"),
    ("semicolon_per_1000",   3.5, 5, "semicolon density above ordinary prose"),
    ("colon_per_1000",       9.0, 4, "high colon density"),
    ("exclamation_per_1000", 6.0, 3, "exclamation density"),
    ("paren_per_1000",      14.0, 3, "parenthetical density"),
]

#: Openers that front a subordinate clause. Models lean on them heavily to
#: vary rhythm; human prose starts far more sentences with a plain subject.
_SUBORDINATE_OPENER = re.compile(
    r"^(While|Whether|Although|Though|Despite|By|Through|Given|Since|As|"
    r"When|If|Rather|Instead|Beyond|Unlike|With|Without)\b", re.I)

_ELLIPSIS = re.compile(r"…|\.\.\.")
#: A serial (Oxford) comma opportunity: "a, b, and c" vs "a, b and c".
_LIST_OXFORD = re.compile(r",\s+(?:and|or)\s+\w")
_LIST_PLAIN = re.compile(r"\w\s+(?:and|or)\s+\w+\s*[.,;)]")


#: Markdown scaffolding: headings, bullets and numbered items. Their colons and
#: commas are structural ("**Latency:** 40ms", "a, b, c" in a table row), not
#: authorial, and counting them makes every well-formatted document look guilty.
_MD_STRUCTURAL = re.compile(r"^\s*(?:#{1,6}\s|[-*+]\s|\d+[.)]\s|>\s|\||\s*\w+\s*\|)")


def prose_lines(text: str) -> str:
    """The running-prose portion of a document, with list scaffolding removed."""
    kept = [ln for ln in text.splitlines() if not _MD_STRUCTURAL.match(ln)]
    body = "\n".join(kept)
    # If a document is nearly all list, there is no prose to rate — fall back
    # rather than divide by a handful of stray words.
    return body if len(body.split()) >= 60 else text


def punctuation_profile(text: str, n_words: int) -> dict:
    """Rates and consistency measures that survive an em-dash find-and-replace."""
    body = prose_lines(text)
    body_words = max(len(_WORD.findall(body)), 1)
    per_k = lambda n: round(n / body_words * 1000, 2)        # noqa: E731

    sentences = _sentences(text)
    openers = [s.split()[0].strip("\"'“‘(").capitalize()
               for s in sentences if s.split()]
    opener_counts = Counter(openers)
    top3 = sum(n for _o, n in opener_counts.most_common(3))

    paragraphs = [p for p in re.split(r"\n\s*\n", text) if len(p.split()) >= 12]
    para_lengths = [len(p.split()) for p in paragraphs]

    oxford = len(_LIST_OXFORD.findall(body))
    plain = len(_LIST_PLAIN.findall(body))

    profile = {
        "comma_per_1000": per_k(body.count(",")),
        "semicolon_per_1000": per_k(body.count(";")),
        "colon_per_1000": per_k(body.count(":")),
        "exclamation_per_1000": per_k(body.count("!")),
        "question_per_1000": per_k(body.count("?")),
        "ellipsis_per_1000": per_k(len(_ELLIPSIS.findall(body))),
        "paren_per_1000": per_k(body.count("(")),
        "prose_words": body_words,
        "sentences": len(sentences),
        "distinct_openers": len(opener_counts),
        "top3_opener_share": round(top3 / len(sentences), 3) if sentences else None,
        "subordinate_opener_share": round(
            sum(1 for s in sentences if _SUBORDINATE_OPENER.match(s)) / len(sentences), 3
        ) if sentences else None,
        "oxford_comma_uses": oxford,
        "oxford_comma_share": round(oxford / (oxford + plain), 3) if (oxford + plain) else None,
        "paragraphs": len(para_lengths),
        "paragraph_length_cv": None,
    }
    if len(para_lengths) >= 4:
        mean = statistics.fmean(para_lengths)
        if mean > 0:
            profile["paragraph_length_cv"] = round(
                statistics.pstdev(para_lengths) / mean, 3)
    return profile


#: Joint ceiling for the correlated rhythm features. Uniform prose is a real
#: signal but a weak one — on its own it must never reach the reporting
#: threshold, or every changelog and product list becomes a SUSPECT.
UNIFORMITY_CAP = 22.0


def score_punctuation(profile: dict) -> tuple[list[tuple[str, int, float]],
                                              list[tuple[str, int, float]]]:
    """Score the profile. Returns (punctuation hits, uniformity hits).

    They are returned separately because the caller caps them separately: the
    punctuation rates are largely independent of each other, while the
    uniformity measures are three views of the same property.
    """
    hits: list[tuple[str, int, float]] = []
    uniformity: list[tuple[str, int, float]] = []

    for key, threshold, weight, label in PUNCT_RULES:
        value = profile.get(key)
        if value is None or value < threshold:
            continue
        # Scale with the overshoot, but cap it — a list-heavy document should
        # not out-score an actual generation record.
        bump = min(weight * 2.0, weight * (value / threshold))
        hits.append((f"{label} ({value:.0f}/1000 words)", int(value), round(bump, 1)))

    share = profile.get("top3_opener_share")
    if share is not None and profile["sentences"] >= 10 and share > 0.40:
        uniformity.append((f"repetitive sentence openers (top 3 start {share:.0%} "
                           f"of sentences)", profile["sentences"],
                           round((share - 0.40) * 40, 1)))

    sub = profile.get("subordinate_opener_share")
    if sub is not None and profile["sentences"] >= 10 and sub > 0.30:
        hits.append((f"subordinate-clause openers on {sub:.0%} of sentences",
                     profile["sentences"], round((sub - 0.30) * 35, 1)))

    oxford = profile.get("oxford_comma_share")
    if oxford is not None and profile["oxford_comma_uses"] >= 5 and oxford >= 0.95:
        hits.append((f"perfectly consistent Oxford comma across "
                     f"{profile['oxford_comma_uses']} lists",
                     profile["oxford_comma_uses"], 5.0))

    cv = profile.get("paragraph_length_cv")
    if cv is not None and profile["paragraphs"] >= 5 and cv < 0.35:
        uniformity.append((f"uniform paragraph lengths (CV {cv:.2f} over "
                           f"{profile['paragraphs']} paragraphs)",
                           profile["paragraphs"], round((0.35 - cv) * 45, 1)))

    return hits, uniformity


# ---------------------------------------------------------------------------

def _sentences(text: str) -> list[str]:
    flat = re.sub(r"\s+", " ", text)
    return [s for s in _SENT_SPLIT.split(flat) if len(s.split()) >= 3]


def burstiness(text: str) -> tuple[float, int]:
    """Coefficient of variation of sentence length. Humans vary; models don't."""
    lengths = [len(s.split()) for s in _sentences(text)]
    if len(lengths) < 8:
        return -1.0, len(lengths)
    mean = statistics.fmean(lengths)
    if mean <= 0:
        return -1.0, len(lengths)
    return statistics.pstdev(lengths) / mean, len(lengths)


def em_dash_rate(text: str, words: int) -> float:
    return len(re.findall(r"[—–]", text)) / words * 1000


def analyse(text: str) -> dict:
    words = _WORD.findall(text)
    n_words = len(words)
    result: dict = {
        "words": n_words,
        "score": 0.0,
        "hits": [],
        "leakage": [],
        "family": None,
        "family_scores": {},
    }
    if n_words == 0:
        return result

    score = 0.0
    # Lexical = word choice and fixed constructions. Tracked separately because
    # punctuation and rhythm may only *corroborate* it, never manufacture a
    # finding on their own — see the gate in detect().
    lexical_score = 0.0
    lexical_count = 0
    hits: list[tuple[str, int, float]] = []
    for pattern, weight, label in COMPILED:
        count = len(pattern.findall(text))
        if not count:
            continue
        # Saturating contribution: repetition of one tic isn't proportionally
        # more damning than the first instance.
        contribution = weight * (1 + math.log(count, 3)) if count > 1 else weight
        contribution *= min(1.0, 900 / max(n_words, 300))
        score += contribution
        lexical_score += contribution
        lexical_count += 1
        hits.append((label, count, round(contribution, 1)))

    em = em_dash_rate(text, n_words)
    if em >= 2.0:
        bump = min(18.0, (em - 1.0) * 5)
        score += bump
        lexical_score += bump
        lexical_count += 1
        hits.append((f"em-dash density {em:.1f}/1000 words", int(em), round(bump, 1)))

    # Sentence-length uniformity, opener repetition and paragraph uniformity all
    # measure the same underlying thing: rhythmic sameness. They are collected
    # here and capped jointly, so a templated-but-human document (a changelog, a
    # product list, a set of log lines) cannot stack three correlated features
    # into a high score.
    uniformity: list[tuple[str, int, float]] = []

    cv, n_sent = burstiness(text)
    if cv >= 0 and cv < 0.45:
        uniformity.append(
            (f"low sentence-length variation (CV {cv:.2f} over {n_sent} sentences)",
             n_sent, round((0.45 - cv) * 55, 1)))
    result["burstiness"] = round(cv, 3) if cv >= 0 else None

    # Curly punctuation alongside em dashes: chat UIs emit it, keyboards don't.
    if re.search(r"[“”‘’]", text) and em >= 1.5:
        score += 4
        lexical_score += 4
        hits.append(("typographic quotes plus em dashes", 1, 4.0))

    # Punctuation and structure. Scored separately and capped, so that stripping
    # em dashes — the one tell everybody knows about — does not clear a document.
    profile = punctuation_profile(text, n_words)
    punct_hits, uniformity_hits = score_punctuation(profile)
    uniformity.extend(uniformity_hits)

    punct_total = min(sum(h[2] for h in punct_hits), 30.0)
    uniformity_total = min(sum(h[2] for h in uniformity), UNIFORMITY_CAP)
    score += punct_total + uniformity_total

    hits.extend(punct_hits)
    hits.extend(uniformity)
    result["punctuation"] = profile
    result["punctuation_score"] = round(punct_total, 1)
    result["uniformity_score"] = round(uniformity_total, 1)

    for pattern, label in COMPILED_LEAK:
        m = pattern.search(text)
        if m:
            result["leakage"].append((label, m.group(0)[:80]))

    fam_scores: dict[str, int] = {}
    for family, patterns in COMPILED_FAMILY.items():
        distinct = sum(1 for p in patterns if p.search(text))
        if distinct:
            fam_scores[family] = distinct
    result["family_scores"] = fam_scores
    if fam_scores:
        ranked = sorted(fam_scores.items(), key=lambda kv: kv[1], reverse=True)
        top, top_n = ranked[0]
        runner_n = ranked[1][1] if len(ranked) > 1 else 0
        if top_n >= 3 and top_n > runner_n:
            result["family"] = top

    hits.sort(key=lambda h: h[2], reverse=True)
    result["score"] = round(min(score, 100.0), 1)
    result["lexical_score"] = round(lexical_score, 1)
    result["lexical_features"] = lexical_count
    result["hits"] = hits[:10]
    result["em_dash_per_1000"] = round(em, 2)
    return result


def _vendor_watermark_note(family: str | None) -> str:
    """What could settle the question that this module cannot.

    Reported as context on the finding rather than as its own tier-U result: a
    stylometric lean is a guess, and pairing a guess with a watermark notice
    would read as though a watermark had been detected.
    """
    if not family:
        return ""
    if family.startswith("Anthropic"):
        return ("If this really is recent Claude output it carries a "
                "SynthID-Text watermark, which only Anthropic's detection API "
                "can read (announced 2026-08-14, not yet released). Nothing "
                "local can confirm or refute it.")
    if family.startswith("Google"):
        return ("If this really is Gemini output it carries a SynthID-Text "
                "watermark, readable only via Google's SynthID Detector.")
    return ""


def detect(ctx: FileCtx) -> list[Finding]:
    text = ctx.text
    if not text:
        return []

    if looks_like_code(text, ctx.ext):
        ctx.notes.append("stylometry-skipped:code")
        return []

    text = strip_non_prose(text)
    findings: list[Finding] = []
    stats = analyse(text)

    if stats["leakage"]:
        labels = ", ".join(sorted({lbl for lbl, _ in stats["leakage"]}))
        quote = stats["leakage"][0][1]
        findings.append(Finding(
            tier=Tier.B, detector=DETECTOR,
            signal="text.assistant_leakage",
            summary=f"Verbatim chat-assistant phrasing present ({labels}): \"{quote}\"",
            source=stats["family"],
            evidence={"matches": stats["leakage"][:8],
                      "note": "Humans rarely write these unprompted; strongly "
                              "suggests text pasted from an assistant."},
        ))

    if stats["words"] < MIN_WORDS:
        if not findings:
            ctx.notes.append(f"stylometry-skipped:{stats['words']}w")
        return findings

    score = stats["score"]

    # Corroboration gate. Punctuation rates and rhythmic uniformity are real
    # signals but weak and highly shared with ordinary careful writing — a
    # semicolon habit plus even paragraphs is a writing style, not evidence.
    # They may raise a score that word choice already earned; they may not
    # produce a finding alone.
    if stats["lexical_score"] < MIN_LEXICAL_SCORE or stats["lexical_features"] < 2:
        if score >= 35:
            ctx.notes.append(
                f"stylometry-gated:score={score},lexical={stats['lexical_score']}")
        return findings

    if score >= 35:
        band = ("strongly" if score >= 65 else "moderately")
        top = "; ".join(f"{label} (×{count})" for label, count, _w in stats["hits"][:4])
        findings.append(Finding(
            tier=Tier.C, detector=DETECTOR,
            signal="text.stylometry",
            summary=(f"Prose style {band} consistent with LLM generation "
                     f"(score {score}/100 over {stats['words']} words): {top}"),
            source=stats["family"],
            evidence={
                "score": score,
                "words": stats["words"],
                "em_dash_per_1000": stats["em_dash_per_1000"],
                "burstiness_cv": stats["burstiness"],
                "punctuation_score": stats.get("punctuation_score"),
                "punctuation_profile": stats.get("punctuation"),
                "top_features": stats["hits"],
                "family_marker_counts": stats["family_scores"],
                "vendor_watermark": _vendor_watermark_note(stats["family"]),
                "caveat": ("Stylometry is not proof. A well-edited human draft, "
                           "a house style guide, or a human imitating this register "
                           "will score the same. Never present this tier alone as "
                           "a finding of AI authorship."),
            },
        ))
    elif score > 0:
        ctx.notes.append(f"stylometry-low:{score}")

    return findings


def spans(text: str) -> list[dict]:
    """Locate every stylistic tell in the text, as character ranges.

    Highlighting has to point at the evidence that was actually matched, not
    shade whole sentences by a guess. Every span here corresponds to a pattern
    that contributed to the score, so a reader can disagree with a specific
    phrase instead of arguing with a number.
    """
    found: list[dict] = []

    for pattern, weight, label in COMPILED:
        for m in pattern.finditer(text):
            found.append({"start": m.start(), "end": m.end(),
                          "label": label, "weight": weight, "kind": "style"})

    for pattern, label in COMPILED_LEAK:
        for m in pattern.finditer(text):
            found.append({"start": m.start(), "end": m.end(),
                          "label": label, "weight": 40.0, "kind": "leakage"})

    # Em dashes are only a tell in quantity, so they are marked when the rate is
    # already high — marking one in an ordinary sentence would be noise.
    n_words = len(_WORD.findall(text))
    if n_words and em_dash_rate(text, n_words) >= 2.0:
        for m in re.finditer("—", text):
            found.append({"start": m.start(), "end": m.end(),
                          "label": "em dash", "weight": 3.0, "kind": "style"})

    found.sort(key=lambda s: (s["start"], -s["weight"]))

    # Overlaps make the markup ambiguous; the heavier span wins the ground.
    merged: list[dict] = []
    for span in found:
        if merged and span["start"] < merged[-1]["end"]:
            if span["weight"] > merged[-1]["weight"]:
                merged[-1] = span
            continue
        merged.append(span)
    return merged
