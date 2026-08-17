Here's the thing about provenance metadata: it's not really about proving what a
file is — it's about proving what a file claims to be. That said, the distinction
matters more than most teams realise, and it's worth noting that the two failure
modes look identical from the outside.

Let's break this down. When a generator writes a manifest, it is making an
assertion. The assertion is signed, which means it is attributable. But
attribution is not the same as truth, and the gap between them is where every
interesting attack lives.

To be clear, this isn't a reason to distrust the entire system. It's a reason to
understand what the system actually guarantees. A signed manifest tells you who
said something, not whether what they said was accurate. That's a meaningful
guarantee — just a narrower one than the marketing suggests.

The short answer is that you should treat provenance as one input among several.
It's important to note that no single signal is decisive here. A few things
follow from that: verify the signature chain, corroborate against file structure,
and never let a single field drive a decision that matters.
