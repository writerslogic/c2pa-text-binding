# Fingerprint stability

A soft binding is only useful if you know *which* edits it survives. This
document states the guarantees exactly, and every row below is backed by a test
in `src/normalize.rs` (module `stability`). If a guarantee is ever weakened, one
of those tests fails.

## Two streams, two guarantees

The algorithms do not share one normalization. They derive from two streams with
deliberately different sensitivity:

| Stream | Used by | Keeps |
|---|---|---|
| **surface** (`normalize::canonical`) | `text-fingerprint.1`, `text-minhash.1` | alphanumeric characters only, NFC, lowercased, single-space separated |
| **structural** (`normalize::structural`) | `text-structure.1` | everything except zero-width/format characters, NFC |

The surface stream throws away case, punctuation, and all whitespace shape. The
structural stream keeps them, because sentence and paragraph boundaries *are*
the signal it reads.

## What the surface fingerprints survive

`text-fingerprint.1` and `text-minhash.1` produce an identical value after any
of these:

| Transformation | Stable | Why |
|---|---|---|
| CRLF ↔ LF line endings | yes | any non-alphanumeric run collapses to one separator |
| Reflowed paragraphs, changed wrapping | yes | same |
| Leading/trailing whitespace | yes | separators do not appear at the edges |
| Runs of spaces or tabs | yes | collapsed to a single space |
| Case changes | yes | lowercased |
| Punctuation added, removed, or changed | yes | punctuation is a separator, never content |
| Byte-order mark added or removed | yes | stripped as a format character |
| Zero-width injection (`U+200B`, `U+200C`, `U+200D`, `U+2060`) | yes | stripped |
| Variation selectors (`U+FE00`–`U+FE0F`) | yes | stripped |
| NFC ↔ NFD (`é` vs `e` + combining acute) | yes | normalized to NFC first |

That last row matters more than it looks: a macOS filesystem round trip can
convert NFC to NFD silently, and without normalization every fingerprint would
break on a file that was merely copied.

## What they must *not* survive

A fingerprint that absorbed real edits would match unrelated text and make the
recovery layer worthless. These change the value:

| Transformation | Stable |
|---|---|
| A word substituted | **no** |
| A word added or removed | **no** |
| Digits changed | **no** |

## The structural fingerprint differs

`text-structure.1` shares only the NFC and zero-width guarantees. It is
**sensitive** to case, punctuation, and line structure by design — that is what
it measures. Use it alongside a surface fingerprint, not instead of one: it
catches reorganisation that the surface stream is blind to, and is in turn
blind to reformatting the surface stream absorbs.

## What none of them survive

No soft binding survives translation, paraphrase, or summarisation. Those
produce different content, and a soft binding measures content. For text that
has been rewritten rather than reformatted, nothing here will recover the
manifest — that is a limit of the approach, not of this implementation.
