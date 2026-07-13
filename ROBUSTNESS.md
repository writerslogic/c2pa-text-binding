# Robustness Evidence for C2PA Soft-Binding Algorithms

**Status:** proposal / reference results. Draft for discussion with the C2PA
soft-binding and conformance task forces.

## Motivation

Every entry in the [C2PA soft-binding algorithm list](https://github.com/c2pa-org/softbinding-algorithm-list)
carries a prose robustness claim ("robust to copy-paste and re-encoding",
"robust to reordering", etc.) but **no measured evidence and no shared way to
produce it**. An implementer choosing an algorithm, or a validator deciding how
much to trust a soft-binding match, has nothing comparable to go on.

This document proposes (1) a small, reproducible robustness methodology, and
(2) an optional per-entry `robustnessEvidence` convention so each algorithm
owner can publish comparable numbers **for their own algorithm** — no
cross-owner ranking, self-reported and auditable. It includes reference results
for the WritersLogic text family (IDs 29, 41, 42, 43, 44) produced with the
harness in `examples/robustness_bench.rs`.

## Methodology

- **Corpus.** PAN'26 Text Watermarking dataset (political speeches),
  [Zenodo 18620130](https://zenodo.org/records/18620130). Per-media corpora
  (image/audio/video) are left to each owner; the framework is media-agnostic.
- **Attack battery (disclosed and reproducible).** Format: strip zero-width /
  variation selectors, NFKD, case-fold, whitespace-collapse, full "retype"
  (strip + NFC + lowercase + whitespace). Structural: truncation (50/90%),
  excerpt (contiguous 30% window). Content: word deletion (5/15%), character
  typos (5%). Paraphrase: DIPPER (`kalpeshk2011/dipper-paraphraser-xxl`) at
  stated lexical/order diversity. (PAN's own competition attacks are held out
  by design; this battery is a disclosed approximation, not PAN's secret set.)
- **Match semantics.** Each algorithm is evaluated with **its own registered
  threshold and match function** — no re-tuning. SimHash Hamming ≤ 32/256;
  structural Hamming ≤ 24/256; MinHash "same or overlapping" = whole-signature
  Jaccard ≥ 0.70 **or** a shared LSH band; watermark = routing pointer
  recovered.
- **Metrics.** Per attack: **Balanced Accuracy** = (survival rate + true-negative
  rate) / 2, plus survival (true-positive) rate. True-negative rate is measured
  against unrelated documents. For formal use we recommend also reporting
  **TPR@1%FPR** and stating the **analytic false-match probability** where a null
  exists: for a 256-bit SimHash the bit-agreement count is Binomial(256, 0.5)
  under the null, so P(Hamming ≤ t) is an incomplete-beta tail; for MinHash-LSH
  it is the banding S-curve; for the structural hash (dependent bits) use
  conformal calibration on a known-negative corpus.
- **Reproducibility.** Model-free algorithms reproduce deterministically from
  any verifier. `cargo run --release --example robustness_bench -- <dataset.jsonl> <limit> [paraphrases.jsonl]`.

## Reference results — WritersLogic text soft-binding family

n = 100 PAN'26 political speeches. Balanced Accuracy per attack (1.000 = perfect,
0.500 = chance). Watermark visible-fidelity = 1.000. The true-negative rate in
this table samples **one** unrelated document per source; for the grounded
all-pairs false-match rate (which reveals that 43 structural is *not*
false-match-free) see [Threshold grounding](#threshold-grounding-and-confidence-tiers)
below.

| attack | 41 SimHash | 43 structural | 44 MinHash | 42 ZWC watermark |
|---|---|---|---|---|
| identity (calibration) | 1.000 | 0.995 | 1.000 | 1.000 |
| strip invisibles | 1.000 | 0.995 | 1.000 | 0.500 |
| NFKD / case-fold / whitespace | 1.000 | 0.995 | 1.000 | 1.000 |
| retype | 1.000 | 0.995 | 1.000 | 0.500 |
| truncate 50% | 0.675 | 0.620 | 0.925 | 0.500 |
| excerpt 30% | 0.615 | 0.525 | 0.625 | 0.500 |
| word deletion 15% | 0.970 | 0.630 | 0.535 | 0.500 |
| typos 5% | 0.805 | 0.635 | 0.500 | 0.500 |
| paraphrase — DIPPER lex60/order60 | 0.500 | 0.500 | 0.500 | 0.500 |
| paraphrase — DIPPER lex60/order0 (synonym-only) | 0.545 | 0.515 | 0.505 | 0.500 |
| **mean (adversarial attacks)** | **0.880** | **0.800** | **0.840** | **0.625** |

Mean is over the primary battery (paraphrase = lex60/order60). The lex60/order0
row is a diagnostic that isolates synonym substitution from reordering.

### Honest reading of these numbers

- **The content fingerprints (41/43/44) are the durable layer.** They survive
  every format transform (strip, NFKD, case, whitespace, retype) because the
  canonical normalization absorbs them, and they degrade gracefully on content
  edits. 44 MinHash is the strongest excerpt/overlap matcher (0.925 at
  truncate-50, 0.625 at excerpt-30) via the LSH band path; 41 SimHash is the
  most robust to light word edits.
- **The ZWC watermark (42) is an exact content-and-carrier binding, not a robust
  recovery mechanism.** It survives only transforms that preserve both the
  canonical content and the invisible carrier, and is invalidated by any content
  change or carrier stripping — consistent with its registry description
  ("invalidated by content modification, by design"). Its value is a keyed,
  spoof-resistant routing pointer, not edit-robust recovery.
- **No model-free algorithm survives strong paraphrase (DIPPER lex60/order60).**
  All collapse to chance. This is the acknowledged ceiling of model-free
  fingerprinting: genuine paraphrase robustness requires either an embedding
  model (which forfeits deterministic verifier reproducibility unless the spec
  pins a model + version) or a retrieval layer. Robustness to paraphrase should
  come from a **combined-channel + retrieval** architecture, not from any single
  fingerprint.
- **Entry 43's "robust to synonym substitution" claim needs narrowing.** The
  lex60/order0 diagnostic isolates synonym substitution from reordering, and 43
  still drops to chance (0.515). The cause is structural: 43 hashes sentence
  **length sequences**, and synonyms carry different token counts ("act" →
  "law on"), so substantive lexical paraphrase shifts the length sequence
  regardless of word order. The claim holds only for light synonym swaps that
  preserve token counts. The durable fix is a token-count-invariant, set-based
  structural signal (e.g. POS / dependency n-gram multisets + function-word
  distribution) rather than length-sequence hashing.

## Threshold grounding and confidence tiers

The table above scores one intensity per attack. To ground the registered
thresholds — and the BOUND / LIKELY / REVIEW tiers built on them — as curves
rather than points, `examples/threshold_sweep.rs` sweeps intensity axes and
tests **all** unrelated document pairs. Numbers below are n = 200 PAN'26
documents (≥ 1024 chars each, so the excerpt/window path is exercised);
reproduce with `cargo run --release --example threshold_sweep -- <dataset> 200`.

**All-pairs false-match rate** (39,800 ordered unrelated pairs, at each
algorithm's registered threshold):

| algorithm | threshold | false matches | FMR |
|---|---|---|---|
| 41 SimHash | Hamming ≤ 32 | 0 / 39,800 | 0.000 |
| 43 structural | Hamming ≤ 24 | 392 / 39,800 | **0.010** |
| 44 MinHash | Jaccard ≥ 0.70 or shared band | 0 / 39,800 | 0.000 |

**Separation margin** (whole-document Hamming, bits): the largest distance under
benign reformatting vs. the smallest distance to any unrelated document.

| algorithm | max benign dist | threshold | min unrelated dist | margin |
|---|---|---|---|---|
| 41 SimHash | 3 | 32 | 44 | **+12** |
| 43 structural | 0 | 24 | 8 | **−16** |

**Edit-distance sweep** (survival, k = word substitutions) and **excerpt-length
sweep** (survival, contiguous window):

| k edits | 41 | 43 | 44 | | fraction | 41 (window) | 44 (LSH) |
|---|---|---|---|---|---|---|---|
| 1 | 1.000 | 1.000 | 1.000 | | 0.1 | 0.045 | 0.000 |
| 4 | 1.000 | 0.995 | 1.000 | | 0.3 | 0.265 | 0.200 |
| 8 | 0.985 | 0.985 | 1.000 | | 0.5 | 0.360 | 0.825 |
| 16 | 0.745 | 0.855 | 0.945 | | 0.7 | 0.845 | 1.000 |
| 32 | 0.225 | 0.590 | 0.610 | | 0.9 | 1.000 | 1.000 |

Reformatting (case-fold → whitespace → zero-width injection → NFKD/retype) holds
survival at **1.000** for all three at every level: normalization absorbs format,
so the whole threshold budget is spent on content edits.

### How this grounds the tiers

- **BOUND requires a *durable* fingerprint match (41 or 44) plus the keyed
  cross-check.** Both durable fingerprints show **zero** false matches over
  39,800 unrelated pairs, so a false BOUND from fingerprint collision is below
  measurement here; the HMAC cross-check bounds *transfer* cryptographically.
  This is what `crosscheck::classify` enforces.
- **A structural (43) match is corroborating only — never BOUND.** Its threshold
  (24) sits *above* the nearest unrelated distance (8): a **−16-bit** margin and
  a measured 1.0% false-match rate. `crosscheck::classify` therefore caps a
  structural-only candidate at LIKELY even with the cross-check present. This
  corrects the single-neighbour reading in the reference table, which reported
  no false matches only because it sampled one negative per document.
- **A watermark (42) hit alone is LIKELY, never BOUND**, because a zero-width
  carrier can be transferred; BOUND still needs the recomputed durable
  fingerprint. The tier logic and these thresholds are unit-tested in
  `src/crosscheck.rs`.

None of this upgrades the conformance claim: the algorithms are registered in
the soft-binding list, which is not the same as C2PA conformance certification.

## Proposed registry convention

Add an **optional** `robustnessEvidence` object to a soft-binding list entry's
`entryMetadata`, populated by the algorithm's owner:

```json
"robustnessEvidence": {
  "methodology": "<url + version of the shared methodology>",
  "corpus": "PAN'26 text-watermarking (Zenodo 18620130)",
  "harness": "<url to the runnable harness>",
  "date": "2026-07-10",
  "results": { "excerpt30": {"balancedAccuracy": 0.625},
               "paraphrase_dipper_l60_o60": {"balancedAccuracy": 0.500} }
}
```

Each owner runs **their own** algorithm, on media appropriate to it, through the
shared methodology and submits the numbers. The registry gains comparable
evidence over time without any party grading another. Numbers are self-reported
but reproducible and auditable via the referenced harness.

## Limitations

- Reference results here are **text-only**; image/audio/video entries need
  per-media attack batteries (crop/compress/rotate; resample/noise; etc.).
- The disclosed attack battery is an approximation of real-world obfuscation,
  **not** an adversarial worst case and not PAN's held-out competition attacks.
- Balanced Accuracy on a fixed corpus is a screening metric; TPR@fixed-FPR on
  ≥2 corpora is the stronger claim (PAN's own finding is that single-dataset
  robustness does not transfer).
