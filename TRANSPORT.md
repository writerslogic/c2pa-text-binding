# Transport-Survivability Evidence for Invisible-Text Provenance Carriers

## Motivation

C2PA Appendix A.8 embeds a manifest into text as a run of Unicode variation
selectors, and states of itself that it "remains under review and may be subject
to change based on implementation feedback and interoperability testing." This
document is that testing: a reproducible measurement of whether an invisible
carrier survives a text pipeline, and — when it does not — whether it fails
*safe* (rejected) or *unsafe* (decodes to the wrong bytes).

It compares the A.8 variation-selector carrier against alternative invisible-text
schemes and against the content-fingerprint recovery layer, so the results speak
to the design of A.8 and to the value of a layered approach.

## Methodology

Every method exposes the same shape: embed a payload into a host text, apply a
transport, re-extract, and classify:

| outcome | meaning |
|---|---|
| `intact` | payload recovered unchanged |
| `gone` | no carrier detected — safe, reads as no manifest |
| `safe` | carrier detected but rejected by the codec — fail-safe |
| `UNSAFE` | carrier decoded to the **wrong** payload — the only real failure |

Methods:

| column | carrier |
|---|---|
| `v1ref`, `v1inl` | A.8 variation selectors (v1), reference-size (42 B) and inline-size (1 KB) |
| `v2ref` | proposed self-delimiting A.8 (v2, no length field), reference-size |
| `zwc` | zero-width watermark with Reed-Solomon coding (`stego`) |
| `tag` | Unicode Tags "ASCII smuggling" carrier |
| `zwbin` | naive zero-width binary, no error correction |
| `simhash` | content fingerprint — recovery layer, carries no bytes |

Three views, all deterministic and credential-free
(`cargo run --release --example transport_survivability`):

1. **Categorical probes** — normalization and targeted stripping.
2. **Partial carrier loss** — a share of carrier code points dropped
   deterministically, isolating error-correction behavior.
3. **Tail truncation** — host kept, only the trailing carrier truncated,
   isolating payload-length effects.

These are Tier 0 codec-level probes, not real-platform measurements; see
Limitations.

## Results

### Categorical transports

```
                    v1ref    v1inl    v2ref    zwc      tag      zwbin    simhash
identity            intact   intact   intact   intact   intact   intact   intact
nfc                 intact   intact   intact   intact   intact   intact   intact
nfkc                intact   intact   intact   intact   intact   intact   intact
nfkd                intact   intact   intact   intact   intact   intact   intact
strip-bom           gone     gone     gone     intact   intact   intact   intact
bmp-only            gone     gone     gone     intact   gone     intact   intact
strip-zero-width    gone     gone     gone     gone     intact   gone     intact
strip-variation-sel gone     gone     gone     intact   intact   intact   intact
strip-tags          intact   intact   intact   intact   gone     intact   intact
```

### Partial carrier loss

```
                    v1ref    v1inl    v2ref    zwc      tag      zwbin    simhash
drop-0%             intact   intact   intact   intact   intact   intact   intact
drop-5%             safe     safe     UNSAFE   intact   safe     safe     intact
drop-10%            safe     safe     UNSAFE   intact   UNSAFE   safe     intact
drop-20%            gone     gone     gone     intact   safe     safe     intact
drop-30%            gone     gone     gone     intact   safe     safe     intact
drop-50%            gone     gone     gone     gone     safe     safe     intact
```

### Tail truncation (host + N carrier code points kept)

```
                    v1ref    v1inl    v2ref    zwc      tag      zwbin    simhash
keep-0              gone     gone     gone     gone     gone     gone     intact
keep-16             safe     safe     UNSAFE   gone     UNSAFE   safe     intact
keep-50             safe     safe     UNSAFE   gone     UNSAFE   safe     intact
keep-100            intact   safe     intact   gone     intact   safe     intact
keep-300            intact   safe     intact   intact   intact   safe     intact
keep-1200           intact   intact   intact   intact   intact   intact   intact
```

## Findings

1. **Unicode normalization is not the threat.** All four normal forms preserve
   every carrier; the visible-text hash procedure's use of NFC is safe.

2. **The A.8 variation-selector carrier is the most transport-fragile of the
   set.** It is lost by BOM stripping (it depends on a `U+FEFF` marker), by any
   BMP-only pipeline (its magic bytes live in the astral plane), and by
   variation-selector filtering. The zero-width watermark survives all three.

3. **Error correction is decisive under partial loss.** The Reed-Solomon
   watermark stays `intact` through ~30% code-point loss; every length-less
   carrier is `gone` or `UNSAFE` by 20%. This is the single largest survivability
   difference in the table, and it is a property of the coding, not the alphabet.

4. **Dropping the length field regresses fail-safety.** The proposed
   self-delimiting v2 frame and the `tag` carrier both fail **UNSAFE** under
   partial loss and truncation: with no length field and a payload that is not
   internally length-delimited (a bare reference), a truncated run decodes to a
   shorter wrong payload instead of being rejected. The A.8 v1 length field is
   exactly what turns those cases into `safe`. **Structural exclusion fixes the
   hash circular dependency, but the wrapper still needs a length or checksum to
   detect truncation** — the self-delimiting simplification must not be applied to
   reference-mode payloads without one.

5. **Aggressive invisible-character sanitization is a hard ceiling.** A filter
   that removes zero-width formatting characters takes out the variation-selector,
   zero-width, and Reed-Solomon carriers alike. No in-band invisible scheme
   survives it. Only the fingerprint layer does.

6. **The fingerprint recovery layer is transport-immune.** Because it is derived
   from the visible words rather than carried in invisible code points, it
   survives every character-level transport here, including the sanitizer that
   erases every carrier. Its complementary weakness — paraphrase and heavy
   editing — is measured on the content axis in `ROBUSTNESS.md`.

7. **Shorter payloads survive truncation that destroys longer ones.** A
   reference-size payload is recovered where an inline-size payload of the same
   carrier is only fail-safe (`keep-100`), supporting a reference-preferred design
   — provided finding 4 is respected.

## Limitations

- These are deterministic codec-level probes, not measurements of real
  applications. The categorical transports model what a pipeline *might* do; they
  do not prove any specific product does it. Tier 1 (real HTML sanitizer
  libraries, platform APIs, and headless web clients) and Tier 2 (native
  desktop and messaging apps) reuse these same methods and classifier over real
  transports and are required for external validity.
- The partial-loss model drops code points independently and uniformly; real
  losses are often structured (whole-run stripping, boundary effects).
- `tag` and `zwbin` are included as comparison methods, not recommended carriers;
  `tag` characters have no legitimate use in C2PA text fields.
