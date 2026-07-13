<p align="center">
  <h1 align="center">c2pa-text-binding</h1>
  <p align="center">C2PA soft binding and content fingerprinting for text assets</p>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/c2pa-text-binding/actions/workflows/ci.yml"><img src="https://github.com/writerslogic/c2pa-text-binding/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/c2pa-text-binding"><img src="https://img.shields.io/crates/v/c2pa-text-binding.svg" alt="crates.io"></a>
  <a href="https://docs.rs/c2pa-text-binding"><img src="https://docs.rs/c2pa-text-binding/badge.svg" alt="docs.rs"></a>
  <a href="#license"><img src="https://img.shields.io/crates/l/c2pa-text-binding.svg" alt="License"></a>
</p>

## Overview

A concrete family of text soft-binding algorithms compatible with the [C2PA Soft Binding](https://spec.c2pa.org/) framework, each registered in the [C2PA soft binding algorithm list](https://github.com/c2pa-org/softbinding-algorithm-list). A soft binding derives a content-keyed value that survives reformatting, re-encoding, excerpting, and light editing, so a manifest is recoverable when the hard binding — a byte-exact hash — has been broken.

| Module | Algorithm (list id) | Kind |
|---|---|---|
| `simhash` | `com.writerslogic.text-fingerprint.1` (41) | surface fingerprint |
| `stego` | `com.writerslogic.zwc-watermark.2` (42) | zero-width watermark |
| `structure` | `com.writerslogic.text-structure.1` (43) | structural fingerprint |
| `minhash` | `com.writerslogic.text-minhash.1` (44) | excerpt/quotation fingerprint |

This crate is the **perceptual/watermark recovery layer**. It is distinct from the Variation-Selector transport used elsewhere in WritersProof, which is a *hard* binding (a `c2pa.hash.data` over normalized text) and is not soft binding. Registration in the algorithm list is **not** C2PA conformance certification.

## Quick Start

```toml
[dependencies]
c2pa-text-binding = "0.1"
```

### Emit and sign a `c2pa.soft-binding` assertion

`soft_binding` builds the normative CBOR assertion (it round-trips through the
`c2pa-rs` reader — see `tests/c2pa_roundtrip.rs`); `manifest` signs it as a
COSE_Sign1 / EdDSA envelope.

```rust
use c2pa_text_binding::{simhash::Fingerprint, soft_binding, sign_cose, SOFT_BINDING_LABEL};

let text = "…the document being bound…";
let secret_key = [7u8; 32];                   // caller-supplied Ed25519 secret
let assertion = soft_binding::from_fingerprint(&Fingerprint::compute(text));
let cbor = assertion.to_cbor()?;              // store under SOFT_BINDING_LABEL
let signed = sign_cose(&cbor, &secret_key)?;  // detached-key COSE_Sign1
# Ok::<(), c2pa_text_binding::Error>(())
```

### Recover and classify a candidate

The verify path recomputes the fingerprint from the current text, compares it to
the stored value at the algorithm's registered threshold, and returns a
confidence tier. BOUND requires a *durable* fingerprint match (41/44, measured
zero false matches) plus the anti-transfer cross-check; a structural (43) match
or a watermark hit alone caps at LIKELY. Tier thresholds are grounded in
[`ROBUSTNESS.md`](ROBUSTNESS.md).

```rust
use c2pa_text_binding::{simhash::Fingerprint, soft_binding::{self, SoftBinding}, verify, Confidence};

let text = "…the document being bound…";
let cbor = soft_binding::from_fingerprint(&Fingerprint::compute(text)).to_cbor()?;

let candidate = SoftBinding::from_cbor(&cbor)?;
let tier = verify(text, &candidate, /*watermark_verified=*/ false, /*crosscheck_ok=*/ true);
assert_eq!(tier, Confidence::Bound);
# Ok::<(), c2pa_text_binding::Error>(())
```

### Register with the Soft Binding Resolution API

These algorithms are registered in the [C2PA soft binding algorithm list](https://github.com/c2pa-org/softbinding-algorithm-list), so a `c2pa.soft-binding` assertion referencing them can drive [decentralized manifest recovery](https://spec.c2pa.org/).

## Related Crates

| Crate | Description |
|---|---|
| [c2pa-structured-text](https://github.com/writerslogic/c2pa-structured-text) | Structured text embedding via ASCII armour delimiters |
| [c2pa-text](https://crates.io/crates/c2pa-text) | Unstructured text embedding via Unicode Variation Selectors |
| [c2pa-rs](https://crates.io/crates/c2pa) | Official C2PA SDK |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

Built by [WritersLogic](https://writerslogic.com)