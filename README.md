<p align="center">
  <h1 align="center">c2pa-text-binding</h1>
  <p align="center">C2PA soft binding and content fingerprinting for text assets</p>
</p>

<p align="center">
  <a href="https://crates.io/crates/c2pa-text-binding"><img src="https://img.shields.io/crates/v/c2pa-text-binding.svg" alt="crates.io"></a>
  <a href="https://docs.rs/c2pa-text-binding"><img src="https://docs.rs/c2pa-text-binding/badge.svg" alt="docs.rs"></a>
  <a href="#license"><img src="https://img.shields.io/crates/l/c2pa-text-binding.svg" alt="License"></a>
</p>

## Overview

Provides a trait-based interface for text content fingerprinting algorithms compatible with the [C2PA Soft Binding](https://c2pa.org/specifications/) framework. Implementations generate content-derived fingerprints that survive reformatting, re-encoding, and partial modification of text content, enabling manifest recovery when hard bindings are broken.

Where hard bindings (cryptographic hashes) break on any byte-level change, soft bindings use perceptual fingerprints to re-associate content with its provenance even after transformation.

## Quick Start

```toml
[dependencies]
c2pa-text-binding = "0.1"
```

### Implement a fingerprinting algorithm

```rust
use c2pa_text_binding::{TextFingerprint, FingerprintResult, Error};

struct MyAlgorithm;

impl TextFingerprint for MyAlgorithm {
    fn algorithm_id(&self) -> &str {
        "com.writerslogic.text-fingerprint-v1"
    }

    fn generate(&self, text: &str) -> Result<FingerprintResult, Error> {
        // Your fingerprinting implementation
        todo!()
    }

    fn match_fingerprint(
        &self,
        text: &str,
        fingerprint: &[u8],
    ) -> Result<f64, Error> {
        // Returns confidence score 0.0..=1.0
        todo!()
    }
}
```

### Register with the Soft Binding Resolution API

Fingerprinting algorithms can be registered with the [C2PA Soft Binding Resolution API](https://c2pa.org/specifications/) to enable decentralized manifest recovery for text assets.

## Related Crates

| Crate | Description |
|---|---|
| [c2pa-structured-text](https://github.com/writerslogic/c2pa-structured-text) | Structured text embedding via ASCII armour delimiters |
| [c2pa-text](https://crates.io/crates/c2pa-text) | Unstructured text embedding via Unicode Variation Selectors |
| [c2pa-rs](https://crates.io/crates/c2pa) | Official C2PA SDK |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

Built by [WritersLogic](https://writerslogic.com)
