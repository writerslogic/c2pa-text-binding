// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference implementation of the WritersLogic C2PA text soft-binding family.
//!
//! Each algorithm links text content to its C2PA manifest without a byte-exact
//! hash, so provenance is recoverable after copying, reformatting, excerpting,
//! or light editing. All algorithms are registered in the C2PA Soft Binding
//! Algorithm List and referenced from a `c2pa.soft-binding` assertion.
//!
//! | Module | Algorithm | Kind |
//! | --- | --- | --- |
//! | [`stego`] | `com.writerslogic.zwc-watermark.2` | watermark (embedded) |
//! | [`simhash`] | `com.writerslogic.text-fingerprint.1` | fingerprint (surface) |
//! | [`minhash`] | `com.writerslogic.text-minhash.1` | fingerprint (excerpt) |
//! | [`structure`] | `com.writerslogic.text-structure.1` | fingerprint (structural) |
//!
//! [`normalize`] is the shared canonical stream; [`crosscheck`] classifies a
//! candidate manifest into a BOUND / LIKELY / REVIEW confidence tier.
//!
//! Everything here compiles to `wasm32-unknown-unknown` and uses pure-Rust
//! crypto only (sha2, hmac, blake2, reed-solomon-erasure). Registration in the
//! C2PA algorithm list is not the same as C2PA conformance certification, which
//! is a separate program this crate makes no claim to.

pub mod crosscheck;
pub mod error;
pub mod minhash;
pub mod normalize;
pub mod simhash;
pub mod stego;
pub mod structure;

pub use crosscheck::{classify, crosscheck_tag, Confidence, Evidence};
pub use error::Error;
pub use minhash::MinHash;
pub use simhash::{Fingerprint, Hash256};
pub use stego::{embed, extract, Recovered};
