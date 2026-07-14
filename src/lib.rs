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
//! [`normalize`] is the shared canonical stream; [`soft_binding`] emits the
//! `c2pa.soft-binding` assertion (CBOR that round-trips through the c2pa-rs
//! reader); [`crosscheck`] recomputes a candidate's fingerprint from the current
//! text and classifies it into a BOUND / LIKELY / REVIEW confidence tier, whose
//! boundaries are grounded in the measured false-match rates in
//! `examples/threshold_sweep.rs`.
//!
//! Everything here compiles to `wasm32-unknown-unknown`. All cryptography is
//! pure Rust with no C bindings (sha2, hmac, blake2, ed25519-dalek, coset); the
//! soft-binding assertion is CBOR via ciborium, and reed-solomon-erasure backs
//! watermark recovery. Registration in the C2PA algorithm list is not the same
//! as C2PA conformance certification, which is a separate program this crate
//! makes no claim to.

pub mod crosscheck;
pub mod error;
pub mod manifest;
pub mod minhash;
pub mod normalize;
pub mod simhash;
pub mod soft_binding;
pub mod stego;
pub mod structure;
pub mod tag;
pub mod vs;
pub mod zwbin;

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(feature = "python")]
mod python;

pub use crosscheck::{
    classify, crosscheck_tag, fingerprint_evidence, verify, Confidence, Evidence,
};
pub use error::Error;
pub use manifest::{public_key, sign_cose, verify_cose};
pub use minhash::MinHash;
pub use simhash::{Fingerprint, Hash256};
pub use soft_binding::{SoftBinding, SOFT_BINDING_LABEL};
pub use stego::{embed, extract, Recovered};
