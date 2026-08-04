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

#![forbid(unsafe_code)]
#![warn(missing_docs)]
pub mod crosscheck;
/// Errors from the soft-binding algorithms.
pub mod error;
pub mod manifest;
pub mod minhash;
pub mod normalize;
pub mod simhash;
pub mod soft_binding;
pub mod stego;
pub mod structure;
pub mod tag;
pub mod zwbin;

/// The A.8 variation-selector transport, re-exported from
/// [`c2pa-unstructured-text`](https://crates.io/crates/c2pa-unstructured-text).
///
/// This was previously a module of this crate. It is a *hard-binding* carrier,
/// which never belonged alongside the soft-binding family here, so it now lives
/// in the crate that owns A.8. The re-export keeps it reachable for the
/// survivability comparison in `examples/transport_survivability.rs`, which
/// measures the hard-binding carrier against the soft-binding ones.
///
/// The API changed with the move: extraction returns `Result<Wrapper, Error>`
/// rather than a `Decoded` enum, since a wrapper now carries its byte range as
/// well as its payload.
pub use c2pa_unstructured_text::wrapper as vs;

/// The byte-level selector codec, re-exported alongside [`vs`].
pub use c2pa_unstructured_text::vs as vs_codec;

/// SHA-256 for the v2 wrapper checksum, over this crate's existing `sha2`.
///
/// The transport crate injects its digest rather than depending on one, so
/// supplying it here keeps that crate's contribution to this dependency tree at
/// zero: everything it needs is already present for the soft-binding family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256Hasher;

impl c2pa_unstructured_text::hardbinding::Hasher for Sha256Hasher {
    fn digest(&self, alg: c2pa_unstructured_text::hardbinding::Algorithm, data: &[u8]) -> Vec<u8> {
        use c2pa_unstructured_text::hardbinding::Algorithm;
        use sha2::Digest;
        // Honour the requested algorithm rather than always answering SHA-256:
        // the v2 checksum only asks for SHA-256, but the trait contract is
        // wider and a silently wrong digest would be worse than a missing one.
        match alg {
            Algorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Algorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Algorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

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
