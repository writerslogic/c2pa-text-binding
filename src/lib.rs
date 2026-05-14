// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! C2PA soft binding and content fingerprinting for text assets.
//!
//! Provides a trait-based interface for text fingerprinting algorithms
//! that can be registered with the C2PA soft binding resolution API.
//! Implementations generate content-derived fingerprints that survive
//! reformatting, re-encoding, and partial modification of text content.

mod error;
mod fingerprint;

pub use error::Error;
pub use fingerprint::{TextFingerprint, FingerprintResult};
