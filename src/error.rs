// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

/// Errors produced by the text soft-binding algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input has too little content for the requested algorithm (e.g. not
    /// enough word boundaries to place a watermark payload).
    ContentTooShort,
    /// A fingerprint value could not be produced.
    GenerationFailed(String),
    /// A fingerprint comparison failed.
    MatchFailed(String),
    /// Reed-Solomon erasure coding/decoding failed.
    Coding(String),
    /// The watermark payload was present but its content-binding HMAC did not
    /// verify against the recomputed content hash (transfer or tamper).
    TagMismatch,
    /// The watermark could not be recovered (too many stripped positions).
    WatermarkUnrecoverable,
    /// A caller-supplied argument was malformed.
    InvalidInput(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContentTooShort => {
                write!(f, "text content too short for this soft-binding algorithm")
            }
            Self::GenerationFailed(s) => write!(f, "fingerprint generation failed: {s}"),
            Self::MatchFailed(s) => write!(f, "fingerprint match failed: {s}"),
            Self::Coding(s) => write!(f, "reed-solomon coding failed: {s}"),
            Self::TagMismatch => write!(
                f,
                "watermark content-binding tag did not verify (transferred or modified content)"
            ),
            Self::WatermarkUnrecoverable => {
                write!(
                    f,
                    "watermark could not be recovered from remaining positions"
                )
            }
            Self::InvalidInput(s) => write!(f, "invalid input: {s}"),
        }
    }
}

impl std::error::Error for Error {}
