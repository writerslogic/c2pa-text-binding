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

impl Error {
    /// The registered C2PA validation status code for this error, or `None`
    /// when the condition carries no status code.
    ///
    /// Always `None`. This crate implements *soft* binding — fingerprinting and
    /// watermarking — whose failures are not hard-binding validation outcomes.
    /// A soft binding that does not match means the recovery path found no
    /// candidate, not that a located manifest failed to validate, and the
    /// specification registers no status code for that.
    ///
    /// Every crate in this family exposes this method, so a dispatcher handling
    /// several embedding methods can ask the same question of any of them.
    pub fn code(&self) -> Option<&'static str> {
        None
    }

    /// Whether this error means the asset carries no provenance at all.
    ///
    /// Always `false`: soft binding is a recovery mechanism used *after* the
    /// hard binding has already failed to locate a manifest, so it is never the
    /// thing that decides whether an asset is unsigned.
    pub fn is_no_manifest_located(&self) -> bool {
        false
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Soft-binding failures are not hard-binding validation outcomes, so no
    /// variant may claim a status code. Guards against a later edit inventing
    /// one.
    #[test]
    fn no_variant_claims_a_status_code() {
        for e in [
            Error::ContentTooShort,
            Error::GenerationFailed("x".into()),
            Error::MatchFailed("x".into()),
            Error::Coding("x".into()),
            Error::TagMismatch,
            Error::WatermarkUnrecoverable,
            Error::InvalidInput("x".into()),
        ] {
            assert_eq!(e.code(), None, "{e:?} claimed a status code");
            assert!(
                !e.is_no_manifest_located(),
                "{e:?} must not decide whether an asset is unsigned"
            );
        }
    }
}
