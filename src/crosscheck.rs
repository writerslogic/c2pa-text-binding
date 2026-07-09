// SPDX-License-Identifier: MIT OR Apache-2.0

//! Content-keyed cross-check and confidence classification.
//!
//! A watermark hit routes to a *candidate* manifest but never establishes a
//! binding on its own — a routing tag can be transferred onto other content.
//! A candidate is only [`Confidence::Bound`] when a fingerprint recomputed from
//! the current text matches the manifest's stored fingerprint, so a transferred
//! tag is rejected. The [`crosscheck_tag`] anti-transfer pointer binds a
//! manifest to a `(repo_id, content_hash)` pair.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Anti-transfer pointer: `HMAC-SHA256(key, repo_id ‖ content_hash)`.
///
/// Stored in the manifest and recomputed on verify; a mismatch means the
/// content or the routing target was swapped.
pub fn crosscheck_tag(key: &[u8], repo_id: &[u8], content_hash: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(repo_id);
    mac.update(content_hash);
    mac.finalize().into_bytes().into()
}

/// The provenance confidence tier surfaced to a verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    /// A fingerprint recomputed from the current text matches the manifest and
    /// the anti-transfer cross-check passes.
    Bound,
    /// A watermark or fingerprint hit, but the binding is not fully confirmed.
    Likely,
    /// Weak or no evidence; a human should review.
    Review,
}

/// Evidence gathered while resolving a candidate manifest.
#[derive(Clone, Copy, Debug, Default)]
pub struct Evidence {
    /// The v2 watermark payload verified against the current content.
    pub watermark_verified: bool,
    /// A surface / structural / lexical fingerprint matched the manifest.
    pub fingerprint_match: bool,
    /// The anti-transfer cross-check tag matched.
    pub crosscheck_ok: bool,
}

/// Classify the evidence into a confidence tier.
///
/// [`Confidence::Bound`] requires a fingerprint cross-check — never a watermark
/// hit alone — so a tag transferred onto unrelated content cannot reach BOUND.
pub fn classify(ev: &Evidence) -> Confidence {
    if ev.fingerprint_match && ev.crosscheck_ok {
        Confidence::Bound
    } else if ev.watermark_verified || ev.fingerprint_match {
        Confidence::Likely
    } else {
        Confidence::Review
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crosscheck_is_deterministic_and_binds_inputs() {
        let a = crosscheck_tag(b"key", b"repo-1", b"hashA");
        assert_eq!(a, crosscheck_tag(b"key", b"repo-1", b"hashA"));
        assert_ne!(a, crosscheck_tag(b"key", b"repo-2", b"hashA"));
        assert_ne!(a, crosscheck_tag(b"key", b"repo-1", b"hashB"));
    }

    #[test]
    fn bound_requires_fingerprint_and_crosscheck() {
        let ev = Evidence {
            watermark_verified: true,
            fingerprint_match: true,
            crosscheck_ok: true,
        };
        assert_eq!(classify(&ev), Confidence::Bound);
    }

    #[test]
    fn watermark_alone_is_only_likely() {
        let ev = Evidence {
            watermark_verified: true,
            fingerprint_match: false,
            crosscheck_ok: false,
        };
        assert_eq!(
            classify(&ev),
            Confidence::Likely,
            "a watermark hit alone must never reach BOUND"
        );
    }

    #[test]
    fn fingerprint_without_crosscheck_is_likely() {
        let ev = Evidence {
            watermark_verified: false,
            fingerprint_match: true,
            crosscheck_ok: false,
        };
        assert_eq!(classify(&ev), Confidence::Likely);
    }

    #[test]
    fn no_evidence_is_review() {
        assert_eq!(classify(&Evidence::default()), Confidence::Review);
    }
}
