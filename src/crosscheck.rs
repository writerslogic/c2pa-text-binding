// SPDX-License-Identifier: MIT OR Apache-2.0

//! Content-keyed cross-check and confidence classification.
//!
//! A watermark hit routes to a *candidate* manifest but never establishes a
//! binding on its own — a routing tag can be transferred onto other content.
//! A candidate is only [`Confidence::Bound`] when a *durable* fingerprint
//! recomputed from the current text matches the manifest's stored fingerprint,
//! so a transferred tag is rejected. The [`crosscheck_tag`] anti-transfer
//! pointer binds a manifest to a `(repo_id, content_hash)` pair.
//!
//! # Empirical grounding of the tiers
//!
//! The tiers are not asserted; they follow the measured false-match rate (FMR)
//! of each algorithm at its registered threshold. On the n=200 all-pairs sweep
//! in `examples/threshold_sweep.rs` (39,800 unrelated document pairs, PAN'26):
//!
//! | algorithm | threshold | measured FMR | separation margin | tier role |
//! | --- | --- | --- | --- | --- |
//! | 41 simhash | Hamming ≤ 32 | 0 / 39,800 | +12 bits | durable → BOUND-eligible |
//! | 44 minhash | Jaccard ≥ 0.70 | 0 / 39,800 | n/a | durable → BOUND-eligible |
//! | 43 structural | Hamming ≤ 24 | 392 / 39,800 (1.0%) | **−16 bits** | corroborating only |
//!
//! The structural fingerprint's threshold sits *above* the nearest unrelated
//! distance (min 8 vs. threshold 24), so a structural match alone is ~1% likely
//! between unrelated documents. It therefore never lifts a candidate past
//! [`Confidence::Likely`]. BOUND requires a durable (41/44) match — measured
//! zero false matches — combined with the keyed crosscheck, which bounds
//! transfer cryptographically rather than statistically. Re-run the sweep to
//! reproduce these numbers on any corpus.

use crate::minhash::{self, MinHash};
use crate::simhash::{self, Fingerprint, Hash256};
use crate::soft_binding::{SoftBinding, ALG_FINGERPRINT, ALG_MINHASH, ALG_STRUCTURE};
use crate::structure;
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
///
/// The two fingerprint fields are split by measured false-match rate: only a
/// *durable* match (41 simhash / 44 minhash, measured FMR ~0) can establish
/// BOUND; a *structural* match (43, measured FMR ~1%) is corroborating and caps
/// at LIKELY. See the module-level table.
#[derive(Clone, Copy, Debug, Default)]
pub struct Evidence {
    /// The v2 watermark payload verified against the current content.
    pub watermark_verified: bool,
    /// A durable fingerprint (surface SimHash 41 or lexical MinHash 44) matched
    /// the manifest. Measured zero false matches at threshold — BOUND-eligible.
    pub durable_fingerprint_match: bool,
    /// The structural fingerprint (43) matched. ~1% false-match rate between
    /// unrelated documents, so this corroborates but never establishes BOUND.
    pub structural_match: bool,
    /// The anti-transfer cross-check tag matched.
    pub crosscheck_ok: bool,
}

/// Classify the evidence into a confidence tier.
///
/// [`Confidence::Bound`] requires a *durable* fingerprint match (41/44) plus the
/// cross-check — never a watermark hit, a structural match, or a bare cross-check
/// alone — so neither a tag transferred onto unrelated content nor a
/// coincidental structural collision can reach BOUND.
pub fn classify(ev: &Evidence) -> Confidence {
    if ev.durable_fingerprint_match && ev.crosscheck_ok {
        Confidence::Bound
    } else if ev.watermark_verified || ev.durable_fingerprint_match || ev.structural_match {
        Confidence::Likely
    } else {
        Confidence::Review
    }
}

/// Recompute the fingerprint named by a candidate `c2pa.soft-binding` assertion
/// from the current `text` and test it against the stored value(s) at that
/// algorithm's registered threshold.
///
/// This is the content half of the verify path: it re-derives the binding and
/// compares, so a candidate routed by a (transferable) watermark is only
/// believed when the current text actually reproduces the stored fingerprint.
/// Watermark verification and the [`crosscheck_tag`] check are supplied by the
/// caller (from [`crate::stego::extract`] and a recomputed tag) and folded in by
/// [`verify`].
///
/// Returns [`Evidence`] with the fingerprint fields set; watermark and
/// cross-check fields are left `false` for the caller to fill.
pub fn fingerprint_evidence(text: &str, candidate: &SoftBinding) -> Evidence {
    let mut ev = Evidence::default();
    match candidate.alg.as_str() {
        ALG_FINGERPRINT => {
            let current = Fingerprint::compute(text).whole;
            ev.durable_fingerprint_match = candidate
                .blocks
                .iter()
                .filter_map(|b| Hash256::from_hex(&b.value))
                .any(|stored| current.hamming(&stored) <= simhash::MATCH_THRESHOLD);
        }
        ALG_MINHASH => {
            if let Some(stored) = candidate
                .blocks
                .first()
                .and_then(|b| parse_minhash(&b.value))
            {
                let current = MinHash::compute(text);
                ev.durable_fingerprint_match = current.jaccard(&stored) >= minhash::MATCH_JACCARD
                    || current.shares_band(&stored);
            }
        }
        ALG_STRUCTURE => {
            if let Some(stored) = candidate
                .blocks
                .first()
                .and_then(|b| Hash256::from_hex(&b.value))
            {
                ev.structural_match = structure::matches(&structure::compute(text), &stored);
            }
        }
        // A watermark-type binding carries no recomputable fingerprint here; its
        // content proof is the extracted tag, folded in via `verify`.
        _ => {}
    }
    ev
}

/// Full verify: gather fingerprint evidence from `text` and a candidate
/// assertion, fold in the externally-computed watermark and cross-check results,
/// and classify into a confidence tier.
pub fn verify(
    text: &str,
    candidate: &SoftBinding,
    watermark_verified: bool,
    crosscheck_ok: bool,
) -> Confidence {
    let mut ev = fingerprint_evidence(text, candidate);
    ev.watermark_verified = watermark_verified;
    ev.crosscheck_ok = crosscheck_ok;
    classify(&ev)
}

/// Parse a stored MinHash signature: 128 big-endian `u64` words, hex-encoded.
fn parse_minhash(value_hex: &str) -> Option<MinHash> {
    let bytes = hex::decode(value_hex).ok()?;
    if bytes.len() != minhash::NUM_PERM * 8 {
        return None;
    }
    let mut sig = [0u64; minhash::NUM_PERM];
    for (word, chunk) in sig.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_be_bytes(chunk.try_into().expect("chunk is 8 bytes"));
    }
    Some(MinHash::from_signature(sig))
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
    fn bound_requires_durable_fingerprint_and_crosscheck() {
        let ev = Evidence {
            watermark_verified: true,
            durable_fingerprint_match: true,
            structural_match: true,
            crosscheck_ok: true,
        };
        assert_eq!(classify(&ev), Confidence::Bound);
    }

    #[test]
    fn watermark_alone_is_only_likely() {
        let ev = Evidence {
            watermark_verified: true,
            crosscheck_ok: false,
            ..Default::default()
        };
        assert_eq!(
            classify(&ev),
            Confidence::Likely,
            "a watermark hit alone must never reach BOUND"
        );
    }

    #[test]
    fn durable_fingerprint_without_crosscheck_is_likely() {
        let ev = Evidence {
            durable_fingerprint_match: true,
            crosscheck_ok: false,
            ..Default::default()
        };
        assert_eq!(classify(&ev), Confidence::Likely);
    }

    #[test]
    fn structural_match_never_reaches_bound() {
        // 43 has a measured ~1% false-match rate, so even with the crosscheck it
        // must cap at LIKELY — a coincidental structural collision plus a keyed
        // tag on transferred content must not read as BOUND.
        let ev = Evidence {
            structural_match: true,
            crosscheck_ok: true,
            ..Default::default()
        };
        assert_eq!(classify(&ev), Confidence::Likely);
    }

    #[test]
    fn no_evidence_is_review() {
        assert_eq!(classify(&Evidence::default()), Confidence::Review);
    }

    #[test]
    fn verify_recomputes_durable_fingerprint_from_text() {
        use crate::soft_binding;

        let text = "The principles of provenance require that a document's origin can be \
            recovered even after it has been copied, reformatted, or lightly edited, so a \
            manifest can be found again when the embedded one is stripped away.";
        let sb = soft_binding::from_fingerprint(&Fingerprint::compute(text));

        // Same text + crosscheck -> BOUND.
        assert_eq!(verify(text, &sb, false, true), Confidence::Bound);
        // Same text, no crosscheck -> LIKELY (fingerprint matched, tag unproven).
        assert_eq!(verify(text, &sb, false, false), Confidence::Likely);
        // Unrelated text -> the durable fingerprint does not match -> REVIEW,
        // even though the (transferable) crosscheck bit is set.
        let unrelated = "Chocolate chip cookies need flour, butter, sugar, eggs, and vanilla \
            before the oven ever reaches three hundred and fifty degrees for the bake.";
        assert_eq!(verify(unrelated, &sb, false, true), Confidence::Review);
    }

    #[test]
    fn verify_structural_candidate_caps_at_likely() {
        use crate::soft_binding;

        let text = "Provenance must survive editing. A soft binding derives a durable value \
            from the words themselves. When the embedded manifest is stripped, a resolver \
            recomputes the value and finds the manifest again.";
        let sb = soft_binding::from_structure(&structure::compute(text));
        // Even the exact same text through a structural candidate + crosscheck
        // stays LIKELY, because 43 is corroborating only.
        assert_eq!(verify(text, &sb, false, true), Confidence::Likely);
    }
}
