// SPDX-License-Identifier: MIT OR Apache-2.0

//! `com.writerslogic.text-fingerprint.1` — a durable 256-bit SimHash over the
//! normalized surface stream, plus overlapping window fingerprints so an
//! excerpt or truncated copy still matches. Embeds nothing in the text.
//!
//! Value: 32-byte SimHash, hex-encoded. Two values identify the same content
//! when their Hamming distance is at most 32 / 256 (12.5%).

use crate::normalize::canonical;
use blake2::{Blake2b512, Digest};
use std::collections::HashMap;

/// Fingerprint width in bits.
pub const FP_BITS: usize = 256;
/// Whole-document / window match threshold: Hamming distance in bits.
pub const MATCH_THRESHOLD: u32 = 32;
/// Window length in normalized characters.
pub const WINDOW_CHARS: usize = 512;
/// Window step (50% overlap).
pub const WINDOW_STEP: usize = 256;

/// A 256-bit locality-sensitive hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// Hamming distance in bits (0 = identical, 256 = opposite).
    pub fn hamming(&self, other: &Self) -> u32 {
        self.0
            .iter()
            .zip(other.0.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum()
    }

    /// Lowercase hex encoding of the 32 bytes.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from a 64-character hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(Hash256(out))
    }
}

/// BLAKE2b-256 (first 32 bytes of BLAKE2b-512) of arbitrary bytes.
pub(crate) fn blake2_256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Blake2b512::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// tf-weighted 256-bit SimHash over a bag of features, each a byte string with
/// an integer weight. Shared by the surface and structural fingerprints.
pub(crate) fn simhash_weighted<'a, I>(features: I) -> Hash256
where
    I: IntoIterator<Item = (&'a [u8], i64)>,
{
    let mut acc = [0i64; FP_BITS];
    for (bytes, weight) in features {
        let h = blake2_256(bytes);
        for (bit, slot) in acc.iter_mut().enumerate() {
            let set = (h[bit / 8] >> (7 - (bit % 8))) & 1 == 1;
            *slot += if set { weight } else { -weight };
        }
    }
    let mut out = [0u8; 32];
    for (bit, &count) in acc.iter().enumerate() {
        if count > 0 {
            out[bit / 8] |= 1 << (7 - (bit % 8));
        }
    }
    Hash256(out)
}

/// tf-weighted SimHash over overlapping character 4-grams of `chars`.
fn simhash_4grams(chars: &[char]) -> Hash256 {
    if chars.is_empty() {
        return Hash256([0u8; 32]);
    }
    let n = 4.min(chars.len());
    let mut counts: HashMap<String, i64> = HashMap::new();
    for gram in chars.windows(n) {
        let key: String = gram.iter().collect();
        *counts.entry(key).or_insert(0) += 1;
    }
    simhash_weighted(counts.iter().map(|(k, w)| (k.as_bytes(), *w)))
}

/// A window fingerprint scoped by its `(start, len)` over the normalized stream.
#[derive(Clone, Debug)]
pub struct WindowFp {
    pub start: usize,
    pub len: usize,
    pub hash: Hash256,
}

/// A whole-document fingerprint plus overlapping window fingerprints.
#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub whole: Hash256,
    pub windows: Vec<WindowFp>,
}

impl Fingerprint {
    /// Compute the fingerprint of `text`.
    pub fn compute(text: &str) -> Self {
        let norm = canonical(text);
        let chars: Vec<char> = norm.chars().collect();
        let whole = simhash_4grams(&chars);
        let mut windows = Vec::new();
        if chars.len() > WINDOW_CHARS {
            let mut start = 0;
            loop {
                let end = (start + WINDOW_CHARS).min(chars.len());
                windows.push(WindowFp {
                    start,
                    len: end - start,
                    hash: simhash_4grams(&chars[start..end]),
                });
                if end == chars.len() {
                    break;
                }
                start += WINDOW_STEP;
            }
        }
        Fingerprint { whole, windows }
    }

    /// The best (smallest) Hamming distance from `candidate`'s whole-document
    /// hash to this fingerprint's whole hash or any of its window hashes.
    pub fn best_distance(&self, candidate: &Hash256) -> u32 {
        let mut best = self.whole.hamming(candidate);
        for w in &self.windows {
            best = best.min(w.hash.hamming(candidate));
        }
        best
    }

    /// Whether `candidate`'s whole-document hash matches this fingerprint
    /// (whole or any window) within [`MATCH_THRESHOLD`].
    pub fn matches(&self, candidate: &Hash256) -> bool {
        self.best_distance(candidate) <= MATCH_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG: &str = "The principles of provenance require that a document's origin \
        can be recovered even after it has been copied, reformatted, or lightly edited. \
        A soft binding derives a durable value from the words themselves so that a \
        manifest can be found again when the embedded one is stripped away by a careless \
        copy-paste or an aggressive text pipeline that normalizes everything in sight.";

    #[test]
    fn identical_text_zero_distance() {
        let a = Fingerprint::compute(LONG);
        let b = Fingerprint::compute(LONG);
        assert_eq!(a.whole.hamming(&b.whole), 0);
    }

    #[test]
    fn reformatting_and_zero_width_survive() {
        let a = Fingerprint::compute(LONG);
        let reformatted = format!("  {}  ", LONG.to_uppercase().replace(' ', "\u{200B} "));
        let b = Fingerprint::compute(&reformatted);
        assert_eq!(
            a.whole.hamming(&b.whole),
            0,
            "case + whitespace + zero-width must not change the fingerprint"
        );
    }

    #[test]
    fn single_word_edit_stays_within_threshold() {
        let a = Fingerprint::compute(LONG);
        let edited = LONG.replacen("copied", "duplicated", 1);
        let b = Fingerprint::compute(&edited);
        let d = a.whole.hamming(&b.whole);
        assert!(
            d <= MATCH_THRESHOLD,
            "single-word edit distance {d} exceeded threshold"
        );
    }

    #[test]
    fn different_documents_diverge() {
        let a = Fingerprint::compute(LONG);
        let other = Fingerprint::compute(
            "Chocolate chip cookies require flour, sugar, butter, eggs, and vanilla; \
             preheat the oven to three hundred and fifty degrees before mixing anything.",
        );
        assert!(
            a.whole.hamming(&other.whole) > MATCH_THRESHOLD,
            "unrelated documents must exceed the match threshold"
        );
    }

    #[test]
    fn windows_present_for_long_text() {
        let big = LONG.repeat(4);
        let fp = Fingerprint::compute(&big);
        assert!(
            !fp.windows.is_empty(),
            "long text must produce window blocks"
        );
        assert!(fp.windows.iter().all(|w| w.len <= WINDOW_CHARS));
    }

    #[test]
    fn excerpt_matches_via_window() {
        let big = LONG.repeat(3);
        let fp = Fingerprint::compute(&big);
        // Take a middle excerpt of the source words.
        let excerpt: String = big.chars().skip(400).take(500).collect();
        let ex = Fingerprint::compute(&excerpt);
        assert!(
            fp.matches(&ex.whole),
            "an excerpt should match one of the window fingerprints"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let fp = Fingerprint::compute(LONG);
        let hex = fp.whole.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Hash256::from_hex(&hex), Some(fp.whole));
    }

    // Pinned test vector: fixed input -> fixed 256-bit value. Guards against
    // any change to normalization, the n-gram scheme, or the hash.
    #[test]
    fn vector_whole_fingerprint() {
        let fp = Fingerprint::compute("The quick brown fox jumps over the lazy dog.");
        assert_eq!(
            fp.whole.to_hex(),
            "aa53230a3df3561f2f6d00bdd84907a5b628d2c694a445656620152bcad0d274",
            "PIN: recompute and update this vector only on an intentional algorithm change"
        );
    }
}
