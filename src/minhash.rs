// SPDX-License-Identifier: MIT OR Apache-2.0

//! `com.writerslogic.text-minhash.1` — MinHash-128 over word 5-gram shingles
//! for excerpt and quotation matching. Estimates Jaccard set overlap; two
//! texts are treated as the same or overlapping content at Jaccard >= 0.70.
//! 32 bands x 4 rows of LSH provide sublinear lookup keys. Deterministic and
//! interoperable with ISO 24138 (ISCC) Text-Code semantics.

use crate::normalize::words;

/// Number of MinHash permutations.
pub const NUM_PERM: usize = 128;
/// LSH bands.
pub const BANDS: usize = 32;
/// Rows per band (`BANDS * ROWS == NUM_PERM`).
pub const ROWS: usize = 4;
/// Word shingle size.
pub const SHINGLE_K: usize = 5;
/// Match threshold on estimated Jaccard similarity.
pub const MATCH_JACCARD: f64 = 0.70;

/// Mersenne prime 2^61 - 1, the modulus for the affine permutation family.
const MERSENNE_61: u64 = (1 << 61) - 1;
/// Fixed seed for the permutation family, pinned so all implementations agree.
const PERM_SEED: u64 = 0x0123_4567_89AB_CDEF;

/// A MinHash signature plus its LSH band hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinHash {
    pub sig: [u64; NUM_PERM],
    pub bands: [u64; BANDS],
    pub shingle_count: usize,
}

/// SplitMix64 step — used only to derive the fixed permutation parameters.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The pinned `(a, b)` affine permutation parameters: h -> (a*h + b) mod p.
fn permutation_params() -> ([u64; NUM_PERM], [u64; NUM_PERM]) {
    let mut state = PERM_SEED;
    let mut a = [0u64; NUM_PERM];
    let mut b = [0u64; NUM_PERM];
    for i in 0..NUM_PERM {
        // a in [1, p-1] so the permutation is a bijection; b in [0, p-1].
        a[i] = (splitmix64(&mut state) % (MERSENNE_61 - 1)) + 1;
        b[i] = splitmix64(&mut state) % MERSENNE_61;
    }
    (a, b)
}

/// FNV-1a 64-bit base hash of a shingle, reduced into the Mersenne field.
fn base_hash(shingle: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &byte in shingle.as_bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(PRIME);
    }
    h % MERSENNE_61
}

/// FNV-1a 64-bit over the little-endian bytes of a band's rows.
fn band_hash(rows: &[u64]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &v in rows {
        for byte in v.to_le_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(PRIME);
        }
    }
    h
}

impl MinHash {
    /// Compute the MinHash signature of `text`.
    pub fn compute(text: &str) -> Self {
        let toks = words(text);
        let shingles = shingles(&toks);
        let (a, b) = permutation_params();
        let mut sig = [u64::MAX; NUM_PERM];
        for s in &shingles {
            let h = base_hash(s);
            for i in 0..NUM_PERM {
                let v = mul_mod(a[i], h).wrapping_add(b[i]) % MERSENNE_61;
                if v < sig[i] {
                    sig[i] = v;
                }
            }
        }
        // Empty input -> all-zero signature (deterministic, never matches real content).
        if shingles.is_empty() {
            sig = [0u64; NUM_PERM];
        }
        let mut bands = [0u64; BANDS];
        for (band, slot) in bands.iter_mut().enumerate() {
            let start = band * ROWS;
            *slot = band_hash(&sig[start..start + ROWS]);
        }
        MinHash {
            sig,
            bands,
            shingle_count: shingles.len(),
        }
    }

    /// Estimated Jaccard similarity: the fraction of equal signature positions.
    pub fn jaccard(&self, other: &Self) -> f64 {
        let equal = self
            .sig
            .iter()
            .zip(other.sig.iter())
            .filter(|(x, y)| x == y)
            .count();
        equal as f64 / NUM_PERM as f64
    }

    /// Whether the two texts share at least one LSH band (candidate for match).
    pub fn shares_band(&self, other: &Self) -> bool {
        self.bands.iter().any(|x| other.bands.contains(x))
    }

    /// Whether the two texts are the same or overlapping content
    /// (estimated Jaccard >= [`MATCH_JACCARD`]).
    pub fn matches(&self, other: &Self) -> bool {
        self.jaccard(other) >= MATCH_JACCARD
    }
}

/// Word 5-gram shingles. Texts shorter than `SHINGLE_K` words yield a single
/// shingle over all their words so short quotations still produce a signature.
fn shingles(toks: &[String]) -> Vec<String> {
    if toks.is_empty() {
        return Vec::new();
    }
    if toks.len() < SHINGLE_K {
        return vec![toks.join(" ")];
    }
    toks.windows(SHINGLE_K).map(|w| w.join(" ")).collect()
}

/// 64-bit modular multiply mod 2^61-1 without overflow, via 128-bit widening.
fn mul_mod(x: u64, y: u64) -> u64 {
    ((x as u128 * y as u128) % MERSENNE_61 as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "the honest limit is that text which is both heavily paraphrased and \
        retyped defeats every layer except an approximate semantic match while everything \
        short of that degrades gracefully across the fingerprint family of algorithms";

    #[test]
    fn identical_text_jaccard_one() {
        let a = MinHash::compute(SRC);
        let b = MinHash::compute(SRC);
        assert_eq!(a.jaccard(&b), 1.0);
        assert_eq!(a, b);
    }

    #[test]
    fn near_duplicate_shares_band() {
        // Whole-document MinHash resolves near-duplicates and large overlaps;
        // small-excerpt matching is the job of per-segment signatures. A
        // one-word edit keeps Jaccard well above the 0.70 threshold, so an LSH
        // band must collide.
        let a = MinHash::compute(SRC);
        let b = MinHash::compute(&SRC.replacen("gracefully", "smoothly", 1));
        assert!(
            a.matches(&b),
            "near-duplicate must match at Jaccard >= 0.70"
        );
        assert!(
            a.shares_band(&b),
            "near-duplicates should share an LSH band"
        );
    }

    #[test]
    fn reordering_and_deletion_stay_high() {
        let a = MinHash::compute(SRC);
        // Delete a clause and reformat; most 5-gram shingles survive.
        let edited = SRC.replace("heavily paraphrased and ", "");
        let b = MinHash::compute(&edited);
        assert!(
            a.jaccard(&b) > 0.5,
            "minor deletion should keep Jaccard high"
        );
    }

    #[test]
    fn unrelated_text_low_jaccard() {
        let a = MinHash::compute(SRC);
        let b = MinHash::compute(
            "a recipe for shortbread needs only butter sugar and flour combined by hand \
             then chilled and baked until the edges are barely golden at the rim",
        );
        assert!(a.jaccard(&b) < MATCH_JACCARD);
        assert!(!a.matches(&b));
    }

    #[test]
    fn casefold_and_zero_width_ignored() {
        let a = MinHash::compute(SRC);
        let b = MinHash::compute(&SRC.to_uppercase().replace(' ', "\u{200B} "));
        assert_eq!(a, b);
    }

    #[test]
    fn bands_derived_from_signature() {
        let a = MinHash::compute(SRC);
        assert_eq!(a.bands.len(), BANDS);
        assert_eq!(BANDS * ROWS, NUM_PERM);
    }

    // Pinned test vector: first four signature values for a fixed input.
    #[test]
    fn vector_signature_prefix() {
        let mh = MinHash::compute("the quick brown fox jumps over the lazy dog again");
        assert_eq!(
            &mh.sig[..4],
            &[
                111552349047830145,
                188277353147072251,
                213821157973154889,
                100998052165424870
            ],
            "PIN: recompute and update on any intentional algorithm change"
        );
    }
}
