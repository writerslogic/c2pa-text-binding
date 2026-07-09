// SPDX-License-Identifier: MIT OR Apache-2.0

//! `com.writerslogic.zwc-watermark.2` — embeds a routing pointer plus a
//! content-binding HMAC tag as invisible zero-width characters at deterministic
//! word-boundary positions.
//!
//! Wire format (v2):
//!
//! * Alphabet `{U+200B=00, U+200C=01, U+200D=10, U+2060=11}` — 2 bits per
//!   symbol; U+FEFF is dropped (BOM hazard). Four symbols form one byte.
//! * Payload = `pointer` (fixed [`POINTER_LEN`] bytes) ‖ `tag`
//!   (`HMAC-SHA256(key, norm_hash ‖ pointer)` truncated to [`TAG_LEN`]).
//! * The payload is Reed-Solomon encoded into [`TOTAL_SHARDS`] one-byte shards
//!   ([`DATA_SHARDS`] data + [`PARITY_SHARDS`] parity). Each shard is written
//!   as a 4-symbol run at one word-gap selected by an HMAC-seeded Fisher-Yates
//!   shuffle. A gap whose run is missing or not exactly four valid symbols is a
//!   clean erasure, so extraction recovers from partial loss.
//!
//! Extraction is blind: `norm_hash` is recomputed from the de-watermarked text,
//! which reproduces the shuffle and verifies the tag. Content modification
//! changes `norm_hash` and invalidates the watermark by design.

use crate::error::Error;
use crate::normalize::canonical;
use hmac::{Hmac, Mac};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// v2 symbol alphabet: index 0..=3 maps to a 2-bit value.
pub const ALPHABET_V2: [char; 4] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}'];
/// v1 symbol alphabet (compat reads only); uses U+FEFF instead of U+2060.
pub const ALPHABET_V1: [char; 4] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'];

/// Routing pointer length in bytes (e.g. a truncated content-address / CID).
pub const POINTER_LEN: usize = 16;
/// Content-binding tag length in bytes.
pub const TAG_LEN: usize = 8;
/// Data shards = payload length in bytes.
pub const DATA_SHARDS: usize = POINTER_LEN + TAG_LEN;
/// Parity shards (recover up to this many lost shards).
pub const PARITY_SHARDS: usize = DATA_SHARDS;
/// Total shards, one per used word-gap.
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;
/// Symbols per shard (one byte = four 2-bit symbols).
const SYMBOLS_PER_SHARD: usize = 4;

/// A recovered watermark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovered {
    /// The routing pointer bytes.
    pub pointer: [u8; POINTER_LEN],
    /// Whether the content-binding tag verified against the current text.
    pub tag_verified: bool,
    /// Number of shards that had to be reconstructed by the erasure code.
    pub shards_recovered: usize,
}

/// SHA-256 of the surface-canonical stream — the blind-recoverable content hash.
pub fn content_hash(text: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical(text).as_bytes());
    h.finalize().into()
}

/// Embed a watermark carrying `pointer` into `text`, bound to the content by
/// `key`. `pointer` is right-truncated / zero-padded to [`POINTER_LEN`].
///
/// Returns [`Error::ContentTooShort`] if the text has fewer than
/// [`TOTAL_SHARDS`] word-gaps to place the coded payload.
pub fn embed(text: &str, key: &[u8], pointer: &[u8]) -> Result<String, Error> {
    let mut ptr = [0u8; POINTER_LEN];
    let n = pointer.len().min(POINTER_LEN);
    ptr[..n].copy_from_slice(&pointer[..n]);

    let norm_hash = content_hash(text);
    let tag = binding_tag(key, &norm_hash, &ptr);

    let mut payload = Vec::with_capacity(DATA_SHARDS);
    payload.extend_from_slice(&ptr);
    payload.extend_from_slice(&tag);

    let shards = rs_encode(&payload)?;

    let gaps = word_gaps(text);
    if gaps.len() < TOTAL_SHARDS {
        return Err(Error::ContentTooShort);
    }
    let order = fisher_yates(&gaps, key, &norm_hash);

    // Map each shard to a gap byte-offset; assemble the sorted insertion list.
    let mut insertions: Vec<(usize, [char; 4])> = Vec::with_capacity(TOTAL_SHARDS);
    for (shard_idx, &gap_rank) in order.iter().take(TOTAL_SHARDS).enumerate() {
        let offset = gaps[gap_rank];
        insertions.push((offset, byte_to_run(shards[shard_idx])));
    }
    insertions.sort_by_key(|(off, _)| *off);

    let mut out = String::with_capacity(text.len() + TOTAL_SHARDS * SYMBOLS_PER_SHARD * 3);
    let mut ins_iter = insertions.iter().peekable();
    for (idx, c) in text.char_indices() {
        while let Some((off, run)) = ins_iter.peek() {
            if *off == idx {
                out.extend(run.iter());
                ins_iter.next();
            } else {
                break;
            }
        }
        out.push(c);
    }
    // Any insertion at end-of-text offset.
    let end = text.len();
    for (off, run) in ins_iter {
        debug_assert_eq!(*off, end);
        out.extend(run.iter());
    }

    Ok(out)
}

/// Blind-extract and verify a v2 watermark from `text`.
pub fn extract(text: &str, key: &[u8]) -> Result<Recovered, Error> {
    let runs = read_runs(text, &ALPHABET_V2);
    let clean = strip_zero_width(text);
    let norm_hash = content_hash(&clean);

    let gaps = word_gaps(&clean);
    if gaps.len() < TOTAL_SHARDS {
        return Err(Error::ContentTooShort);
    }
    let order = fisher_yates(&gaps, key, &norm_hash);

    // For each shard, read the run at its assigned gap; missing/malformed -> erasure.
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    let mut recovered = 0usize;
    for (shard_idx, &gap_rank) in order.iter().take(TOTAL_SHARDS).enumerate() {
        match runs.get(&gap_rank) {
            Some(symbols) if symbols.len() == SYMBOLS_PER_SHARD => {
                shards[shard_idx] = Some(vec![run_to_byte(symbols)]);
            }
            _ => {
                recovered += 1;
            }
        }
    }
    if TOTAL_SHARDS - recovered < DATA_SHARDS {
        return Err(Error::WatermarkUnrecoverable);
    }

    let payload = rs_reconstruct(shards)?;
    let mut ptr = [0u8; POINTER_LEN];
    ptr.copy_from_slice(&payload[..POINTER_LEN]);
    let tag = &payload[POINTER_LEN..DATA_SHARDS];

    let expected = binding_tag(key, &norm_hash, &ptr);
    let tag_verified = ct_eq(tag, &expected);

    Ok(Recovered {
        pointer: ptr,
        tag_verified,
        shards_recovered: recovered,
    })
}

/// Read the raw symbol runs of a v1-alphabet watermark, keyed by gap rank.
/// Compat helper: byte-level interop with the deployed v1 endpoint is not
/// verified here (no accessible v1 reference), so this decodes symbols only.
pub fn read_runs_v1(text: &str) -> std::collections::BTreeMap<usize, Vec<u8>> {
    read_runs(text, &ALPHABET_V1)
}

// --- internals ---------------------------------------------------------------

fn binding_tag(key: &[u8], norm_hash: &[u8; 32], pointer: &[u8; POINTER_LEN]) -> [u8; TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(norm_hash);
    mac.update(pointer);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

fn rs_encode(payload: &[u8]) -> Result<Vec<u8>, Error> {
    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|e| Error::Coding(format!("{e:?}")))?;
    let mut shards: Vec<Vec<u8>> = payload.iter().map(|&b| vec![b]).collect();
    shards.resize(TOTAL_SHARDS, vec![0u8]);
    rs.encode(&mut shards)
        .map_err(|e| Error::Coding(format!("{e:?}")))?;
    Ok(shards.into_iter().map(|s| s[0]).collect())
}

fn rs_reconstruct(mut shards: Vec<Option<Vec<u8>>>) -> Result<Vec<u8>, Error> {
    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|e| Error::Coding(format!("{e:?}")))?;
    rs.reconstruct(&mut shards)
        .map_err(|e| Error::Coding(format!("{e:?}")))?;
    let mut out = Vec::with_capacity(DATA_SHARDS);
    for shard in shards.into_iter().take(DATA_SHARDS) {
        let bytes = shard.ok_or(Error::WatermarkUnrecoverable)?;
        out.push(bytes[0]);
    }
    Ok(out)
}

/// Byte-offset word gaps: the position immediately after each maximal run of
/// non-whitespace characters. Zero-width characters already present are treated
/// as whitespace so gap enumeration is identical before and after embedding.
fn word_gaps(text: &str) -> Vec<usize> {
    let mut gaps = Vec::new();
    let mut in_word = false;
    let mut last_word_end = 0usize;
    for (idx, c) in text.char_indices() {
        let is_sep = c.is_whitespace() || crate::normalize::is_zero_width_format(c);
        if is_sep {
            if in_word {
                gaps.push(last_word_end);
                in_word = false;
            }
        } else {
            in_word = true;
            last_word_end = idx + c.len_utf8();
        }
    }
    if in_word {
        gaps.push(last_word_end);
    }
    gaps
}

/// Read zero-width symbol runs from `text`, keyed by the rank of the preceding
/// word (0-based), using `alphabet` for symbol values.
fn read_runs(text: &str, alphabet: &[char; 4]) -> std::collections::BTreeMap<usize, Vec<u8>> {
    let mut runs: std::collections::BTreeMap<usize, Vec<u8>> = std::collections::BTreeMap::new();
    let mut word_rank = 0usize;
    let mut in_word = false;
    let mut counted_word = false;
    for c in text.chars() {
        if let Some(sym) = symbol_value(c, alphabet) {
            // A run belongs to the most recently completed word.
            if counted_word {
                runs.entry(word_rank - 1).or_default().push(sym);
            }
        } else if c.is_whitespace() {
            in_word = false;
        } else {
            if !in_word {
                word_rank += 1;
                counted_word = true;
            }
            in_word = true;
        }
    }
    runs
}

fn symbol_value(c: char, alphabet: &[char; 4]) -> Option<u8> {
    alphabet.iter().position(|&a| a == c).map(|p| p as u8)
}

fn byte_to_run(byte: u8) -> [char; 4] {
    [
        ALPHABET_V2[((byte >> 6) & 0b11) as usize],
        ALPHABET_V2[((byte >> 4) & 0b11) as usize],
        ALPHABET_V2[((byte >> 2) & 0b11) as usize],
        ALPHABET_V2[(byte & 0b11) as usize],
    ]
}

fn run_to_byte(symbols: &[u8]) -> u8 {
    (symbols[0] << 6) | (symbols[1] << 4) | (symbols[2] << 2) | symbols[3]
}

fn strip_zero_width(text: &str) -> String {
    text.chars()
        .filter(|&c| !crate::normalize::is_zero_width_format(c))
        .collect()
}

/// HMAC-seeded Fisher-Yates permutation of `0..gaps.len()`.
fn fisher_yates(gaps: &[usize], key: &[u8], norm_hash: &[u8; 32]) -> Vec<usize> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"zwc-watermark-v2-placement");
    mac.update(norm_hash);
    let seed = mac.finalize().into_bytes();
    let mut state = u64::from_le_bytes(seed[..8].try_into().expect("32-byte HMAC output"));
    if state == 0 {
        state = 0x9E37_79B9_7F4A_7C15;
    }

    let mut perm: Vec<usize> = (0..gaps.len()).collect();
    for i in (1..perm.len()).rev() {
        let j = (next_rand(&mut state) % (i as u64 + 1)) as usize;
        perm.swap(i, j);
    }
    perm
}

/// xorshift64* PRNG step — deterministic across platforms.
fn next_rand(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// Constant-time byte-slice equality for the tag comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"writerslogic-zwc-protocol-key-v2";
    // ~60 words -> enough gaps for the 48-shard payload.
    const TEXT: &str = "Provenance for text must survive the ordinary journey of a copied \
        passage across editors and pipelines that reflow and re encode everything they touch \
        without asking, so a routing pointer is woven invisibly into the spaces between the \
        words themselves and recovered later by any reader who holds the shared protocol key \
        and recomputes the very same placement from the normalized content of the document.";

    fn pointer() -> Vec<u8> {
        (0..POINTER_LEN as u8).collect()
    }

    #[test]
    fn roundtrip_clean() {
        let marked = embed(TEXT, KEY, &pointer()).unwrap();
        // The watermark is invisible: stripping zero-width chars restores the text.
        assert_eq!(strip_zero_width(&marked), TEXT);
        let rec = extract(&marked, KEY).unwrap();
        assert_eq!(&rec.pointer[..], &pointer()[..]);
        assert!(rec.tag_verified);
        assert_eq!(rec.shards_recovered, 0);
    }

    #[test]
    fn survives_partial_strip() {
        let marked = embed(TEXT, KEY, &pointer()).unwrap();
        // Realistic partial loss: whole zero-width runs vanish (run-collapse or
        // region re-encoding). Drop one in every three runs — within the
        // rate-1/2 code's erasure budget.
        let mut damaged = String::with_capacity(marked.len());
        let mut run_index = 0usize;
        let mut in_run = false;
        for c in marked.chars() {
            if crate::normalize::is_zero_width_format(c) {
                if !in_run {
                    in_run = true;
                    run_index += 1;
                }
                if !run_index.is_multiple_of(3) {
                    damaged.push(c);
                }
            } else {
                in_run = false;
                damaged.push(c);
            }
        }
        let rec = extract(&damaged, KEY).unwrap();
        assert_eq!(
            &rec.pointer[..],
            &pointer()[..],
            "RS must recover the pointer"
        );
        assert!(rec.tag_verified);
        assert!(
            rec.shards_recovered > 0,
            "some shards should have been erased"
        );
    }

    #[test]
    fn content_modification_breaks_tag() {
        let marked = embed(TEXT, KEY, &pointer()).unwrap();
        // Edit the visible content; the placement reseeds and the tag fails.
        let edited = marked.replacen("Provenance", "Ownership", 1);
        // Either the pointer no longer recovers, or the tag fails to verify.
        if let Ok(rec) = extract(&edited, KEY) {
            assert!(!rec.tag_verified, "modified content must not verify")
        }
    }

    #[test]
    fn wrong_key_does_not_verify() {
        let marked = embed(TEXT, KEY, &pointer()).unwrap();
        if let Ok(rec) = extract(&marked, b"a-different-protocol-key-entirely!!") {
            assert!(!rec.tag_verified)
        }
    }

    #[test]
    fn too_short_is_rejected() {
        let err = embed("only a few words here", KEY, &pointer()).unwrap_err();
        assert_eq!(err, Error::ContentTooShort);
    }

    #[test]
    fn byte_run_roundtrip() {
        for byte in [0u8, 1, 42, 0xAB, 0xFF] {
            let run = byte_to_run(byte);
            let syms: Vec<u8> = run
                .iter()
                .map(|&c| symbol_value(c, &ALPHABET_V2).unwrap())
                .collect();
            assert_eq!(run_to_byte(&syms), byte);
        }
    }

    #[test]
    fn v2_alphabet_excludes_bom() {
        assert!(!ALPHABET_V2.contains(&'\u{FEFF}'));
        assert!(ALPHABET_V2.contains(&'\u{2060}'));
    }
}
