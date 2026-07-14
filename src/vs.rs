// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unicode variation-selector transport (C2PA Appendix A.8).
//!
//! Encodes bytes as a run of Unicode variation selectors so a payload rides
//! invisibly in text. Faithful to the published A.8 `C2PATextManifestWrapper`
//! (`U+FEFF` marker, then `magic` + `version` + big-endian `length` + payload),
//! so transport-survivability results reflect the deployed format rather than a
//! stand-in. Distinct from [`crate::stego`], which is the zero-width
//! soft-binding watermark; this is the hard-binding carrier.
//!
//! The point of this module is measurement: [`extract`] reports not just the
//! recovered payload but whether a mangled carrier fails *safe* (rejected) or
//! *unsafe* (decodes to the wrong bytes).

use sha2::{Digest, Sha256};

/// Wrapper identifier, `"C2PATXT\0"`.
pub const MAGIC: [u8; 8] = *b"C2PATXT\0";
/// Wrapper format version defined by A.8.
pub const VERSION: u8 = 1;
/// Version 2 adds a truncated-SHA-256 integrity checksum over the header and
/// payload, so a corrupted wrapper fails safe (rejected) rather than decoding to
/// a wrong payload. The frame is otherwise identical to v1.
pub const VERSION_V2: u8 = 2;
/// Zero-Width No-Break Space that marks the start of a wrapper.
pub const MARKER: char = '\u{FEFF}';

/// Header length: `magic` (8) + `version` (1) + big-endian `length` (4).
const HEADER: usize = 13;
/// Trailing integrity checksum length for v2 (truncated SHA-256).
const CHECKSUM_LEN: usize = 4;

/// Map a byte to its variation selector (A.8 `byteToVariationSelector`).
pub fn byte_to_vs(b: u8) -> char {
    let cp = if b <= 15 {
        0xFE00 + b as u32
    } else {
        0xE0100 + (b as u32 - 16)
    };
    char::from_u32(cp).expect("variation-selector code points are valid scalars")
}

/// Map a variation selector back to its byte, or `None` if `c` is not one
/// (A.8 `variationSelectorToByte`).
pub fn vs_to_byte(c: char) -> Option<u8> {
    match c as u32 {
        cp @ 0xFE00..=0xFE0F => Some((cp - 0xFE00) as u8),
        cp @ 0xE0100..=0xE01EF => Some((cp - 0xE0100 + 16) as u8),
        _ => None,
    }
}

/// Whether `c` is a variation selector usable by this codec.
pub fn is_vs(c: char) -> bool {
    vs_to_byte(c).is_some()
}

/// Marker followed by the variation-selector encoding of `bytes`.
fn carry(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(1 + bytes.len());
    out.push(MARKER);
    out.extend(bytes.iter().map(|&b| byte_to_vs(b)));
    out
}

/// Encode `payload` as a complete A.8 v1 wrapper: `U+FEFF` marker followed by
/// the variation-selector encoding of `magic + version + length + payload`.
pub fn encode(payload: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    carry(&bytes)
}

/// Encode `payload` as a v2 wrapper: the v1 frame (`magic + version 2 + length +
/// payload`) followed by a truncated SHA-256 checksum over those bytes.
pub fn encode_v2(payload: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(HEADER + payload.len() + CHECKSUM_LEN);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION_V2);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum[..CHECKSUM_LEN]);
    carry(&bytes)
}

/// Append a v1 wrapper carrying `payload` to the end of `text`, per A.8
/// placement.
pub fn embed(text: &str, payload: &[u8]) -> String {
    let mut s = String::with_capacity(text.len() + 4 * (HEADER + payload.len()) + 3);
    s.push_str(text);
    s.push_str(&encode(payload));
    s
}

/// Append a v2 wrapper carrying `payload` to the end of `text`.
pub fn embed_v2(text: &str, payload: &[u8]) -> String {
    let mut s = String::with_capacity(text.len() + 4 * (HEADER + payload.len() + CHECKSUM_LEN) + 3);
    s.push_str(text);
    s.push_str(&encode_v2(payload));
    s
}

/// Outcome of decoding a text asset, carrying the fail-safety distinction the
/// survivability harness classifies on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// No wrapper could be located (marker absent, or no run matched `magic`).
    None,
    /// A wrapper was detected (`magic` matched) but its structure did not
    /// decode — the carrier was mangled and the codec rejected it (fail-safe).
    Corrupt,
    /// A wrapper decoded to this payload. The caller compares it against the
    /// original to separate `intact` from a fail-*unsafe* wrong decode.
    Payload(Vec<u8>),
}

/// Locate and decode the first valid `C2PATextManifestWrapper` in `text`.
///
/// Scans for a `U+FEFF` marker followed by a contiguous variation-selector run
/// whose leading bytes match [`MAGIC`]. A run that matches the magic but is
/// truncated or length-inconsistent yields [`Decoded::Corrupt`] rather than
/// guessing at a payload.
pub fn extract(text: &str) -> Decoded {
    let chars: Vec<char> = text.chars().collect();
    let mut saw_magic = false;

    let mut i = 0;
    while i < chars.len() {
        if chars[i] != MARKER {
            i += 1;
            continue;
        }
        // Decode the contiguous variation-selector run after the marker.
        let mut run = Vec::new();
        let mut j = i + 1;
        while j < chars.len() {
            match vs_to_byte(chars[j]) {
                Some(b) => run.push(b),
                None => break,
            }
            j += 1;
        }

        if run.len() > MAGIC.len() && run[..MAGIC.len()] == MAGIC {
            saw_magic = true;
            match run[MAGIC.len()] {
                VERSION if run.len() >= HEADER => {
                    let len = u32::from_be_bytes([run[9], run[10], run[11], run[12]]) as usize;
                    if run.len() >= HEADER + len {
                        return Decoded::Payload(run[HEADER..HEADER + len].to_vec());
                    }
                }
                VERSION_V2 if run.len() >= HEADER => {
                    let len = u32::from_be_bytes([run[9], run[10], run[11], run[12]]) as usize;
                    let end = HEADER + len;
                    if run.len() >= end + CHECKSUM_LEN {
                        let expected = Sha256::digest(&run[..end]);
                        if run[end..end + CHECKSUM_LEN] == expected[..CHECKSUM_LEN] {
                            return Decoded::Payload(run[HEADER..end].to_vec());
                        }
                    }
                }
                _ => {}
            }
        }
        i = j.max(i + 1);
    }

    if saw_magic {
        Decoded::Corrupt
    } else {
        Decoded::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_mapping_matches_spec_vectors() {
        assert_eq!(byte_to_vs(0x00), '\u{FE00}');
        assert_eq!(byte_to_vs(0x0F), '\u{FE0F}');
        assert_eq!(byte_to_vs(0x10), '\u{E0100}');
        assert_eq!(byte_to_vs(0xFF), '\u{E01EF}');
        for b in 0u8..=255 {
            assert_eq!(vs_to_byte(byte_to_vs(b)), Some(b));
        }
    }

    #[test]
    fn magic_encodes_to_expected_code_points() {
        let seq: Vec<char> = MAGIC.iter().map(|&b| byte_to_vs(b)).collect();
        let expected = [
            '\u{E0133}',
            '\u{E0122}',
            '\u{E0140}',
            '\u{E0131}',
            '\u{E0144}',
            '\u{E0148}',
            '\u{E0144}',
            '\u{FE00}',
        ];
        assert_eq!(seq, expected);
    }

    #[test]
    fn round_trip_recovers_payload() {
        let payload = b"https://fabrikam.com/m/a1b2c3.c2pa";
        let text = embed("The quick brown fox.", payload);
        assert_eq!(extract(&text), Decoded::Payload(payload.to_vec()));
    }

    #[test]
    fn stripping_the_run_yields_none() {
        let text = embed("hello", b"x");
        let stripped: String = text
            .chars()
            .filter(|c| !is_vs(*c) && *c != MARKER)
            .collect();
        assert_eq!(extract(&stripped), Decoded::None);
    }

    #[test]
    fn truncated_run_fails_safe_not_wrong() {
        let text = embed("hello", b"abcdefghij");
        // Drop the last few carrier code points: magic still matches, body short.
        let mut chars: Vec<char> = text.chars().collect();
        chars.truncate(chars.len() - 4);
        let mangled: String = chars.into_iter().collect();
        assert_eq!(extract(&mangled), Decoded::Corrupt);
    }

    #[test]
    fn v2_round_trips_with_checksum() {
        let payload = b"https://fabrikam.com/m/a1b2c3.c2pa";
        assert_eq!(
            extract(&embed_v2("Doc.", payload)),
            Decoded::Payload(payload.to_vec())
        );
    }

    #[test]
    fn v2_checksum_rejects_corruption_fail_safe() {
        // Corrupt a payload code point: the checksum no longer matches, so extract
        // rejects rather than returning a wrong payload (unlike v1).
        let payload = b"AAAAAAAAAAAAAAAA".to_vec();
        let mut chars: Vec<char> = encode_v2(&payload).chars().collect();
        let i = 1 + MAGIC.len() + 1 + 4 + 2; // marker + magic + version + length, into payload
        let b = vs_to_byte(chars[i]).expect("payload code point");
        chars[i] = byte_to_vs(b ^ 0xFF);
        let mangled: String = chars.into_iter().collect();
        assert_eq!(extract(&mangled), Decoded::Corrupt);
    }
}
