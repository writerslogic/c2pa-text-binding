// SPDX-License-Identifier: MIT OR Apache-2.0

//! Naive zero-width binary carrier.
//!
//! One bit per code point: `U+200B` = 0, `U+200C` = 1, eight bits per byte,
//! most-significant first, no framing beyond a magic and no error correction.
//! It shares the zero-width alphabet with [`crate::stego`] but omits the
//! Reed-Solomon coding, so the benchmark can attribute `stego`'s partial-loss
//! survival to the coding rather than the alphabet.

/// Bit symbols: index 0 = clear, index 1 = set.
const ZERO: char = '\u{200B}';
const ONE: char = '\u{200C}';

/// Carrier magic.
pub const MAGIC: [u8; 4] = *b"C2ZW";

/// Whether `c` is one of the two bit symbols.
pub fn is_bit(c: char) -> bool {
    c == ZERO || c == ONE
}

/// Encode `payload` as `magic || payload`, eight zero-width bits per byte.
pub fn encode(payload: &[u8]) -> String {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(payload);
    let mut out = String::with_capacity(bytes.len() * 8 * 3);
    for byte in bytes {
        for bit in (0..8).rev() {
            out.push(if (byte >> bit) & 1 == 1 { ONE } else { ZERO });
        }
    }
    out
}

/// Append a zero-width binary carrier for `payload` to the end of `text`.
pub fn embed(text: &str, payload: &[u8]) -> String {
    let mut s = String::with_capacity(text.len() + (MAGIC.len() + payload.len()) * 24);
    s.push_str(text);
    s.push_str(&encode(payload));
    s
}

/// Decode outcome, mirroring [`crate::vs::Decoded`] for uniform classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    None,
    Corrupt,
    Payload(Vec<u8>),
}

/// Recover a payload from the contiguous zero-width bit run in `text`.
pub fn extract(text: &str) -> Decoded {
    let bits: Vec<char> = text.chars().filter(|c| is_bit(*c)).collect();
    if bits.is_empty() {
        return Decoded::None;
    }
    if !bits.len().is_multiple_of(8) {
        return Decoded::Corrupt;
    }
    let bytes: Vec<u8> = bits
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .fold(0u8, |acc, &c| (acc << 1) | (c == ONE) as u8)
        })
        .collect();
    if bytes.len() >= MAGIC.len() && bytes[..MAGIC.len()] == MAGIC {
        Decoded::Payload(bytes[MAGIC.len()..].to_vec())
    } else {
        Decoded::Corrupt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_recovers_payload() {
        let payload = b"c2pa-manifest-01";
        let text = embed("A document body.", payload);
        assert_eq!(extract(&text), Decoded::Payload(payload.to_vec()));
    }

    #[test]
    fn eight_code_points_per_byte() {
        assert_eq!(encode(b"z").chars().count(), (MAGIC.len() + 1) * 8);
    }

    #[test]
    fn stripping_bits_yields_none() {
        let text = embed("hi", b"x");
        let stripped: String = text.chars().filter(|c| !is_bit(*c)).collect();
        assert_eq!(extract(&stripped), Decoded::None);
    }

    #[test]
    fn losing_one_bit_fails_safe() {
        let mut chars: Vec<char> = embed("hi", b"payload").chars().collect();
        chars.pop();
        let mangled: String = chars.into_iter().collect();
        assert_eq!(extract(&mangled), Decoded::Corrupt);
    }
}
