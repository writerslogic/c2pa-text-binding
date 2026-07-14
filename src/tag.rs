// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unicode Tags carrier (the documented "ASCII smuggling" primitive).
//!
//! The Tags block (U+E0000-U+E007F) has a code point for each ASCII value:
//! `U+E0000 + b`. Arbitrary bytes are hex-encoded to ASCII first, so one input
//! byte costs two tag code points. Included purely as a comparison method for
//! the survivability benchmark; tag characters are called out as having no
//! legitimate use in C2PA text fields, so this is a carrier under study, not a
//! recommended one.

/// Carrier magic, hex-encoded and tag-mapped like the rest of the payload.
pub const MAGIC: [u8; 4] = *b"C2TG";

/// Map an ASCII byte (0x00-0x7F) to its tag code point.
fn ascii_to_tag(b: u8) -> Option<char> {
    (b <= 0x7F).then(|| char::from_u32(0xE0000 + b as u32).expect("tag code points are valid"))
}

/// Map a tag code point back to its ASCII byte, or `None` if `c` is not one.
pub fn tag_to_ascii(c: char) -> Option<u8> {
    match c as u32 {
        cp @ 0xE0000..=0xE007F => Some((cp - 0xE0000) as u8),
        _ => None,
    }
}

/// Whether `c` is a tag character.
pub fn is_tag(c: char) -> bool {
    tag_to_ascii(c).is_some()
}

/// Encode `payload` as a tag-character run: `hex(magic || payload)`, each hex
/// digit carried as its tag code point.
pub fn encode(payload: &[u8]) -> String {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(payload);
    hex::encode(bytes)
        .bytes()
        .filter_map(ascii_to_tag)
        .collect()
}

/// Append a tag-character carrier for `payload` to the end of `text`.
pub fn embed(text: &str, payload: &[u8]) -> String {
    let mut s = String::with_capacity(text.len() + text.len());
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

/// Recover a payload from the contiguous tag-character run in `text`.
pub fn extract(text: &str) -> Decoded {
    let ascii: Vec<u8> = text.chars().filter_map(tag_to_ascii).collect();
    if ascii.is_empty() {
        return Decoded::None;
    }
    match hex::decode(&ascii) {
        Ok(bytes) if bytes.len() >= MAGIC.len() && bytes[..MAGIC.len()] == MAGIC => {
            Decoded::Payload(bytes[MAGIC.len()..].to_vec())
        }
        _ => Decoded::Corrupt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_recovers_payload() {
        let payload = b"https://fabrikam.com/m/a1b2c3.c2pa";
        let text = embed("A short document.", payload);
        assert_eq!(extract(&text), Decoded::Payload(payload.to_vec()));
    }

    #[test]
    fn two_tag_code_points_per_byte() {
        // hex doubles the byte count; magic(4) + payload(3) = 7 bytes -> 14 tags.
        assert_eq!(encode(b"abc").chars().count(), (MAGIC.len() + 3) * 2);
    }

    #[test]
    fn stripping_tags_yields_none() {
        let text = embed("hi", b"x");
        let stripped: String = text.chars().filter(|c| !is_tag(*c)).collect();
        assert_eq!(extract(&stripped), Decoded::None);
    }

    #[test]
    fn odd_length_run_fails_safe() {
        let mut chars: Vec<char> = embed("hi", b"payload").chars().collect();
        chars.pop(); // one hex nibble lost -> odd length -> not decodable
        let mangled: String = chars.into_iter().collect();
        assert_eq!(extract(&mangled), Decoded::Corrupt);
    }
}
