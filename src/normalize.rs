// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical normalization shared by the text soft-binding family.
//!
//! Two streams are produced from the same source text:
//!
//! * [`canonical`] — the *surface* stream used by `text-fingerprint.1` and
//!   `text-minhash.1`: NFC, strip zero-width/format characters, lowercase,
//!   collapse whitespace, strip punctuation. Reformatting, re-encoding, case
//!   and whitespace edits, and zero-width injection leave it unchanged.
//! * [`structural`] — the *structure-preserving* stream used by
//!   `text-structure.1`: NFC and strip zero-width/format only, keeping
//!   sentence/paragraph boundaries and punctuation, which are the signal.

use unicode_normalization::UnicodeNormalization;

/// Zero-width and format characters removed by every algorithm.
///
/// U+200B ZERO WIDTH SPACE, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM,
/// U+2060 WORD JOINER, and variation selectors U+FE00–U+FE0F.
pub fn is_zero_width_format(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}'
    ) || matches!(c, '\u{FE00}'..='\u{FE0F}')
}

/// Surface canonical stream for the fingerprint and MinHash algorithms.
///
/// Alphanumeric characters (including CJK) are kept; every other character —
/// whitespace, punctuation, and symbols — acts as a token separator that
/// collapses to a single space, with no leading or trailing space.
pub fn canonical(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_separator = false;
    for c in text.nfc() {
        if is_zero_width_format(c) {
            continue;
        }
        for lc in c.to_lowercase() {
            if lc.is_alphanumeric() {
                if pending_separator && !out.is_empty() {
                    out.push(' ');
                }
                pending_separator = false;
                out.push(lc);
            } else {
                pending_separator = true;
            }
        }
    }
    out
}

/// Structure-preserving stream: NFC and strip zero-width/format only.
///
/// Case, punctuation, and sentence/paragraph boundaries are preserved so the
/// structural fingerprint can read them.
pub fn structural(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.nfc() {
        if is_zero_width_format(c) {
            continue;
        }
        out.push(c);
    }
    out
}

/// Word tokens of the surface stream: the whitespace-separated pieces of
/// [`canonical`]. Used by MinHash shingling and structural token counting.
pub fn words(text: &str) -> Vec<String> {
    canonical(text)
        .split(' ')
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_and_format() {
        let dirty = "he\u{200B}llo\u{FEFF} wor\u{2060}ld";
        assert_eq!(canonical(dirty), "hello world");
    }

    #[test]
    fn lowercases_and_collapses_whitespace() {
        assert_eq!(canonical("Hello   WORLD\t\nFoo"), "hello world foo");
    }

    #[test]
    fn punctuation_separates_tokens() {
        assert_eq!(canonical("foo, bar; baz."), "foo bar baz");
        assert_eq!(canonical("foo,bar"), "foo bar");
    }

    #[test]
    fn no_leading_or_trailing_space() {
        assert_eq!(canonical("  ...hi!  "), "hi");
    }

    #[test]
    fn nfc_equivalence() {
        // "é" as precomposed vs. combining sequence must canonicalize equal.
        let precomposed = "caf\u{00E9}";
        let decomposed = "cafe\u{0301}";
        assert_eq!(canonical(precomposed), canonical(decomposed));
    }

    #[test]
    fn structural_keeps_punctuation_and_case() {
        let s = "Hello, World! A test.";
        assert_eq!(structural(s), s);
    }

    #[test]
    fn structural_strips_zero_width() {
        assert_eq!(structural("a\u{200D}b."), "ab.");
    }

    #[test]
    fn words_tokenizes() {
        assert_eq!(
            words("The quick, brown fox."),
            vec!["the", "quick", "brown", "fox"]
        );
    }

    // Pinned test vector: input -> canonical value.
    #[test]
    fn vector_canonical() {
        let input = "The Quick\u{200B} Brown Fox — jumps!";
        assert_eq!(canonical(input), "the quick brown fox jumps");
    }
}
