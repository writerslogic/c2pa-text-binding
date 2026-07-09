// SPDX-License-Identifier: MIT OR Apache-2.0

//! `com.writerslogic.text-structure.1` — a deterministic, model-free 256-bit
//! SimHash over a document's structural skeleton: sentence-length sequence,
//! paragraph shape, punctuation-class profile, and function-word skeleton.
//! Survives synonym-level paraphrase that defeats a surface fingerprint.
//! Match when Hamming distance <= 24 / 256.

use crate::normalize::structural;
use crate::simhash::{simhash_weighted, Hash256};

/// Structural match threshold in bits.
pub const MATCH_THRESHOLD: u32 = 24;

// Independent per-family weights so the four features combine without one
// dominating; structural features are lower-entropy than lexical n-grams.
const W_SENTENCE: i64 = 3;
const W_PARAGRAPH: i64 = 2;
const W_PUNCT: i64 = 1;
const W_SKELETON: i64 = 2;

/// English closed-class (function) words kept in the skeleton; content words
/// are masked. Fixed and pinned as part of the `.1` algorithm version.
const FUNCTION_WORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "nor", "so", "yet", "for", "of", "to", "in", "on", "at",
    "by", "as", "is", "are", "was", "were", "be", "been", "being", "am", "do", "does", "did",
    "have", "has", "had", "will", "would", "shall", "should", "can", "could", "may", "might",
    "must", "with", "from", "into", "onto", "upon", "over", "under", "above", "below", "between",
    "through", "during", "before", "after", "about", "against", "among", "around", "because", "if",
    "then", "than", "that", "this", "these", "those", "it", "its", "he", "she", "they", "them",
    "his", "her", "their", "our", "your", "my", "we", "you", "i", "me", "us", "who", "whom",
    "whose", "which", "what", "when", "where", "why", "how", "not", "no", "yes", "all", "any",
    "some", "each", "every", "both", "few", "many", "more", "most", "other", "such", "only", "own",
    "same", "too", "very", "just", "also", "here", "there", "up", "down", "out", "off", "again",
    "once", "while", "until",
];

/// Compute the structural fingerprint of `text`.
pub fn compute(text: &str) -> Hash256 {
    let norm = structural(text);
    let paragraphs = split_paragraphs(&norm);

    let mut sentence_lengths: Vec<usize> = Vec::new();
    let mut paragraph_lengths: Vec<usize> = Vec::new();
    let mut skeleton_tokens: Vec<String> = Vec::new();

    for para in &paragraphs {
        let sentences = split_sentences(para);
        paragraph_lengths.push(sentences.len());
        for sent in &sentences {
            let words = word_tokens(sent);
            sentence_lengths.push(words.len());
            for w in &words {
                if FUNCTION_WORDS.contains(&w.as_str()) {
                    skeleton_tokens.push(w.clone());
                } else {
                    skeleton_tokens.push("_".to_string());
                }
            }
        }
    }

    // Own the feature key strings so their bytes outlive the SimHash borrow.
    let mut features: Vec<(String, i64)> = Vec::new();

    // Sentence-length sequence: unigrams and bigrams to keep order signal.
    for len in &sentence_lengths {
        features.push((format!("SL1:{len}"), W_SENTENCE));
    }
    for pair in sentence_lengths.windows(2) {
        features.push((format!("SL2:{},{}", pair[0], pair[1]), W_SENTENCE));
    }

    // Paragraph-length sequence.
    for len in &paragraph_lengths {
        features.push((format!("PL:{len}"), W_PARAGRAPH));
    }

    // Punctuation-class profile: multiset of classes over the whole document.
    for (class, count) in punctuation_profile(&norm) {
        features.push((format!("PUNCT:{class}"), W_PUNCT * count as i64));
    }

    // Function-word skeleton: 3-gram shingles of the masked token sequence.
    if skeleton_tokens.len() >= 3 {
        for w in skeleton_tokens.windows(3) {
            features.push((format!("FW:{} {} {}", w[0], w[1], w[2]), W_SKELETON));
        }
    } else if !skeleton_tokens.is_empty() {
        features.push((format!("FW:{}", skeleton_tokens.join(" ")), W_SKELETON));
    }

    simhash_weighted(features.iter().map(|(k, w)| (k.as_bytes(), *w)))
}

/// Whether two structural fingerprints identify the same underlying structure.
/// A structural hit is corroborating evidence, not a sole provenance decision.
pub fn matches(a: &Hash256, b: &Hash256) -> bool {
    a.hamming(b) <= MATCH_THRESHOLD
}

fn split_paragraphs(text: &str) -> Vec<String> {
    let mut paras = Vec::new();
    let mut current = String::new();
    let mut blank_run = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            blank_run += 1;
            if blank_run >= 1 && !current.trim().is_empty() {
                paras.push(std::mem::take(&mut current));
            }
        } else {
            blank_run = 0;
            current.push_str(line);
            current.push(' ');
        }
    }
    if !current.trim().is_empty() {
        paras.push(current);
    }
    if paras.is_empty() {
        paras.push(text.to_string());
    }
    paras
}

fn split_sentences(para: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut current = String::new();
    for c in para.chars() {
        current.push(c);
        if matches!(c, '.' | '!' | '?') && current.trim().len() > 1 {
            sentences.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        sentences.push(current);
    }
    if sentences.is_empty() && !para.trim().is_empty() {
        sentences.push(para.to_string());
    }
    sentences
}

fn word_tokens(sentence: &str) -> Vec<String> {
    sentence
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect()
}

/// Ordered multiset of punctuation classes as `(class, count)` pairs.
fn punctuation_profile(text: &str) -> Vec<(char, usize)> {
    let mut counts: std::collections::BTreeMap<char, usize> = std::collections::BTreeMap::new();
    for c in text.chars() {
        if let Some(class) = punctuation_class(c) {
            *counts.entry(class).or_insert(0) += 1;
        }
    }
    counts.into_iter().collect()
}

/// Fold a character into a punctuation class, or `None` if not punctuation.
fn punctuation_class(c: char) -> Option<char> {
    match c {
        '.' | '\u{2026}' => Some('.'), // period / ellipsis
        ',' => Some(','),
        ';' => Some(';'),
        ':' => Some(':'),
        '?' => Some('?'),
        '!' => Some('!'),
        '-' | '\u{2013}' | '\u{2014}' => Some('-'), // hyphen / en / em dash
        '(' | ')' | '[' | ']' | '{' | '}' => Some('('),
        '"' | '\'' | '\u{201C}' | '\u{201D}' | '\u{2018}' | '\u{2019}' => Some('"'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "Provenance must survive editing. A soft binding derives a durable value \
        from the words themselves. When the embedded manifest is stripped, a resolver \
        recomputes the value and finds the manifest again.\n\nText is mutable, so no single \
        technique wins. A family of algorithms with different fragility profiles is combined \
        by the verifier. Casual redistribution stays fully recoverable.";

    #[test]
    fn identical_text_zero_distance() {
        let a = compute(SRC);
        let b = compute(SRC);
        assert_eq!(a.hamming(&b), 0);
    }

    #[test]
    fn synonym_paraphrase_stays_within_threshold() {
        let a = compute(SRC);
        // Swap content words for synonyms; structure (sentence rhythm,
        // punctuation, function words) is preserved.
        let para = SRC
            .replace("survive", "outlast")
            .replace("durable", "lasting")
            .replace("stripped", "removed")
            .replace("recomputes", "recalculates")
            .replace("mutable", "changeable")
            .replace("technique", "method")
            .replace("fragility", "brittleness")
            .replace("redistribution", "resharing");
        let b = compute(&para);
        let d = a.hamming(&b);
        assert!(
            d <= MATCH_THRESHOLD,
            "synonym-level paraphrase distance {d} exceeded structural threshold"
        );
    }

    #[test]
    fn reformatting_survives() {
        let a = compute(SRC);
        let b = compute(&SRC.replace(". ", ".  \u{200B}"));
        assert!(matches(&a, &b));
    }

    #[test]
    fn different_structure_diverges() {
        let a = compute(SRC);
        let b = compute(
            "One short line. Another. And a third! Then a question? Yes. No. Maybe. \
             Terse fragments everywhere, with commas, dashes — and semicolons; many of them.",
        );
        assert!(
            a.hamming(&b) > MATCH_THRESHOLD,
            "a structurally different document must exceed the threshold"
        );
    }

    // Pinned test vector.
    #[test]
    fn vector_structure() {
        let h = compute("First sentence here. Second one follows. Third to close it.");
        assert_eq!(
            h.to_hex(),
            "1e7b9ab9dabce9dfe4461a259434f09be52147161a0228234838f86e7dc60a62",
            "PIN: recompute and update on any intentional algorithm change"
        );
    }
}
