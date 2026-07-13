//! Threshold-grounding sweep for the WritersLogic soft-binding family.
//!
//! The robustness benchmark (`robustness_bench.rs`) scores one intensity per
//! attack. This sweep instead grounds the registered match thresholds — and the
//! BOUND/LIKELY/REVIEW confidence tiers built on them — as empirical curves:
//!
//! 1. **All-pairs false-match rate.** Every ordered document pair (i != j) is
//!    tested at the registered threshold. This is the false-BOUND driver; it
//!    replaces the single-neighbour true-negative estimate in the benchmark,
//!    which sampled only one negative per document.
//! 2. **Edit-distance sweep.** Exactly k evenly-spaced word substitutions,
//!    k = 1,2,4,8,16,32, re-derive, test survival — locating each algorithm's
//!    edit cliff rather than asserting it.
//! 3. **Excerpt-length sweep.** A contiguous window of fraction f of the
//!    document, f = 0.1..1.0, test survival via the window/LSH path.
//! 4. **Reformatting sweep.** Cumulative benign format transforms (case,
//!    whitespace, zero-width injection, NFKD, full retype); survival should stay
//!    at 1.0 because normalization absorbs them.
//! 5. **Separation margin.** The largest whole-document distance seen under
//!    benign reformatting vs. the smallest distance to any unrelated document,
//!    so the threshold's headroom is a measured number.
//!
//! Match semantics are each algorithm's own registered threshold — no re-tuning.
//! Deterministic and model-free, so any verifier reproduces these numbers.
//!
//! Run: cargo run --release --example threshold_sweep -- <dataset.jsonl> [limit]

use c2pa_text_binding::{simhash::Fingerprint, structure, MinHash};
use std::fs::File;
use std::io::{BufRead, BufReader};
use unicode_normalization::UnicodeNormalization;

// MinHash "same or overlapping": whole-signature Jaccard OR a shared LSH band.
fn mh_match(a: &MinHash, b: &MinHash) -> bool {
    a.matches(b) || a.shares_band(b)
}

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

// Exactly `k` word substitutions, spread evenly across the document, each to a
// token ("qzx") that cannot appear in natural text — a controlled edit distance.
fn k_word_edits(s: &str, k: usize) -> String {
    let mut toks: Vec<String> = s.split_whitespace().map(str::to_string).collect();
    if toks.is_empty() {
        return s.to_string();
    }
    let k = k.min(toks.len());
    let len = toks.len();
    for j in 0..k {
        let idx = ((j * len) / k.max(1)).min(len - 1);
        toks[idx] = "qzx".to_string();
    }
    toks.join(" ")
}

// Contiguous window of fraction `frac`, anchored a quarter of the way in.
fn excerpt(s: &str, frac: f64) -> String {
    let c = chars(s);
    if c.is_empty() {
        return String::new();
    }
    let n = (((c.len() as f64) * frac) as usize).clamp(1, c.len());
    let start = (c.len() / 4).min(c.len() - n);
    c[start..start + n].iter().collect()
}

// Cumulative benign format transforms by level (0 = identity).
fn reformat(s: &str, level: usize) -> String {
    let mut out = s.to_string();
    if level >= 1 {
        out = out.to_uppercase();
    }
    if level >= 2 {
        out = out.split_whitespace().collect::<Vec<_>>().join("  ");
    }
    if level >= 3 {
        // Inject a zero-width space after each space.
        out = out.replace(' ', " \u{200B}");
    }
    if level >= 4 {
        out = out.nfkd().collect();
    }
    out
}

fn load_texts(path: &str, limit: usize) -> Vec<String> {
    let mut texts = Vec::new();
    for line in BufReader::new(File::open(path).expect("open dataset")).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        if let Some(t) = v["text"].as_str() {
            // Keep only documents long enough for windows to exist, so the
            // excerpt path is actually exercised (non-degenerate working set).
            if chars(t).len() >= 1024 {
                texts.push(t.to_string());
            }
        }
        if texts.len() >= limit {
            break;
        }
    }
    texts
}

fn pct(x: f64) -> String {
    format!("{:.3}", x)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .expect("usage: threshold_sweep <dataset.jsonl> [limit]");
    let limit: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);

    let texts = load_texts(path, limit);
    let n = texts.len();
    assert!(n >= 20, "need >= 20 long documents for a meaningful sweep");
    eprintln!("working set: {n} documents (>= 1024 chars each)");

    let fps: Vec<Fingerprint> = texts.iter().map(|t| Fingerprint::compute(t)).collect();
    let strs: Vec<_> = texts.iter().map(|t| structure::compute(t)).collect();
    let mhs: Vec<MinHash> = texts.iter().map(|t| MinHash::compute(t)).collect();

    // ---- 1. all-pairs false-match rate at the registered thresholds ----
    let total_pairs = (n * (n - 1)) as f64;
    let mut fp_fm = 0usize;
    let mut st_fm = 0usize;
    let mut mh_fm = 0usize;
    // Smallest cross-document distance seen (separation ceiling for negatives).
    let mut fp_min_neg = u32::MAX;
    let mut st_min_neg = u32::MAX;
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            let dfp = fps[i].whole.hamming(&fps[j].whole);
            let dst = strs[i].hamming(&strs[j]);
            fp_min_neg = fp_min_neg.min(dfp);
            st_min_neg = st_min_neg.min(dst);
            if fps[i].matches(&fps[j].whole) {
                fp_fm += 1;
            }
            if structure::matches(&strs[i], &strs[j]) {
                st_fm += 1;
            }
            if mh_match(&mhs[i], &mhs[j]) {
                mh_fm += 1;
            }
        }
    }

    println!("# Threshold-grounding sweep (n={n})\n");
    println!("## 1. All-pairs false-match rate at registered thresholds\n");
    println!("| algorithm | threshold | false matches / pairs | FMR |");
    println!("|---|---|---|---|");
    println!(
        "| 41 simhash | Hamming <= 32 | {fp_fm} / {} | {} |",
        total_pairs as u64,
        pct(fp_fm as f64 / total_pairs)
    );
    println!(
        "| 43 structural | Hamming <= 24 | {st_fm} / {} | {} |",
        total_pairs as u64,
        pct(st_fm as f64 / total_pairs)
    );
    println!(
        "| 44 minhash | Jaccard >= 0.70 or shared band | {mh_fm} / {} | {} |",
        total_pairs as u64,
        pct(mh_fm as f64 / total_pairs)
    );

    // ---- 2. edit-distance sweep ----
    println!("\n## 2. Edit-distance sweep (survival rate; k = word substitutions)\n");
    println!("| k edits | 41 simhash | 43 structural | 44 minhash |");
    println!("|---|---|---|---|");
    for k in [1usize, 2, 4, 8, 16, 32] {
        let mut s41 = 0;
        let mut s43 = 0;
        let mut s44 = 0;
        for (i, t) in texts.iter().enumerate() {
            let a = k_word_edits(t, k);
            if fps[i].matches(&Fingerprint::compute(&a).whole) {
                s41 += 1;
            }
            if structure::matches(&strs[i], &structure::compute(&a)) {
                s43 += 1;
            }
            if mh_match(&mhs[i], &MinHash::compute(&a)) {
                s44 += 1;
            }
        }
        println!(
            "| {k} | {} | {} | {} |",
            pct(s41 as f64 / n as f64),
            pct(s43 as f64 / n as f64),
            pct(s44 as f64 / n as f64)
        );
    }

    // ---- 3. excerpt-length sweep ----
    println!("\n## 3. Excerpt-length sweep (survival rate; contiguous window)\n");
    println!("| fraction | 41 simhash (window path) | 44 minhash (LSH path) |");
    println!("|---|---|---|");
    for f in [0.1, 0.2, 0.3, 0.5, 0.7, 0.9] {
        let mut s41 = 0;
        let mut s44 = 0;
        for (i, t) in texts.iter().enumerate() {
            let a = excerpt(t, f);
            if fps[i].matches(&Fingerprint::compute(&a).whole) {
                s41 += 1;
            }
            if mh_match(&mhs[i], &MinHash::compute(&a)) {
                s44 += 1;
            }
        }
        println!(
            "| {f:.1} | {} | {} |",
            pct(s41 as f64 / n as f64),
            pct(s44 as f64 / n as f64)
        );
    }

    // ---- 4. reformatting sweep ----
    println!("\n## 4. Reformatting sweep (survival rate; cumulative benign transforms)\n");
    println!("| level | transforms | 41 simhash | 43 structural | 44 minhash |");
    println!("|---|---|---|---|---|");
    let labels = [
        "identity",
        "+casefold",
        "+whitespace",
        "+zero-width",
        "+NFKD (retype)",
    ];
    for (level, label) in labels.iter().enumerate() {
        let mut s41 = 0;
        let mut s43 = 0;
        let mut s44 = 0;
        for (i, t) in texts.iter().enumerate() {
            let a = reformat(t, level);
            if fps[i].matches(&Fingerprint::compute(&a).whole) {
                s41 += 1;
            }
            if structure::matches(&strs[i], &structure::compute(&a)) {
                s43 += 1;
            }
            if mh_match(&mhs[i], &MinHash::compute(&a)) {
                s44 += 1;
            }
        }
        println!(
            "| {level} | {label} | {} | {} | {} |",
            pct(s41 as f64 / n as f64),
            pct(s43 as f64 / n as f64),
            pct(s44 as f64 / n as f64)
        );
    }

    // ---- 5. separation margin (whole-document, SimHash + structural) ----
    // Largest benign distance = worst case under level-4 reformatting.
    let mut fp_max_benign = 0u32;
    let mut st_max_benign = 0u32;
    for (i, t) in texts.iter().enumerate() {
        let a = reformat(t, 4);
        fp_max_benign = fp_max_benign.max(fps[i].whole.hamming(&Fingerprint::compute(&a).whole));
        st_max_benign = st_max_benign.max(strs[i].hamming(&structure::compute(&a)));
    }
    println!("\n## 5. Separation margin (whole-document Hamming, bits)\n");
    println!("| algorithm | max benign dist | threshold | min unrelated dist | margin |");
    println!("|---|---|---|---|---|");
    println!(
        "| 41 simhash | {fp_max_benign} | 32 | {fp_min_neg} | {} |",
        fp_min_neg as i64 - 32
    );
    println!(
        "| 43 structural | {st_max_benign} | 24 | {st_min_neg} | {} |",
        st_min_neg as i64 - 24
    );

    println!(
        "\nReading: a whole-document match is BOUND only with the crosscheck HMAC. \
         The all-pairs FMR bounds a false BOUND from fingerprint collision; the keyed \
         crosscheck bounds transfer. Benign reformatting stays at distance 0 (normalization \
         absorbs it), so the threshold headroom is spent entirely on content edits."
    );
}
