//! Robustness benchmark for the WritersLogic soft-binding family against a
//! format + content attack battery, scored PAN-style (Balanced Accuracy).
//!
//! Fingerprints (41 SimHash / 43 structural / 44 MinHash): derive from the
//! original, attack, re-derive, and test whether the match survives. The
//! watermark (42 ZWC v2, `embed`/`extract`): insert, attack the watermarked
//! text, and test whether the routing pointer is recovered.
//!
//! Balanced Accuracy = (survival rate + true-negative rate) / 2, where the
//! true-negative rate is measured against unrelated documents. Thresholds come
//! from the algorithms themselves (SimHash 32, structural 24, MinHash 0.70),
//! so this benchmarks the algorithms exactly as registered. MinHash uses its
//! "same or overlapping" semantics: whole-signature Jaccard OR a shared LSH
//! band (the sublinear excerpt/quotation path).
//!
//! An optional third argument is a JSONL of precomputed paraphrases
//! ({"orig": "...", "para": "..."}) which adds a "dipper_paraphrase" attack.
//!
//! Run: cargo run --release --example robustness_bench -- /tmp/pan_train.jsonl [limit] [paraphrases.jsonl]

use c2pa_text_binding::{
    embed, extract, normalize::is_zero_width_format, simhash::Fingerprint, structure, MinHash,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use unicode_normalization::UnicodeNormalization;

const KEY: &[u8] = b"pan-benchmark-fixed-key-0001";
const POINTER: &[u8] = b"c2pa-manifest-01"; // 16 bytes

// MinHash "same or overlapping content": whole-signature Jaccard (same) or a
// shared LSH band (overlapping — the excerpt/quotation path).
fn mh_match(a: &MinHash, b: &MinHash) -> bool {
    a.matches(b) || a.shares_band(b)
}

// ------------------------------ attacks ------------------------------
fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}
fn strip_invis(s: &str) -> String {
    s.chars().filter(|c| !is_zero_width_format(*c)).collect()
}
fn whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
fn retype(s: &str) -> String {
    whitespace(&strip_invis(&s.nfc().collect::<String>()).to_lowercase())
}
fn take_frac(s: &str, frac: f64) -> String {
    let c = chars(s);
    let n = ((c.len() as f64) * frac) as usize;
    c[..n.max(1).min(c.len())].iter().collect()
}
fn window_frac(s: &str, frac: f64) -> String {
    let c = chars(s);
    let n = (((c.len() as f64) * frac) as usize).max(1).min(c.len());
    let start = (c.len() / 4).min(c.len() - n);
    c[start..start + n].iter().collect()
}
fn word_delete(s: &str, every: usize) -> String {
    s.split_whitespace()
        .enumerate()
        .filter(|(i, _)| i % every != 0)
        .map(|(_, w)| w)
        .collect::<Vec<_>>()
        .join(" ")
}
fn typos(s: &str, every: usize) -> String {
    chars(s)
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            if i % every == 0 && c.is_alphabetic() {
                'x'
            } else {
                c
            }
        })
        .collect()
}
fn syn(w: &str) -> Option<&'static str> {
    Some(match w {
        "big" => "large",
        "small" => "minor",
        "important" => "significant",
        "help" => "assist",
        "make" => "create",
        "use" => "employ",
        "show" => "demonstrate",
        "need" => "require",
        "start" => "begin",
        "end" => "conclude",
        "get" => "obtain",
        "said" => "stated",
        "think" => "believe",
        "want" => "desire",
        "good" => "positive",
        "bad" => "negative",
        "problem" => "issue",
        "change" => "alter",
        "new" => "novel",
        "old" => "prior",
        "fast" => "rapid",
        "slow" => "gradual",
        "buy" => "purchase",
        "build" => "construct",
        "keep" => "retain",
        "give" => "provide",
        "find" => "locate",
        "tell" => "inform",
        "ask" => "request",
        "work" => "function",
        "wrong" => "incorrect",
        "real" => "genuine",
        "hard" => "difficult",
        "easy" => "simple",
        "strong" => "robust",
        "weak" => "fragile",
        "clear" => "evident",
        "ensure" => "guarantee",
        "allow" => "permit",
        "reduce" => "lower",
        "increase" => "raise",
        "protect" => "safeguard",
        "support" => "back",
        _ => return None,
    })
}
// Token-count-preserving light synonym substitution (1 open-class word -> 1 word),
// so sentence-length sequences are unchanged. Tests entry 43's specific claim.
fn synonym_swap(s: &str) -> String {
    s.split_whitespace()
        .map(|tok| {
            let core: String = tok.chars().filter(|c| c.is_alphabetic()).collect();
            match syn(&core.to_lowercase()) {
                Some(rep) => tok.replacen(&core, rep, 1),
                None => tok.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

type Attack = (&'static str, Box<dyn Fn(&str) -> String>);

fn attacks(paraphrases: Option<HashMap<String, String>>) -> Vec<Attack> {
    let mut v: Vec<Attack> = vec![
        ("identity", Box::new(|s: &str| s.to_string())),
        ("strip_invisibles", Box::new(|s: &str| strip_invis(s))),
        ("nfkd", Box::new(|s: &str| s.nfkd().collect())),
        ("casefold", Box::new(|s: &str| s.to_lowercase())),
        ("whitespace", Box::new(|s: &str| whitespace(s))),
        ("retype", Box::new(|s: &str| retype(s))),
        ("truncate90", Box::new(|s: &str| take_frac(s, 0.9))),
        ("truncate50", Box::new(|s: &str| take_frac(s, 0.5))),
        ("excerpt30", Box::new(|s: &str| window_frac(s, 0.3))),
        ("word_del_5pct", Box::new(|s: &str| word_delete(s, 20))),
        ("word_del_15pct", Box::new(|s: &str| word_delete(s, 7))),
        ("typos_5pct", Box::new(|s: &str| typos(s, 20))),
        ("synonym_swap", Box::new(|s: &str| synonym_swap(s))),
    ];
    if let Some(map) = paraphrases {
        // paraphrase is precomputed per original text; fall back to identity if absent
        v.push((
            "dipper_paraphrase",
            Box::new(move |s: &str| {
                map.get(&strip_invis(s))
                    .cloned()
                    .unwrap_or_else(|| s.to_string())
            }),
        ));
    }
    v
}

// ------------------------------ helpers ------------------------------
fn bal_acc(survival: f64, tnr: f64) -> f64 {
    (survival + tnr) / 2.0
}

struct Row {
    attack: String,
    ba: f64,
    survival: f64,
}

fn summarize(rows: &[Row]) -> (f64, f64, f64) {
    let ident = rows
        .iter()
        .find(|r| r.attack == "identity")
        .map(|r| r.ba)
        .unwrap_or(0.0);
    let adv: Vec<&Row> = rows.iter().filter(|r| r.attack != "identity").collect();
    let mean_ba = adv.iter().map(|r| r.ba).sum::<f64>() / adv.len() as f64;
    let mean_surv = adv.iter().map(|r| r.survival).sum::<f64>() / adv.len() as f64;
    (ident, mean_ba, mean_surv)
}

fn load_paraphrases(path: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in BufReader::new(File::open(path).unwrap()).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        if let (Some(o), Some(p)) = (v["orig"].as_str(), v["para"].as_str()) {
            map.insert(o.to_string(), p.to_string());
        }
    }
    map
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .expect("usage: robustness_bench <dataset.jsonl> [limit] [paraphrases.jsonl]");
    let limit: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(300);
    let paraphrases = args.get(3).map(|p| load_paraphrases(p));

    // load texts, keep only those that embed successfully (comparable working set)
    let mut texts: Vec<String> = Vec::new();
    for line in BufReader::new(File::open(path).unwrap()).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        if let Some(t) = v["text"].as_str() {
            if embed(t, KEY, POINTER).is_ok() {
                texts.push(t.to_string());
            }
        }
        if texts.len() >= limit {
            break;
        }
    }
    let n = texts.len();
    eprintln!("working set: {n} embeddable documents");

    let atks = attacks(paraphrases);

    // precompute originals
    let fps: Vec<Fingerprint> = texts.iter().map(|t| Fingerprint::compute(t)).collect();
    let strs: Vec<_> = texts.iter().map(|t| structure::compute(t)).collect();
    let mhs: Vec<MinHash> = texts.iter().map(|t| MinHash::compute(t)).collect();
    let wms: Vec<String> = texts
        .iter()
        .map(|t| embed(t, KEY, POINTER).unwrap())
        .collect();

    // true-negative rates (unrelated documents must NOT match) — attack-independent
    let other = |i: usize| (i + 1) % n;
    let tnr_41 = 1.0
        - fps
            .iter()
            .enumerate()
            .filter(|(i, f)| f.matches(&fps[other(*i)].whole))
            .count() as f64
            / n as f64;
    let tnr_43 = 1.0
        - strs
            .iter()
            .enumerate()
            .filter(|(i, h)| structure::matches(h, &strs[other(*i)]))
            .count() as f64
            / n as f64;
    let tnr_44 = 1.0
        - mhs
            .iter()
            .enumerate()
            .filter(|(i, m)| mh_match(m, &mhs[other(*i)]))
            .count() as f64
            / n as f64;
    // watermark FP: extracting from an unrelated *unwatermarked* text must not yield our pointer
    let wm_fp = texts
        .iter()
        .filter(|t| matches!(extract(t, KEY), Ok(r) if r.pointer == pointer_padded()))
        .count();
    let tnr_wm = 1.0 - wm_fp as f64 / n as f64;
    // watermark fidelity: stripping the invisibles restores the visible text
    let fidelity = wms
        .iter()
        .zip(&texts)
        .filter(|(w, t)| strip_invis(w) == strip_invis(t))
        .count() as f64
        / n as f64;

    let mut fp41 = Vec::new();
    let mut fp43 = Vec::new();
    let mut fp44 = Vec::new();
    let mut wm42 = Vec::new();

    for (name, atk) in &atks {
        // fingerprints: attack the ORIGINAL, re-derive, test survival
        let s41 = fps
            .iter()
            .zip(&texts)
            .filter(|(f, t)| f.matches(&Fingerprint::compute(&atk(t)).whole))
            .count() as f64
            / n as f64;
        let s43 = strs
            .iter()
            .zip(&texts)
            .filter(|(h, t)| structure::matches(h, &structure::compute(&atk(t))))
            .count() as f64
            / n as f64;
        let s44 = mhs
            .iter()
            .zip(&texts)
            .filter(|(m, t)| mh_match(m, &MinHash::compute(&atk(t))))
            .count() as f64
            / n as f64;
        // watermark: attack the WATERMARKED text, extract, test pointer recovery
        let swm = wms
            .iter()
            .filter(|w| matches!(extract(&atk(w), KEY), Ok(r) if r.pointer == pointer_padded()))
            .count() as f64
            / n as f64;

        fp41.push(Row {
            attack: name.to_string(),
            ba: bal_acc(s41, tnr_41),
            survival: s41,
        });
        fp43.push(Row {
            attack: name.to_string(),
            ba: bal_acc(s43, tnr_43),
            survival: s43,
        });
        fp44.push(Row {
            attack: name.to_string(),
            ba: bal_acc(s44, tnr_44),
            survival: s44,
        });
        wm42.push(Row {
            attack: name.to_string(),
            ba: bal_acc(swm, tnr_wm),
            survival: swm,
        });
    }

    // ------------------------------ report ------------------------------
    println!("# Robustness benchmark (n={n}, PAN'26 political speeches)\n");
    println!("| attack | 41 simhash BA | 43 structural BA | 44 minhash BA | 42 zwc-wm BA |");
    println!("|---|---|---|---|---|");
    for i in 0..atks.len() {
        println!(
            "| {} | {:.3} | {:.3} | {:.3} | {:.3} |",
            fp41[i].attack, fp41[i].ba, fp43[i].ba, fp44[i].ba, wm42[i].ba
        );
    }
    println!("\n## Summary (mean over adversarial attacks; identity = calibration)\n");
    println!("| algorithm | identity BA | mean BA | mean survival |");
    println!("|---|---|---|---|");
    for (label, rows) in [
        ("41 simhash", &fp41),
        ("43 structural", &fp43),
        ("44 minhash", &fp44),
        ("42 zwc-watermark", &wm42),
    ] {
        let (id, mba, msv) = summarize(rows);
        println!("| {label} | {id:.3} | {mba:.3} | {msv:.3} |");
    }
    println!(
        "\nTrue-negative rates: 41={tnr_41:.3} 43={tnr_43:.3} 44={tnr_44:.3} wm={tnr_wm:.3}  |  watermark visible-fidelity={fidelity:.3}"
    );
}

fn pointer_padded() -> [u8; 16] {
    let mut p = [0u8; 16];
    let k = POINTER.len().min(16);
    p[..k].copy_from_slice(&POINTER[..k]);
    p
}
