// SPDX-License-Identifier: MIT OR Apache-2.0

//! Comparative transport-survivability benchmark for invisible-text provenance
//! carriers, plus the fingerprint recovery layer.
//!
//! Every method exposes the same shape: embed a payload into a host text, apply
//! a transport, re-extract, and classify the outcome:
//!
//!   intact   payload recovered unchanged
//!   gone     no carrier detected (safe: reads as no manifest)
//!   safe     carrier detected but rejected by the codec (fail-safe)
//!   UNSAFE   carrier decoded to the WRONG payload (the only real failure)
//!
//! Columns:
//!   v1ref/v1inl  A.8 variation selectors (v1), reference- and inline-size
//!   v2ref        proposed self-delimiting A.8 (v2), reference-size
//!   zwc          zero-width watermark with Reed-Solomon coding (`stego`)
//!   tag          Unicode Tags "ASCII smuggling" carrier
//!   zwbin        naive zero-width binary, no error correction
//!   simhash      content fingerprint (recovery layer, carries no bytes)
//!
//! Three views: a categorical probe battery, a partial-loss dose sweep (how much
//! carrier loss each method tolerates — the error-correction axis), and a length
//! sweep (reference vs inline payload survival under tail truncation). All are
//! deterministic and need no credentials; Tier 1 reuses these methods and the
//! classifier over real sanitizer libraries and platforms.
//!
//! Run: cargo run --release --example transport_survivability

use c2pa_text_binding::normalize::is_zero_width_format;
use c2pa_text_binding::simhash::Fingerprint;
use c2pa_text_binding::{stego, tag, vs, zwbin};
use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

const KEY: &[u8] = b"transport-survivability-fixed-key";
const ZWC_POINTER: &[u8] = b"c2pa-manifest-01"; // 16 bytes
const REFERENCE: &[u8] = b"https://fabrikam.com/manifests/a1b2c3.c2pa"; // 42 bytes

const HOST: &str = "\
Provenance travels with content when the carrier survives the journey. A reader \
copies a paragraph from one application and pastes it into another, and along \
the way the text passes through clipboards, editors, message queues, and \
storage layers that each feel free to rewrite what they consider formatting. \
The question this benchmark answers is narrow and testable: after such a trip, \
is the embedded provenance still there, is it gone, or is it quietly wrong. \
Only the last outcome is dangerous, and a careful codec should make it \
impossible by construction rather than by luck or good fortune of the day.";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Intact,
    Gone,
    Safe,
    Unsafe,
    BindingBroken,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Intact => "intact",
            Outcome::Gone => "gone",
            Outcome::Safe => "safe",
            Outcome::Unsafe => "UNSAFE",
            Outcome::BindingBroken => "bind-broke",
        }
    }
}

/// The carrier survived, but does the content binding still validate? A hard
/// binding is a hash over the visible text; a transport that reflows or
/// normalizes the visible content breaks it even when the carrier is intact.
fn binding_ok(transformed: &str) -> bool {
    let visible: String = transformed.chars().filter(|c| !is_carrier_cp(*c)).collect();
    // A.8 hard binding: exact NFC bytes, not the whitespace-tolerant soft-binding
    // canonicalization. Reflow that the carrier survives still breaks this.
    let nfc = |s: &str| s.nfc().collect::<String>();
    nfc(&visible) == nfc(HOST)
}

/// Refine a carrier's recovery outcome with the binding check: a recovered
/// payload whose visible text no longer hashes to the original is `bind-broke`,
/// not `intact`. The fingerprint method carries no binding, so it is exempt.
fn refine(name: &str, transformed: &str, o: Outcome) -> Outcome {
    if name != "simhash" && o == Outcome::Intact && !binding_ok(transformed) {
        Outcome::BindingBroken
    } else {
        o
    }
}

/// Fold a carrier `Decoded`-style result into an [`Outcome`] against `want`.
fn classify(decoded: Option<Vec<u8>>, corrupt: bool, want: &[u8]) -> Outcome {
    match decoded {
        Some(p) if p == want => Outcome::Intact,
        Some(_) => Outcome::Unsafe,
        None if corrupt => Outcome::Safe,
        None => Outcome::Gone,
    }
}

fn vs_outcome(d: vs::Decoded, want: &[u8]) -> Outcome {
    match d {
        vs::Decoded::Payload(p) => classify(Some(p), false, want),
        vs::Decoded::Corrupt => Outcome::Safe,
        vs::Decoded::None => Outcome::Gone,
    }
}

fn tag_outcome(d: tag::Decoded, want: &[u8]) -> Outcome {
    match d {
        tag::Decoded::Payload(p) => classify(Some(p), false, want),
        tag::Decoded::Corrupt => Outcome::Safe,
        tag::Decoded::None => Outcome::Gone,
    }
}

fn zwbin_outcome(d: zwbin::Decoded, want: &[u8]) -> Outcome {
    match d {
        zwbin::Decoded::Payload(p) => classify(Some(p), false, want),
        zwbin::Decoded::Corrupt => Outcome::Safe,
        zwbin::Decoded::None => Outcome::Gone,
    }
}

fn zwc_outcome(carried: &str) -> Outcome {
    let mut want = [0u8; stego::POINTER_LEN];
    let k = ZWC_POINTER.len().min(stego::POINTER_LEN);
    want[..k].copy_from_slice(&ZWC_POINTER[..k]);
    match stego::extract(carried, KEY) {
        Ok(r) if r.pointer == want => Outcome::Intact,
        Ok(_) => Outcome::Unsafe,
        Err(_) => Outcome::Gone,
    }
}

fn simhash_outcome(carried: &str) -> Outcome {
    if Fingerprint::compute(HOST).matches(&Fingerprint::compute(carried).whole) {
        Outcome::Intact
    } else {
        Outcome::Gone
    }
}

struct Method {
    name: &'static str,
    embedded: String,
    recover: Box<dyn Fn(&str) -> Outcome>,
}

fn methods() -> Vec<Method> {
    let inline: Vec<u8> = (0..1024).map(|i| (i * 37 + 11) as u8).collect();
    let mut v = Vec::new();

    v.push(Method {
        name: "v1ref",
        embedded: vs::embed(HOST, REFERENCE),
        recover: Box::new(|t| vs_outcome(vs::extract(t), REFERENCE)),
    });
    v.push(Method {
        name: "v1inl",
        embedded: vs::embed(HOST, &inline),
        recover: Box::new(move |t| vs_outcome(vs::extract(t), &inline)),
    });
    v.push(Method {
        name: "v2ref",
        embedded: vs::embed_v2(HOST, REFERENCE, 0),
        recover: Box::new(|t| vs_outcome(vs::extract(t), REFERENCE)),
    });
    if let Ok(embedded) = stego::embed(HOST, KEY, ZWC_POINTER) {
        v.push(Method {
            name: "zwc",
            embedded,
            recover: Box::new(zwc_outcome),
        });
    }
    v.push(Method {
        name: "tag",
        embedded: tag::embed(HOST, REFERENCE),
        recover: Box::new(|t| tag_outcome(tag::extract(t), REFERENCE)),
    });
    v.push(Method {
        name: "zwbin",
        embedded: zwbin::embed(HOST, REFERENCE),
        recover: Box::new(|t| zwbin_outcome(zwbin::extract(t), REFERENCE)),
    });
    v.push(Method {
        name: "simhash",
        embedded: HOST.to_string(),
        recover: Box::new(simhash_outcome),
    });
    v
}

type Transport = (&'static str, fn(&str) -> String);

fn transports() -> Vec<Transport> {
    vec![
        ("identity", |s| s.to_string()),
        ("nfc", |s| s.nfc().collect()),
        ("nfkc", |s| s.nfkc().collect()),
        ("nfkd", |s| s.nfkd().collect()),
        ("strip-bom", |s| {
            s.chars().filter(|&c| c != '\u{FEFF}').collect()
        }),
        ("bmp-only", |s| {
            s.chars().filter(|&c| (c as u32) <= 0xFFFF).collect()
        }),
        ("strip-zero-width", |s| {
            s.chars().filter(|&c| !is_zero_width_format(c)).collect()
        }),
        ("strip-variation-sel", |s| {
            s.chars()
                .filter(|&c| !vs::is_vs(c) && c != vs::MARKER)
                .collect()
        }),
        ("strip-tags", |s| {
            s.chars().filter(|&c| !tag::is_tag(c)).collect()
        }),
    ]
}

/// Whether `c` belongs to any carrier alphabet used here.
fn is_carrier_cp(c: char) -> bool {
    vs::is_vs(c)
        || c == vs::MARKER
        || tag::is_tag(c)
        || matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}')
}

/// Deterministically drop `pct`% of the carrier code points in `text`.
fn drop_carrier(text: &str, pct: u32) -> String {
    text.chars()
        .enumerate()
        .filter(|(i, c)| {
            let bucket = ((*i as u64).wrapping_mul(2_654_435_761) >> 16) % 100;
            !is_carrier_cp(*c) || bucket >= pct as u64
        })
        .map(|(_, c)| c)
        .collect()
}

/// Remove a single contiguous burst of `pct`% of the carrier code points.
/// Error-correcting codes tolerate scattered loss but not a burst that wipes
/// consecutive shards, so this is where the Reed-Solomon advantage inverts.
fn burst_loss(text: &str, pct: u32) -> String {
    let positions: Vec<usize> = text
        .chars()
        .enumerate()
        .filter(|(_, c)| is_carrier_cp(*c))
        .map(|(i, _)| i)
        .collect();
    if positions.is_empty() {
        return text.to_string();
    }
    let n = (positions.len() as u64 * pct as u64 / 100) as usize;
    let start = positions.len() / 4; // deterministic burst location
    let drop: std::collections::HashSet<usize> = positions[start..(start + n).min(positions.len())]
        .iter()
        .copied()
        .collect();
    text.chars()
        .enumerate()
        .filter(|(i, _)| !drop.contains(i))
        .map(|(_, c)| c)
        .collect()
}

/// Keep the host plus `keep` trailing carrier code points.
fn truncate_after_host(text: &str, keep: usize) -> String {
    let host = HOST.chars().count();
    text.chars().take(host + keep).collect()
}

fn print_row(label: String, cells: impl Iterator<Item = Outcome>) {
    print!("{label:<20}");
    for c in cells {
        print!("{:<9}", c.label());
    }
    println!();
}

fn header(methods: &[Method], title: &str) {
    println!("\n{title}");
    print!("{:<20}", "");
    for m in methods {
        print!("{:<9}", m.name);
    }
    println!();
    println!("{}", "-".repeat(20 + 9 * methods.len()));
}

/// Emit each method's embedded text as JSON for an external transport driver.
fn emit() {
    let map: BTreeMap<&str, String> = methods()
        .into_iter()
        .map(|m| (m.name, m.embedded))
        .collect();
    println!(
        "{}",
        serde_json::to_string(&map).expect("serialize vectors")
    );
}

/// Classify a `{transport: {method: transformed_text}}` results file produced
/// by a real-transport driver, and print the matrix.
fn classify_file(path: &str) {
    let raw = std::fs::read_to_string(path).expect("read results file");
    let results: BTreeMap<String, BTreeMap<String, String>> =
        serde_json::from_str(&raw).expect("parse results json");
    let methods = methods();

    print!("{:<20}", "");
    for m in &methods {
        print!("{:<9}", m.name);
    }
    println!();
    println!("{}", "-".repeat(20 + 9 * methods.len()));
    for (transport, per_method) in &results {
        print!("{transport:<20}");
        for m in &methods {
            let cell = per_method
                .get(m.name)
                .map(|t| refine(m.name, t, (m.recover)(t)).label());
            print!("{:<9}", cell.unwrap_or("n/a"));
        }
        println!();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("emit") => emit(),
        Some("classify") => classify_file(args.get(2).expect("usage: classify <file>")),
        _ => tier0(),
    }
}

/// A method expressed for the corpus sweep: embed given (host, payload), and
/// classify given (transformed, host, payload). `embed` returns `None` when the
/// host cannot carry the method (e.g. too short for the Reed-Solomon watermark).
struct CorpusMethod {
    name: &'static str,
    embed: fn(&str, &[u8]) -> Option<String>,
    recover: fn(&str, &str, &[u8]) -> Outcome,
}

fn cm_v1_embed(h: &str, p: &[u8]) -> Option<String> {
    Some(vs::embed(h, p))
}
fn cm_v2_embed(h: &str, p: &[u8]) -> Option<String> {
    Some(vs::embed_v2(h, p, 0))
}
fn cm_vs_recover(t: &str, _h: &str, p: &[u8]) -> Outcome {
    vs_outcome(vs::extract(t), p)
}
fn cm_tag_embed(h: &str, p: &[u8]) -> Option<String> {
    Some(tag::embed(h, p))
}
fn cm_tag_recover(t: &str, _h: &str, p: &[u8]) -> Outcome {
    tag_outcome(tag::extract(t), p)
}
fn cm_zwbin_embed(h: &str, p: &[u8]) -> Option<String> {
    Some(zwbin::embed(h, p))
}
fn cm_zwbin_recover(t: &str, _h: &str, p: &[u8]) -> Outcome {
    zwbin_outcome(zwbin::extract(t), p)
}
fn cm_zwc_embed(h: &str, _p: &[u8]) -> Option<String> {
    stego::embed(h, KEY, ZWC_POINTER).ok()
}
fn cm_zwc_recover(t: &str, _h: &str, _p: &[u8]) -> Outcome {
    zwc_outcome(t)
}
fn cm_sim_embed(h: &str, _p: &[u8]) -> Option<String> {
    Some(h.to_string())
}
fn cm_sim_recover(t: &str, h: &str, _p: &[u8]) -> Outcome {
    if Fingerprint::compute(h).matches(&Fingerprint::compute(t).whole) {
        Outcome::Intact
    } else {
        Outcome::Gone
    }
}

fn corpus_methods() -> Vec<CorpusMethod> {
    vec![
        CorpusMethod {
            name: "vs-v1",
            embed: cm_v1_embed,
            recover: cm_vs_recover,
        },
        CorpusMethod {
            name: "vs-v2",
            embed: cm_v2_embed,
            recover: cm_vs_recover,
        },
        CorpusMethod {
            name: "zwc",
            embed: cm_zwc_embed,
            recover: cm_zwc_recover,
        },
        CorpusMethod {
            name: "tag",
            embed: cm_tag_embed,
            recover: cm_tag_recover,
        },
        CorpusMethod {
            name: "zwbin",
            embed: cm_zwbin_embed,
            recover: cm_zwbin_recover,
        },
        CorpusMethod {
            name: "simhash",
            embed: cm_sim_embed,
            recover: cm_sim_recover,
        },
    ]
}

/// Host texts spanning length, script, direction, emoji, legitimate variation
/// selectors, and irregular whitespace.
fn corpus_hosts() -> Vec<&'static str> {
    vec![
        "Short note: the quick brown fox jumps over the lazy dog by the riverbank.",
        HOST,
        "\u{6587}\u{7AE0}\u{306E}\u{6765}\u{6B74}\u{306F}\u{3001}\u{5185}\u{5BB9}\u{304C}\u{30B3}\u{30D4}\u{30FC}\u{3055}\u{308C}\u{518D}\u{30D5}\u{30A9}\u{30FC}\u{30DE}\u{30C3}\u{30C8}\u{3055}\u{308C}\u{8EFD}\u{304F}\u{7DE8}\u{96C6}\u{3055}\u{308C}\u{305F}\u{5F8C}\u{3067}\u{3082}\u{56DE}\u{5FA9}\u{3067}\u{304D}\u{308B}\u{5FC5}\u{8981}\u{304C}\u{3042}\u{308B}\u{3002}",
        "\u{064A}\u{062C}\u{0628} \u{0623}\u{0646} \u{064A}\u{0643}\u{0648}\u{0646} \u{0645}\u{0646} \u{0627}\u{0644}\u{0645}\u{0645}\u{0643}\u{0646} \u{0627}\u{0633}\u{062A}\u{0639}\u{0627}\u{062F}\u{0629} \u{0623}\u{0635}\u{0644} \u{0627}\u{0644}\u{0645}\u{0633}\u{062A}\u{0646}\u{062F} \u{062D}\u{062A}\u{0649} \u{0628}\u{0639}\u{062F} \u{0646}\u{0633}\u{062E}\u{0647} \u{0648}\u{062A}\u{062D}\u{0631}\u{064A}\u{0631}\u{0647}.",
        "Emoji punctuate this line \u{1F3A8}\u{1F4F7}\u{270D}\u{FE0F} where selectors \u{1F600}\u{1F680}\u{1F512} ride along with the rendered glyphs across the whole passage of text here.",
        "CJK variation sequences like \u{845B}\u{E0100} and \u{82A6}\u{E0101} appear legitimately in well-formed text and must never be mistaken for an embedded provenance wrapper.",
        "Whitespace   is    irregular\n\nhere,\twith  tabs and\nnewlines  scattered\n   throughout   the   entire   paragraph   to   exercise   normalization   and   reflow.",
    ]
}

fn corpus_payloads() -> Vec<Vec<u8>> {
    vec![
        b"https://fabrikam.com/manifests/a1b2c3.c2pa".to_vec(),
        (0..256u32).map(|i| (i * 31 + 7) as u8).collect(),
        (0..1024u32).map(|i| (i * 37 + 11) as u8).collect(),
    ]
}

/// Per-(method, transport) survival rate over the whole host x payload corpus.
fn corpus_survival() {
    let hosts = corpus_hosts();
    let payloads = corpus_payloads();
    let methods = corpus_methods();
    let cells = hosts.len() * payloads.len();

    println!("\n== corpus survival rate (intact / applicable, over {cells} host*payload cells) ==");
    print!("{:<20}", "");
    for m in &methods {
        print!("{:<9}", m.name);
    }
    println!();
    println!("{}", "-".repeat(20 + 9 * methods.len()));

    for (tname, tf) in transports() {
        print!("{tname:<20}");
        for m in &methods {
            let (mut intact, mut total) = (0u32, 0u32);
            for host in &hosts {
                for payload in &payloads {
                    if let Some(embedded) = (m.embed)(host, payload) {
                        total += 1;
                        if (m.recover)(&tf(&embedded), host, payload) == Outcome::Intact {
                            intact += 1;
                        }
                    }
                }
            }
            let cell = match (intact * 100).checked_div(total) {
                Some(pct) => format!("{pct}%"),
                None => "n/a".to_string(),
            };
            print!("{cell:<9}");
        }
        println!();
    }
}

type Hop = Box<dyn Fn(&str) -> String>;

fn hop<F: Fn(&str) -> String + 'static>(f: F) -> Hop {
    Box::new(f)
}

/// Named multi-hop journeys. Content rarely crosses a single transport; survival
/// compounds, and one lossy hop kills the whole chain.
fn journeys() -> Vec<(&'static str, Vec<Hop>)> {
    vec![
        (
            "nfc>nfkc",
            vec![hop(|s| s.nfc().collect()), hop(|s| s.nfkc().collect())],
        ),
        (
            "relay: 3x drop5%",
            vec![
                hop(|s| drop_carrier(s, 5)),
                hop(|s| drop_carrier(s, 5)),
                hop(|s| drop_carrier(s, 5)),
            ],
        ),
        (
            "edit: d8>nfkc>d8",
            vec![
                hop(|s| drop_carrier(s, 8)),
                hop(|s| s.nfkc().collect()),
                hop(|s| drop_carrier(s, 8)),
            ],
        ),
        (
            "web>bom-strip>nfc",
            vec![
                hop(|s| s.nfc().collect()),
                hop(|s| s.chars().filter(|&c| c != '\u{FEFF}').collect()),
                hop(|s| s.nfc().collect()),
            ],
        ),
    ]
}

fn tier0() {
    let methods = methods();

    header(
        &methods,
        "== categorical transports (codec failure-mode probes) ==",
    );
    for (name, tf) in transports() {
        print_row(
            name.to_string(),
            methods.iter().map(|m| {
                let t = tf(&m.embedded);
                refine(m.name, &t, (m.recover)(&t))
            }),
        );
    }

    header(
        &methods,
        "== partial carrier loss (recovery vs % code points dropped) ==",
    );
    for pct in [0u32, 5, 10, 20, 30, 50] {
        print_row(
            format!("drop-{pct}%"),
            methods.iter().map(|m| {
                let t = drop_carrier(&m.embedded, pct);
                refine(m.name, &t, (m.recover)(&t))
            }),
        );
    }

    header(
        &methods,
        "== tail truncation (host + N carrier code points kept) ==",
    );
    for keep in [0usize, 16, 50, 100, 300, 1200] {
        print_row(
            format!("keep-{keep}"),
            methods.iter().map(|m| {
                let t = truncate_after_host(&m.embedded, keep);
                refine(m.name, &t, (m.recover)(&t))
            }),
        );
    }

    header(
        &methods,
        "== loss structure at a fixed carrier-loss budget: scattered vs burst ==",
    );
    for (label, kind) in [
        ("scattered-15%", 0u8),
        ("burst-15%", 1),
        ("scattered-25%", 2),
        ("burst-25%", 3),
    ] {
        print_row(
            label.to_string(),
            methods.iter().map(|m| {
                let t = match kind {
                    0 => drop_carrier(&m.embedded, 15),
                    1 => burst_loss(&m.embedded, 15),
                    2 => drop_carrier(&m.embedded, 25),
                    _ => burst_loss(&m.embedded, 25),
                };
                refine(m.name, &t, (m.recover)(&t))
            }),
        );
    }

    header(&methods, "== multi-hop journeys (composed transports) ==");
    for (label, hops) in journeys() {
        print_row(
            label.to_string(),
            methods.iter().map(|m| {
                let t = hops.iter().fold(m.embedded.clone(), |acc, f| f(&acc));
                refine(m.name, &t, (m.recover)(&t))
            }),
        );
    }

    corpus_survival();
}
