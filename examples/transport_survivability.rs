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
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Intact => "intact",
            Outcome::Gone => "gone",
            Outcome::Safe => "safe",
            Outcome::Unsafe => "UNSAFE",
        }
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

fn main() {
    let methods = methods();

    header(
        &methods,
        "== categorical transports (codec failure-mode probes) ==",
    );
    for (name, tf) in transports() {
        print_row(
            name.to_string(),
            methods.iter().map(|m| (m.recover)(&tf(&m.embedded))),
        );
    }

    header(
        &methods,
        "== partial carrier loss (recovery vs % code points dropped) ==",
    );
    for pct in [0u32, 5, 10, 20, 30, 50] {
        print_row(
            format!("drop-{pct}%"),
            methods
                .iter()
                .map(|m| (m.recover)(&drop_carrier(&m.embedded, pct))),
        );
    }

    header(
        &methods,
        "== tail truncation (host + N carrier code points kept) ==",
    );
    for keep in [0usize, 16, 50, 100, 300, 1200] {
        print_row(
            format!("keep-{keep}"),
            methods
                .iter()
                .map(|m| (m.recover)(&truncate_after_host(&m.embedded, keep))),
        );
    }
}
