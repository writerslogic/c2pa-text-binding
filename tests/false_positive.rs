// SPDX-License-Identifier: MIT OR Apache-2.0

//! False-positive and cross-carrier controls.
//!
//! A survival benchmark is only half a benchmark without a false-positive axis:
//! a decoder must not hallucinate a payload in clean text (including text that
//! legitimately contains variation selectors, per the Unicode security notes),
//! and one carrier's output must not decode as another carrier's payload.

use c2pa_text_binding::{tag, vs, zwbin};

const CLEAN: &[&str] = &[
    "A perfectly ordinary paragraph with no hidden provenance whatsoever.",
    "Emoji carry legitimate variation selectors: a smiley \u{263A}\u{FE0F} and a heart \u{2764}\u{FE0F}.",
    "CJK ideographic variation sequence: \u{845B}\u{E0100} is a valid rendering hint.",
    "A stray zero-width joiner \u{200D} and no-break space \u{FEFF} without any magic.",
    "",
];

fn vs_is_payload(s: &str) -> bool {
    matches!(vs::extract(s), vs::Decoded::Payload(_))
}
fn tag_is_payload(s: &str) -> bool {
    matches!(tag::extract(s), tag::Decoded::Payload(_))
}
fn zwbin_is_payload(s: &str) -> bool {
    matches!(zwbin::extract(s), zwbin::Decoded::Payload(_))
}

#[test]
fn clean_text_yields_no_manifest() {
    for &text in CLEAN {
        assert!(!vs_is_payload(text), "vs false-positive on: {text:?}");
        assert!(!tag_is_payload(text), "tag false-positive on: {text:?}");
        assert!(!zwbin_is_payload(text), "zwbin false-positive on: {text:?}");
    }
}

#[test]
fn carriers_do_not_confuse_each_other() {
    let host = "The document body used for every carrier under test here.";
    let payload = b"https://fabrikam.com/m/a1b2c3.c2pa";

    let vs_text = vs::embed(host, payload);
    let vs2_text = vs::embed_v2(host, payload, 0);
    let tag_text = tag::embed(host, payload);
    let zwbin_text = zwbin::embed(host, payload);

    // No decoder may return a payload for a carrier that is not its own.
    assert!(!tag_is_payload(&vs_text) && !zwbin_is_payload(&vs_text));
    assert!(!tag_is_payload(&vs2_text) && !zwbin_is_payload(&vs2_text));
    assert!(!vs_is_payload(&tag_text) && !zwbin_is_payload(&tag_text));
    assert!(!vs_is_payload(&zwbin_text) && !tag_is_payload(&zwbin_text));

    // Sanity: each decoder still recovers its own payload.
    assert!(vs_is_payload(&vs_text));
    assert!(vs_is_payload(&vs2_text));
    assert!(tag_is_payload(&tag_text));
    assert!(zwbin_is_payload(&zwbin_text));
}
