// SPDX-License-Identifier: MIT OR Apache-2.0

//! Property-based fail-safety tests for the invisible-text carriers.
//!
//! The safety invariant a provenance carrier must hold: after any lossy
//! transport it may return the correct payload or reject (None/Corrupt/error),
//! but it must never silently return a *different* payload. These properties
//! search the input space for such UNSAFE decodes automatically — the way the
//! v2 self-delimiting frame's UNSAFE behavior was first found by hand.
//!
//! They also characterize the integrity gap: `stego`'s HMAC content-binding tag
//! makes "verified implies correct" hold under any mutation, while the raw
//! carriers have no integrity check and can be driven to a wrong payload by byte
//! modification (not just truncation) — so A.8 needs a checksum, not only a
//! length field.

use c2pa_text_binding::{stego, vs};
use proptest::prelude::*;

const KEY: &[u8] = b"fail-safety-fixed-key-0001";

const HOST: &str = "\
Provenance travels with content when the carrier survives the journey. A reader \
copies a paragraph from one application and pastes it into another, and along \
the way the text passes through clipboards, editors, message queues, and \
storage layers that each rewrite what they consider formatting, so a careful \
codec must fail safe rather than return something plausible but wrong today.";

#[derive(Debug, Clone)]
enum Op {
    Drop(usize),
    Truncate(usize),
    Remap(usize),
}

/// Apply lossy operations to a carrier string. `allow_remap` enables byte
/// modification of variation selectors (vs. drop/truncate only).
fn apply(text: &str, ops: &[Op], allow_remap: bool) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    for op in ops {
        if chars.is_empty() {
            break;
        }
        match *op {
            Op::Drop(i) => {
                chars.remove(i % chars.len());
            }
            Op::Truncate(k) => {
                let n = chars.len().saturating_sub(k % (chars.len() + 1));
                chars.truncate(n);
            }
            Op::Remap(i) if allow_remap => {
                let i = i % chars.len();
                if let Some(b) = vs::vs_to_byte(chars[i]) {
                    chars[i] = vs::byte_to_vs(b.wrapping_add(1));
                }
            }
            Op::Remap(_) => {}
        }
    }
    chars.into_iter().collect()
}

fn op_strategy() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        prop_oneof![
            any::<usize>().prop_map(Op::Drop),
            any::<usize>().prop_map(Op::Truncate),
            any::<usize>().prop_map(Op::Remap),
        ],
        0..8,
    )
}

proptest! {
    /// A.8 v1's length field makes *tail truncation* fail-safe: a shortened run
    /// no longer satisfies the declared length, so `extract` rejects rather than
    /// return a wrong payload.
    ///
    /// Property testing disproved the stronger claim (drop-safety in general): an
    /// interior drop landing in the 4-byte length field can shrink the declared
    /// length so the shortened run still satisfies it, yielding a wrong payload.
    /// The length field is not self-protecting — see the characterizations below;
    /// A.8 needs a checksum, not just a length.
    #[test]
    fn vs_v1_tail_truncation_is_fail_safe(
        payload in prop::collection::vec(any::<u8>(), 1..200),
        cut in 0usize..400,
    ) {
        let full = vs::embed("", &payload);
        let keep = full.chars().count().saturating_sub(cut);
        let truncated: String = full.chars().take(keep).collect();
        if let vs::Decoded::Payload(p) = vs::extract(&truncated) {
            prop_assert_eq!(p, payload.clone());
        }
    }

    /// `stego`'s HMAC content-binding tag makes a verified recovery always
    /// correct, under any mutation including byte modification.
    #[test]
    fn zwc_verified_is_always_correct(
        ptr in prop::collection::vec(any::<u8>(), 1..=stego::POINTER_LEN),
        ops in op_strategy(),
    ) {
        let mut want = [0u8; stego::POINTER_LEN];
        want[..ptr.len()].copy_from_slice(&ptr);
        if let Ok(embedded) = stego::embed(HOST, KEY, &ptr) {
            let mangled = apply(&embedded, &ops, true);
            if let Ok(r) = stego::extract(&mangled, KEY) {
                if r.tag_verified {
                    prop_assert_eq!(r.pointer, want);
                }
            }
        }
    }
}

/// Characterization: with no integrity field, byte *modification* of the payload
/// region yields a wrong payload that still parses — UNSAFE. Locks in the
/// conclusion that A.8 needs a checksum, not just a length. (This is why the
/// property above restricts v1 to drop/truncate.)
#[test]
fn v1_without_integrity_returns_wrong_payload_under_modification() {
    let payload = b"AAAAAAAA".to_vec();
    let mut chars: Vec<char> = vs::embed("", &payload).chars().collect();
    let last = chars.len() - 1;
    let b = vs::vs_to_byte(chars[last]).expect("last char is a variation selector");
    chars[last] = vs::byte_to_vs(b ^ 0xFF);
    let mangled: String = chars.into_iter().collect();
    match vs::extract(&mangled) {
        vs::Decoded::Payload(p) => {
            assert_ne!(
                p, payload,
                "modified payload still parsed; no integrity check"
            )
        }
        other => panic!("expected a wrong-payload (UNSAFE) decode, got {other:?}"),
    }
}

/// Characterization of the case property testing found: the run layout is
/// `[FEFF][magic x8][version][length x4][payload]`, so dropping the low length
/// byte shifts a zero payload byte into the length field. The declared length
/// becomes 0 and `extract` returns an empty (wrong) payload — the length field
/// does not protect itself, reinforcing the need for a checksum.
#[test]
fn v1_length_field_drop_yields_wrong_payload() {
    let payload = vec![0u8; 40];
    let mut chars: Vec<char> = vs::embed("", &payload).chars().collect();
    chars.remove(13); // low byte of the big-endian length field
    let mangled: String = chars.into_iter().collect();
    match vs::extract(&mangled) {
        vs::Decoded::Payload(p) => {
            assert_ne!(p, payload, "length-field drop returned a wrong payload")
        }
        other => panic!("expected an UNSAFE decode from length corruption, got {other:?}"),
    }
}
