// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-implementation interoperability with Encypher's `c2pa-text`, the A.8
//! originator's reference library.
//!
//! `ENCYPHER_WRAPPER` is the exact UTF-8 output of `c2pa_text.encode_wrapper`
//! (captured from the installed reference library; regenerate with
//! `harness/interop.py`) for `PAYLOAD`. Interoperability is real, not
//! self-referential, only if both directions hold: this crate's decoder reads
//! Encypher's encoded bytes, and this crate's encoder produces byte-identical
//! bytes. Encypher's wrapper is byte-identical to A.8 v1 (same `C2PATXT\0`
//! magic, version 1, and `U+FEFF` marker).

use c2pa_text_binding::vs;

const PAYLOAD_HEX: &str = "633270612d6d616e69666573742d3031";
const ENCYPHER_WRAPPER_HEX: &str = "efbbbff3a084b3f3a084a2f3a08580f3a084b1f3a08584f3a08588f3a08584efb880efb881efb880efb880efb880f3a08480f3a08593f3a084a2f3a085a0f3a08591f3a0849df3a0859df3a08591f3a0859ef3a08599f3a08596f3a08595f3a085a3f3a085a4f3a0849df3a084a0f3a084a1";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn decodes_encypher_reference_output() {
    let text =
        String::from_utf8(unhex(ENCYPHER_WRAPPER_HEX)).expect("reference output is valid UTF-8");
    match vs::extract(&text) {
        vs::Decoded::Payload(p) => assert_eq!(p, unhex(PAYLOAD_HEX)),
        other => panic!("this crate failed to decode Encypher's wrapper: {other:?}"),
    }
}

#[test]
fn encoder_is_byte_identical_to_encypher() {
    let ours = vs::encode(&unhex(PAYLOAD_HEX));
    assert_eq!(
        ours.as_bytes(),
        unhex(ENCYPHER_WRAPPER_HEX).as_slice(),
        "A.8 wrapper bytes must match the Encypher reference library exactly",
    );
}
