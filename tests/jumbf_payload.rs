// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real JUMBF-structured payloads for the carrier.
//!
//! The transport benchmark otherwise carries opaque bytes. This proves the
//! variation-selector carrier round-trips a genuine C2PA content structure — a
//! real COSE_Sign1 signature (Ed25519, as `manifest::sign_cose` produces),
//! wrapped in a JUMBF superbox (4-byte big-endian length + `jumb` type) — and
//! demonstrates the truncation detection a self-delimiting v2 decoder should
//! rely on: the JUMBF box declares its own length, so a short run is detectable
//! without a wrapper length field.
//!
//! (A fully signed manifest store via the external `c2pa` Builder needs a test
//! signer and a source asset; the content here is real C2PA crypto, wrapped in a
//! real JUMBF box, which is what the carrier and the length-detection property
//! actually exercise.)

use c2pa_text_binding::manifest::sign_cose;
use c2pa_text_binding::vs;

/// Wrap `content` in a JUMBF superbox: 4-byte big-endian length, `jumb` type.
fn jumbf_box(content: &[u8]) -> Vec<u8> {
    let total = (content.len() + 8) as u32;
    let mut b = Vec::with_capacity(content.len() + 8);
    b.extend_from_slice(&total.to_be_bytes());
    b.extend_from_slice(b"jumb");
    b.extend_from_slice(content);
    b
}

/// Declared total length from a JUMBF box header, if this looks like one.
fn jumbf_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() >= 8 && &bytes[4..8] == b"jumb" {
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
    } else {
        None
    }
}

fn real_manifest_payload() -> Vec<u8> {
    let key = [7u8; 32];
    let claim = b"c2pa claim bytes bound by a real Ed25519 COSE_Sign1 signature";
    let cose = sign_cose(claim, &key).expect("COSE signing must succeed");
    jumbf_box(&cose)
}

#[test]
fn real_jumbf_payload_round_trips() {
    let payload = real_manifest_payload();
    assert_eq!(
        jumbf_len(&payload),
        Some(payload.len()),
        "box must be self-consistent"
    );

    let text = vs::embed("A document carrying a genuine C2PA manifest.", &payload);
    match vs::extract(&text) {
        vs::Decoded::Payload(p) => {
            assert_eq!(p, payload);
            assert_eq!(
                jumbf_len(&p),
                Some(p.len()),
                "recovered box length is intact"
            );
        }
        other => panic!("expected the real JUMBF payload back, got {other:?}"),
    }
}

#[test]
fn jumbf_length_detects_truncation() {
    // The property a fixed v2 (self-delimiting) decoder relies on: the JUMBF box
    // declares its own length, so a truncated payload is detectable even with no
    // wrapper length field — the box says more bytes should follow than remain.
    let payload = real_manifest_payload();
    let truncated = &payload[..payload.len() - 16];
    let declared = jumbf_len(truncated).expect("header survives a tail truncation");
    assert!(
        declared > truncated.len(),
        "JUMBF length ({declared}) exceeds the {} bytes present -> truncation detected",
        truncated.len(),
    );
}
