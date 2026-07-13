// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof that the `c2pa.soft-binding` assertions this crate emits round-trip
//! through the C2PA reference reader.
//!
//! The bytes from [`SoftBinding::to_cbor`] are decoded with `c2pa_cbor` — the
//! exact CBOR codec `c2pa-rs` calls in `AssertionCbor::from_cbor_assertion` —
//! into `c2pa::assertions::SoftBinding`, the reader's own assertion type. If the
//! fields populate and re-encode identically, the assertion is well-formed for
//! that reader. This is a build-time conformance check, not a claim of C2PA
//! conformance certification.

use c2pa::assertions::region_of_interest::RegionOfInterest;
use c2pa::assertions::SoftBinding as C2paSoftBinding;
use c2pa_text_binding::{
    minhash::MinHash,
    simhash::Fingerprint,
    soft_binding::{
        self, ALG_FINGERPRINT, ALG_MINHASH, ALG_STRUCTURE, ALG_WATERMARK, SOFT_BINDING_LABEL,
    },
    structure,
};

const LONG: &str = "The principles of provenance require that a document's origin can be \
    recovered even after it has been copied, reformatted, or lightly edited. A soft binding \
    derives a durable value from the words themselves so that a manifest can be found again \
    when the embedded one is stripped away by a careless copy-paste or an aggressive text \
    pipeline that normalizes everything in sight. Text is mutable, so no single technique \
    wins; a family of algorithms with different fragility profiles is combined by the verifier.";

// Decode our emitted assertion bytes into the c2pa-rs reader's SoftBinding type
// using the reader's own CBOR codec.
fn read_with_c2pa(bytes: &[u8]) -> C2paSoftBinding {
    c2pa_cbor::from_slice(bytes).expect("c2pa-rs reader must decode the soft-binding assertion")
}

#[test]
fn label_matches_reference_reader() {
    assert_eq!(SOFT_BINDING_LABEL, C2paSoftBinding::LABEL);
    assert_eq!(SOFT_BINDING_LABEL, "c2pa.soft-binding");
}

#[test]
fn fingerprint_assertion_roundtrips_through_c2pa() {
    let fp = Fingerprint::compute(&LONG.repeat(4)); // long enough to have windows
    let sb = soft_binding::from_fingerprint(&fp);
    assert!(!fp.windows.is_empty(), "test text must exercise windows");

    let bytes = sb.to_cbor().unwrap();
    let read = read_with_c2pa(&bytes);

    assert_eq!(read.alg.as_deref(), Some(ALG_FINGERPRINT));
    // whole + one block per window, all present in the reader's view.
    assert_eq!(read.blocks.len(), 1 + fp.windows.len());
    assert_eq!(read.blocks[0].value, fp.whole.to_hex());

    // The whole-document block is unscoped; each window carries a textual region
    // whose character offsets survive the round-trip.
    assert!(read.blocks[0].scope.region.is_none());
    for (block, win) in read.blocks[1..].iter().zip(&fp.windows) {
        let region: &RegionOfInterest = block
            .scope
            .region
            .as_ref()
            .expect("window block must carry a region");
        let text = region.region[0]
            .text
            .as_ref()
            .expect("textual range expected");
        let sel = &text.selectors[0].selector;
        assert_eq!(sel.start, Some(win.start as i32));
        assert_eq!(sel.end, Some((win.start + win.len) as i32));
        assert_eq!(block.value, win.hash.to_hex());
    }
}

#[test]
fn structure_assertion_roundtrips_through_c2pa() {
    let sb = soft_binding::from_structure(&structure::compute(LONG));
    let read = read_with_c2pa(&sb.to_cbor().unwrap());
    assert_eq!(read.alg.as_deref(), Some(ALG_STRUCTURE));
    assert_eq!(read.blocks.len(), 1);
    assert_eq!(read.blocks[0].value, structure::compute(LONG).to_hex());
}

#[test]
fn minhash_assertion_roundtrips_through_c2pa() {
    let mh = MinHash::compute(LONG);
    let sb = soft_binding::from_minhash(&mh);
    let read = read_with_c2pa(&sb.to_cbor().unwrap());
    assert_eq!(read.alg.as_deref(), Some(ALG_MINHASH));
    assert_eq!(read.blocks.len(), 1);
    // Value is the 128 signature words, big-endian, hex: 128 * 8 * 2 chars.
    assert_eq!(
        read.blocks[0].value.len(),
        MinHash::compute(LONG).sig.len() * 16
    );
}

#[test]
fn watermark_assertion_roundtrips_through_c2pa() {
    let pointer = b"c2pa-manifest-01";
    let sb = soft_binding::from_watermark_pointer(pointer);
    let read = read_with_c2pa(&sb.to_cbor().unwrap());
    assert_eq!(read.alg.as_deref(), Some(ALG_WATERMARK));
    assert_eq!(read.blocks.len(), 1);
    assert_eq!(read.blocks[0].value, hex::encode(pointer));
}

#[test]
fn reencoding_from_reader_is_stable() {
    // Encode -> decode into the reader's type -> re-encode with the reader's
    // codec -> decode again: the reader's view is a fixed point.
    let sb = soft_binding::from_structure(&structure::compute(LONG));
    let ours = sb.to_cbor().unwrap();
    let read1 = read_with_c2pa(&ours);
    let reencoded = c2pa_cbor::to_vec(&read1).unwrap();
    let read2 = read_with_c2pa(&reencoded);
    assert_eq!(read1, read2);
}
