// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `c2pa.soft-binding` assertion emitted for each algorithm in this family.
//!
//! This builds the normative `soft-binding-map` from the C2PA specification
//! (`soft-binding.cddl`) as deterministic CBOR. The structure mirrors the
//! `c2pa-rs` reference reader's `SoftBinding` type field-for-field, so the bytes
//! produced here deserialize directly into that reader — see
//! `tests/c2pa_roundtrip.rs`, which decodes them with the exact CBOR codec
//! (`c2pa_cbor`) that `c2pa-rs` uses and reconstructs its `SoftBinding`.
//!
//! Per the CDDL, a block's `value` is algorithm-specific. The reference reader
//! types it as a text string, so every value here is the algorithm's hex
//! encoding (the same hex the registry descriptions record). Window scopes for
//! the surface fingerprint are carried as textual character ranges
//! (`region-of-interest.cddl` `Textual`); the offsets are into the algorithm's
//! normalized character stream, which is where the fingerprint is computed.
//!
//! Emitting an assertion is not signing it: [`to_cbor`] returns the assertion
//! bytes, which the caller signs with [`crate::manifest::sign_cose`]. Presence
//! in the C2PA soft-binding algorithm list is not conformance certification.

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::minhash::MinHash;
use crate::simhash::{Fingerprint, Hash256};

/// The C2PA assertion label a soft-binding payload is stored under.
pub const SOFT_BINDING_LABEL: &str = "c2pa.soft-binding";

/// Registered algorithm identifier for `text-fingerprint.1` (list id 41).
pub const ALG_FINGERPRINT: &str = "com.writerslogic.text-fingerprint.1";
/// Registered algorithm identifier for `zwc-watermark.2` (list id 42).
pub const ALG_WATERMARK: &str = "com.writerslogic.zwc-watermark.2";
/// Registered algorithm identifier for `text-structure.1` (list id 43).
pub const ALG_STRUCTURE: &str = "com.writerslogic.text-structure.1";
/// Registered algorithm identifier for `text-minhash.1` (list id 44).
pub const ALG_MINHASH: &str = "com.writerslogic.text-minhash.1";

/// A `soft-binding-map`: one or more soft bindings over the asset's content.
///
/// Field layout and names match the C2PA CDDL and the `c2pa-rs` reader. `pad`
/// is always emitted (an empty byte string) as the reference writer does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftBinding {
    /// The registered soft-binding algorithm identifier.
    pub alg: String,
    /// One block per scoped soft-binding value.
    pub blocks: Vec<Block>,
    /// A human-readable description of what this binding covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Zero-filled padding; kept empty. Present to match the reference writer.
    #[serde(with = "serde_bytes")]
    pub pad: Vec<u8>,
}

/// A single `soft-binding-block-map`: a scope plus the value over that scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Where in the content this value applies.
    pub scope: Scope,
    /// The algorithm-specific value (hex) over this block of content.
    pub value: String,
}

/// A `soft-binding-scope-map`. Only the textual `region` is used by this family;
/// an empty scope means the whole asset.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// A region of interest bounding this block (textual character range).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<RegionOfInterest>,
}

/// A minimal region of interest carrying one or more `Range`s.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionOfInterest {
    /// The ranges making up this region.
    pub region: Vec<Range>,
}

/// A single range. Only the textual variant is produced here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// Range discriminator; always [`RangeType::Textual`] here.
    #[serde(rename = "type")]
    pub range_type: RangeType,
    /// The textual selection for a `Textual` range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<Text>,
}

/// The C2PA `RangeType` discriminator (camelCase on the wire).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RangeType {
    /// A textual character-offset range.
    Textual,
}

/// A textual range: one or more character-offset selectors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Text {
    /// The selected sub-ranges.
    pub selectors: Vec<TextSelectorRange>,
}

/// One `[start, end)` character range over the normalized stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextSelectorRange {
    /// The selector giving the start and end character offsets.
    pub selector: TextSelector,
}

/// A character-offset selector. `fragment` is required by the C2PA type; for
/// plain text there is no sub-resource, so it is empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextSelector {
    /// Sub-resource fragment identifier; empty for plain text.
    pub fragment: String,
    /// Start character offset into the normalized stream.
    pub start: Option<i32>,
    /// End character offset (exclusive) into the normalized stream.
    pub end: Option<i32>,
}

impl SoftBinding {
    /// A whole-asset soft binding: one block with an empty scope.
    pub fn whole(alg: &str, value_hex: String) -> Self {
        SoftBinding {
            alg: alg.to_string(),
            blocks: vec![Block {
                scope: Scope::default(),
                value: value_hex,
            }],
            name: None,
            pad: Vec::new(),
        }
    }

    /// Push a block scoped to the character range `[start, start+len)` of the
    /// normalized stream. Used to record the surface fingerprint's windows.
    pub fn push_window(&mut self, start: usize, len: usize, value_hex: String) {
        let s = i32::try_from(start).unwrap_or(i32::MAX);
        let e = i32::try_from(start.saturating_add(len)).unwrap_or(i32::MAX);
        self.blocks.push(Block {
            scope: Scope {
                region: Some(RegionOfInterest {
                    region: vec![Range {
                        range_type: RangeType::Textual,
                        text: Some(Text {
                            selectors: vec![TextSelectorRange {
                                selector: TextSelector {
                                    fragment: String::new(),
                                    start: Some(s),
                                    end: Some(e),
                                },
                            }],
                        }),
                    }],
                }),
            },
            value: value_hex,
        });
    }

    /// Serialize to deterministic CBOR (the assertion payload to be signed).
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out)
            .map_err(|e| Error::GenerationFailed(format!("soft-binding CBOR encode: {e}")))?;
        Ok(out)
    }

    /// Parse a soft-binding assertion back from CBOR (for verifiers and tests).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes)
            .map_err(|e| Error::InvalidInput(format!("soft-binding CBOR decode: {e}")))
    }
}

/// Build the `text-fingerprint.1` (list id 41) soft binding: the whole-document
/// SimHash plus one scoped block per overlapping window.
pub fn from_fingerprint(fp: &Fingerprint) -> SoftBinding {
    let mut sb = SoftBinding::whole(ALG_FINGERPRINT, fp.whole.to_hex());
    for w in &fp.windows {
        sb.push_window(w.start, w.len, w.hash.to_hex());
    }
    sb
}

/// Build the `text-structure.1` (list id 43) soft binding: the whole-document
/// structural SimHash.
pub fn from_structure(hash: &Hash256) -> SoftBinding {
    SoftBinding::whole(ALG_STRUCTURE, hash.to_hex())
}

/// Build the `text-minhash.1` (list id 44) soft binding. The value is the 128
/// signature values as big-endian `u64` bytes, hex-encoded — a deterministic,
/// verifier-reproducible serialization of the recorded signature.
pub fn from_minhash(mh: &MinHash) -> SoftBinding {
    let mut bytes = Vec::with_capacity(mh.sig.len() * 8);
    for v in &mh.sig {
        bytes.extend_from_slice(&v.to_be_bytes());
    }
    SoftBinding::whole(ALG_MINHASH, hex::encode(bytes))
}

/// Build the `zwc-watermark.2` (list id 42) soft binding. The value is the
/// routing pointer embedded in the carrier, hex-encoded — the identifier a
/// manifest repository is keyed by.
pub fn from_watermark_pointer(pointer: &[u8]) -> SoftBinding {
    SoftBinding::whole(ALG_WATERMARK, hex::encode(pointer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_binding_roundtrips_through_cbor() {
        let sb = SoftBinding::whole(ALG_FINGERPRINT, "deadbeef".into());
        let bytes = sb.to_cbor().unwrap();
        assert_eq!(SoftBinding::from_cbor(&bytes).unwrap(), sb);
    }

    #[test]
    fn windows_carry_textual_char_ranges() {
        let mut sb = SoftBinding::whole(ALG_FINGERPRINT, "00".into());
        sb.push_window(0, 512, "11".into());
        sb.push_window(256, 512, "22".into());
        assert_eq!(sb.blocks.len(), 3);
        let win = &sb.blocks[1];
        let sel = &win.scope.region.as_ref().unwrap().region[0]
            .text
            .as_ref()
            .unwrap()
            .selectors[0]
            .selector;
        assert_eq!(sel.start, Some(0));
        assert_eq!(sel.end, Some(512));
        // Whole-asset block one has no region.
        assert!(sb.blocks[0].scope.region.is_none());
        let bytes = sb.to_cbor().unwrap();
        assert_eq!(SoftBinding::from_cbor(&bytes).unwrap(), sb);
    }

    #[test]
    fn alg_is_required_and_present() {
        let sb = SoftBinding::whole(ALG_WATERMARK, "abcd".into());
        let bytes = sb.to_cbor().unwrap();
        // The decoded map must carry a non-empty alg (CDDL: no default).
        let back = SoftBinding::from_cbor(&bytes).unwrap();
        assert_eq!(back.alg, ALG_WATERMARK);
        assert!(!back.blocks.is_empty());
    }
}
