// SPDX-License-Identifier: MIT OR Apache-2.0

//! `wasm-bindgen` facade for the browser. Compiled only for `wasm32`.
//!
//! Everything runs client-side: the sign/verify flows never send text to a
//! server. Functions are granular so the JS layer assembles the manifest and
//! performs comparisons; nothing here needs a JSON dependency.

use crate::{crosscheck, manifest, minhash, simhash, soft_binding, stego, structure};
use wasm_bindgen::prelude::*;

fn parse_key32(hex_str: &str) -> Result<[u8; 32], JsError> {
    let v = hex::decode(hex_str.trim()).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    if v.len() != 32 {
        return Err(JsError::new("expected a 32-byte (64 hex char) key"));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    Ok(k)
}

/// `com.writerslogic.text-fingerprint.1` — 256-bit surface SimHash, hex.
#[wasm_bindgen]
pub fn text_fingerprint(text: &str) -> String {
    simhash::Fingerprint::compute(text).whole.to_hex()
}

/// `com.writerslogic.text-structure.1` — 256-bit structural SimHash, hex.
#[wasm_bindgen]
pub fn text_structure(text: &str) -> String {
    structure::compute(text).to_hex()
}

/// `com.writerslogic.text-minhash.1` — 128 signature values, comma-joined.
#[wasm_bindgen]
pub fn minhash_signature(text: &str) -> String {
    minhash::MinHash::compute(text)
        .sig
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// The 32 LSH band hashes, comma-joined — index keys for discovery.
#[wasm_bindgen]
pub fn minhash_bands(text: &str) -> String {
    minhash::MinHash::compute(text)
        .bands
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Hamming distance in bits between two 256-bit hex fingerprints.
#[wasm_bindgen]
pub fn hamming_hex(a: &str, b: &str) -> Result<u32, JsError> {
    let ha = simhash::Hash256::from_hex(a.trim()).ok_or_else(|| JsError::new("bad hex a"))?;
    let hb = simhash::Hash256::from_hex(b.trim()).ok_or_else(|| JsError::new("bad hex b"))?;
    Ok(ha.hamming(&hb))
}

/// Estimated Jaccard from two comma-joined MinHash signatures.
#[wasm_bindgen]
pub fn minhash_jaccard(sig_a: &str, sig_b: &str) -> Result<f64, JsError> {
    let a = parse_sig(sig_a)?;
    let b = parse_sig(sig_b)?;
    let equal = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    Ok(equal as f64 / minhash::NUM_PERM as f64)
}

fn parse_sig(s: &str) -> Result<Vec<u64>, JsError> {
    let v: Result<Vec<u64>, _> = s.split(',').map(|p| p.trim().parse::<u64>()).collect();
    let v = v.map_err(|e| JsError::new(&format!("invalid signature: {e}")))?;
    if v.len() != minhash::NUM_PERM {
        return Err(JsError::new("signature must have 128 values"));
    }
    Ok(v)
}

/// SHA-256 of the canonical stream (the blind-recoverable content hash), hex.
#[wasm_bindgen]
pub fn content_hash(text: &str) -> String {
    hex::encode(stego::content_hash(text))
}

/// Embed a `zwc-watermark.2` carrying `pointer_hex`, bound to the content by
/// `key_hex`. Returns the watermarked text.
#[wasm_bindgen]
pub fn embed_watermark(text: &str, pointer_hex: &str, key_hex: &str) -> Result<String, JsError> {
    let key = hex::decode(key_hex.trim()).map_err(|e| JsError::new(&format!("bad key: {e}")))?;
    let pointer =
        hex::decode(pointer_hex.trim()).map_err(|e| JsError::new(&format!("bad pointer: {e}")))?;
    stego::embed(text, &key, &pointer).map_err(|e| JsError::new(&e.to_string()))
}

/// Blind-extract and verify a `zwc-watermark.2`. Returns
/// `{"pointer":"<hex>","verified":<bool>,"recovered":<n>}`.
#[wasm_bindgen]
pub fn extract_watermark(text: &str, key_hex: &str) -> Result<String, JsError> {
    let key = hex::decode(key_hex.trim()).map_err(|e| JsError::new(&format!("bad key: {e}")))?;
    let rec = stego::extract(text, &key).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(format!(
        "{{\"pointer\":\"{}\",\"verified\":{},\"recovered\":{}}}",
        hex::encode(rec.pointer),
        rec.tag_verified,
        rec.shards_recovered
    ))
}

/// Derive the Ed25519 public key (hex) from a 32-byte secret key (hex).
#[wasm_bindgen]
pub fn public_key(secret_hex: &str) -> Result<String, JsError> {
    let mut sk = parse_key32(secret_hex)?;
    let pk = manifest::public_key(&sk);
    sk.iter_mut().for_each(|b| *b = 0);
    Ok(hex::encode(pk))
}

/// Sign a payload (e.g. the soft-binding assertion JSON) as tagged
/// COSE_Sign1 / EdDSA. Returns the envelope as hex.
#[wasm_bindgen]
pub fn sign(payload: &str, secret_hex: &str) -> Result<String, JsError> {
    let mut sk = parse_key32(secret_hex)?;
    let out =
        manifest::sign_cose(payload.as_bytes(), &sk).map_err(|e| JsError::new(&e.to_string()));
    sk.iter_mut().for_each(|b| *b = 0);
    Ok(hex::encode(out?))
}

/// Verify a hex COSE_Sign1 envelope against a hex public key; returns the
/// payload string on success, throws on failure.
#[wasm_bindgen]
pub fn verify(cose_hex: &str, public_hex: &str) -> Result<String, JsError> {
    let pk = parse_key32(public_hex)?;
    let cose = hex::decode(cose_hex.trim()).map_err(|e| JsError::new(&format!("bad cose: {e}")))?;
    let payload = manifest::verify_cose(&cose, &pk).map_err(|e| JsError::new(&e.to_string()))?;
    String::from_utf8(payload).map_err(|e| JsError::new(&format!("payload not utf-8: {e}")))
}

/// Build the `c2pa.soft-binding` assertion (list id 41, surface fingerprint)
/// as CBOR, hex-encoded. Sign the result with [`sign`] and store it under the
/// `c2pa.soft-binding` label. Includes per-window scoped blocks.
#[wasm_bindgen]
pub fn soft_binding_fingerprint(text: &str) -> String {
    let fp = simhash::Fingerprint::compute(text);
    let sb = soft_binding::from_fingerprint(&fp);
    hex::encode(sb.to_cbor().expect("soft-binding CBOR encode"))
}

/// Build the `c2pa.soft-binding` assertion (list id 43, structural) as CBOR hex.
#[wasm_bindgen]
pub fn soft_binding_structure(text: &str) -> String {
    let sb = soft_binding::from_structure(&structure::compute(text));
    hex::encode(sb.to_cbor().expect("soft-binding CBOR encode"))
}

/// Build the `c2pa.soft-binding` assertion (list id 44, MinHash) as CBOR hex.
#[wasm_bindgen]
pub fn soft_binding_minhash(text: &str) -> String {
    let sb = soft_binding::from_minhash(&minhash::MinHash::compute(text));
    hex::encode(sb.to_cbor().expect("soft-binding CBOR encode"))
}

/// Build the `c2pa.soft-binding` assertion (list id 42, ZWC watermark) for a
/// routing `pointer_hex`, as CBOR hex.
#[wasm_bindgen]
pub fn soft_binding_watermark(pointer_hex: &str) -> Result<String, JsError> {
    let pointer =
        hex::decode(pointer_hex.trim()).map_err(|e| JsError::new(&format!("bad pointer: {e}")))?;
    let sb = soft_binding::from_watermark_pointer(&pointer);
    Ok(hex::encode(
        sb.to_cbor().map_err(|e| JsError::new(&e.to_string()))?,
    ))
}

/// Anti-transfer cross-check tag (hex): `HMAC(key, repo_id ‖ content_hash)`.
#[wasm_bindgen]
pub fn cross_check(
    key_hex: &str,
    repo_id: &str,
    content_hash_hex: &str,
) -> Result<String, JsError> {
    let key = hex::decode(key_hex.trim()).map_err(|e| JsError::new(&format!("bad key: {e}")))?;
    let ch = hex::decode(content_hash_hex.trim())
        .map_err(|e| JsError::new(&format!("bad content hash: {e}")))?;
    Ok(hex::encode(crosscheck::crosscheck_tag(
        &key,
        repo_id.as_bytes(),
        &ch,
    )))
}
