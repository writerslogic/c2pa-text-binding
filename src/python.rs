// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native Python bindings (feature `python`), packaged as a wheel by maturin.
//!
//! The surface mirrors the wasm facade: text in, hex/`int`-list out, so a Python
//! caller assembles the manifest and performs comparisons without a CBOR
//! dependency. Everything runs in-process; no text is sent anywhere. Secret key
//! material is zeroed after use.

use crate::{crosscheck, manifest, minhash, simhash, soft_binding, stego, structure};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn hexerr(what: &str, e: impl core::fmt::Display) -> PyErr {
    PyValueError::new_err(format!("invalid {what}: {e}"))
}

fn parse_key32(hex_str: &str) -> PyResult<[u8; 32]> {
    let v = hex::decode(hex_str.trim()).map_err(|e| hexerr("hex", e))?;
    if v.len() != 32 {
        return Err(PyValueError::new_err(
            "expected a 32-byte (64 hex char) key",
        ));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    Ok(k)
}

/// `com.writerslogic.text-fingerprint.1` — 256-bit surface SimHash, hex.
#[pyfunction]
fn text_fingerprint(text: &str) -> String {
    simhash::Fingerprint::compute(text).whole.to_hex()
}

/// `com.writerslogic.text-structure.1` — 256-bit structural SimHash, hex.
#[pyfunction]
fn text_structure(text: &str) -> String {
    structure::compute(text).to_hex()
}

/// `com.writerslogic.text-minhash.1` — the 128 signature values.
#[pyfunction]
fn minhash_signature(text: &str) -> Vec<u64> {
    minhash::MinHash::compute(text).sig.to_vec()
}

/// The 32 LSH band hashes — index keys for discovery.
#[pyfunction]
fn minhash_bands(text: &str) -> Vec<u64> {
    minhash::MinHash::compute(text).bands.to_vec()
}

/// Hamming distance in bits between two 256-bit hex fingerprints.
#[pyfunction]
fn hamming_hex(a: &str, b: &str) -> PyResult<u32> {
    let ha =
        simhash::Hash256::from_hex(a.trim()).ok_or_else(|| PyValueError::new_err("bad hex a"))?;
    let hb =
        simhash::Hash256::from_hex(b.trim()).ok_or_else(|| PyValueError::new_err("bad hex b"))?;
    Ok(ha.hamming(&hb))
}

/// SHA-256 of the canonical stream (the blind-recoverable content hash), hex.
#[pyfunction]
fn content_hash(text: &str) -> String {
    hex::encode(stego::content_hash(text))
}

/// Embed a `zwc-watermark.2` carrying `pointer_hex`, bound to the content by
/// `key_hex`. Returns the watermarked text.
#[pyfunction]
fn embed_watermark(text: &str, pointer_hex: &str, key_hex: &str) -> PyResult<String> {
    let key = hex::decode(key_hex.trim()).map_err(|e| hexerr("key", e))?;
    let pointer = hex::decode(pointer_hex.trim()).map_err(|e| hexerr("pointer", e))?;
    stego::embed(text, &key, &pointer).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Blind-extract and verify a `zwc-watermark.2`.
/// Returns `(pointer_hex, tag_verified, shards_recovered)`.
#[pyfunction]
fn extract_watermark(text: &str, key_hex: &str) -> PyResult<(String, bool, usize)> {
    let key = hex::decode(key_hex.trim()).map_err(|e| hexerr("key", e))?;
    let rec = stego::extract(text, &key).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok((
        hex::encode(rec.pointer),
        rec.tag_verified,
        rec.shards_recovered,
    ))
}

/// Derive the Ed25519 public key (hex) from a 32-byte secret key (hex).
#[pyfunction]
fn public_key(secret_hex: &str) -> PyResult<String> {
    let mut sk = parse_key32(secret_hex)?;
    let pk = manifest::public_key(&sk);
    sk.iter_mut().for_each(|b| *b = 0);
    Ok(hex::encode(pk))
}

/// Sign a payload as tagged COSE_Sign1 / EdDSA. Returns the envelope as hex.
#[pyfunction]
fn sign(payload: &str, secret_hex: &str) -> PyResult<String> {
    let mut sk = parse_key32(secret_hex)?;
    let out = manifest::sign_cose(payload.as_bytes(), &sk);
    sk.iter_mut().for_each(|b| *b = 0);
    out.map(hex::encode)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Verify a hex COSE_Sign1 envelope against a hex public key; returns the
/// payload string on success, raises on failure.
#[pyfunction]
fn verify(cose_hex: &str, public_hex: &str) -> PyResult<String> {
    let pk = parse_key32(public_hex)?;
    let cose = hex::decode(cose_hex.trim()).map_err(|e| hexerr("cose", e))?;
    let payload =
        manifest::verify_cose(&cose, &pk).map_err(|e| PyValueError::new_err(e.to_string()))?;
    String::from_utf8(payload).map_err(|e| PyValueError::new_err(format!("payload not utf-8: {e}")))
}

/// Anti-transfer cross-check tag (hex): `HMAC(key, repo_id ‖ content_hash)`.
#[pyfunction]
fn cross_check(key_hex: &str, repo_id: &str, content_hash_hex: &str) -> PyResult<String> {
    let key = hex::decode(key_hex.trim()).map_err(|e| hexerr("key", e))?;
    let ch = hex::decode(content_hash_hex.trim()).map_err(|e| hexerr("content hash", e))?;
    Ok(hex::encode(crosscheck::crosscheck_tag(
        &key,
        repo_id.as_bytes(),
        &ch,
    )))
}

/// Build the `c2pa.soft-binding` assertion (id 41, surface fingerprint) as CBOR,
/// hex-encoded. Sign the result with [`sign`]; includes per-window blocks.
#[pyfunction]
fn soft_binding_fingerprint(text: &str) -> String {
    let sb = soft_binding::from_fingerprint(&simhash::Fingerprint::compute(text));
    hex::encode(sb.to_cbor().expect("soft-binding CBOR encode"))
}

/// Build the `c2pa.soft-binding` assertion (id 43, structural) as CBOR hex.
#[pyfunction]
fn soft_binding_structure(text: &str) -> String {
    let sb = soft_binding::from_structure(&structure::compute(text));
    hex::encode(sb.to_cbor().expect("soft-binding CBOR encode"))
}

/// Build the `c2pa.soft-binding` assertion (id 44, MinHash) as CBOR hex.
#[pyfunction]
fn soft_binding_minhash(text: &str) -> String {
    let sb = soft_binding::from_minhash(&minhash::MinHash::compute(text));
    hex::encode(sb.to_cbor().expect("soft-binding CBOR encode"))
}

/// Build the `c2pa.soft-binding` assertion (id 42, ZWC watermark) for a routing
/// `pointer_hex`, as CBOR hex.
#[pyfunction]
fn soft_binding_watermark(pointer_hex: &str) -> PyResult<String> {
    let pointer = hex::decode(pointer_hex.trim()).map_err(|e| hexerr("pointer", e))?;
    let sb = soft_binding::from_watermark_pointer(&pointer);
    sb.to_cbor()
        .map(hex::encode)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Recompute the fingerprint from `text`, compare against a candidate
/// `c2pa.soft-binding` assertion (hex CBOR), and classify. Returns
/// `"BOUND"`, `"LIKELY"`, or `"REVIEW"`.
#[pyfunction]
fn verify_tier(
    text: &str,
    assertion_cbor_hex: &str,
    watermark_verified: bool,
    crosscheck_ok: bool,
) -> PyResult<String> {
    let bytes = hex::decode(assertion_cbor_hex.trim()).map_err(|e| hexerr("assertion", e))?;
    let candidate = soft_binding::SoftBinding::from_cbor(&bytes)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let tier = crosscheck::verify(text, &candidate, watermark_verified, crosscheck_ok);
    Ok(match tier {
        crosscheck::Confidence::Bound => "BOUND",
        crosscheck::Confidence::Likely => "LIKELY",
        crosscheck::Confidence::Review => "REVIEW",
    }
    .to_string())
}

/// The `c2pa_text_binding` native module.
#[pymodule]
fn c2pa_text_binding(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add(
        "__doc__",
        "WritersLogic C2PA text soft-binding family (native bindings).",
    )?;
    m.add_function(wrap_pyfunction!(text_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(text_structure, m)?)?;
    m.add_function(wrap_pyfunction!(minhash_signature, m)?)?;
    m.add_function(wrap_pyfunction!(minhash_bands, m)?)?;
    m.add_function(wrap_pyfunction!(hamming_hex, m)?)?;
    m.add_function(wrap_pyfunction!(content_hash, m)?)?;
    m.add_function(wrap_pyfunction!(embed_watermark, m)?)?;
    m.add_function(wrap_pyfunction!(extract_watermark, m)?)?;
    m.add_function(wrap_pyfunction!(public_key, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(cross_check, m)?)?;
    m.add_function(wrap_pyfunction!(soft_binding_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(soft_binding_structure, m)?)?;
    m.add_function(wrap_pyfunction!(soft_binding_minhash, m)?)?;
    m.add_function(wrap_pyfunction!(soft_binding_watermark, m)?)?;
    m.add_function(wrap_pyfunction!(verify_tier, m)?)?;
    Ok(())
}
