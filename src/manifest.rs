// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal COSE_Sign1 (EdDSA / Ed25519) signing and verification for a
//! `c2pa.soft-binding` assertion payload.
//!
//! This produces a compact, self-verifying signed envelope over an opaque
//! payload (typically the [`crate::soft_binding::SoftBinding`] assertion CBOR).
//! It is deterministic — the Ed25519 key is supplied by the caller, so no RNG is
//! needed and the same input always yields the same signature. This is a
//! *minimal* manifest for self-contained resolution; it is not a full JUMBF
//! C2PA manifest and makes no claim to C2PA conformance certification.

use crate::error::Error;
use coset::{
    iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// The C2PA assertion label a soft-binding payload is stored under.
///
/// Defined in [`crate::soft_binding`]; re-exported here for callers signing the
/// assertion.
pub use crate::soft_binding::SOFT_BINDING_LABEL;

/// Derive the 32-byte Ed25519 public key from a 32-byte secret key.
pub fn public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret_key)
        .verifying_key()
        .to_bytes()
}

/// Sign `payload` as a tagged COSE_Sign1 envelope with EdDSA over Ed25519.
pub fn sign_cose(payload: &[u8], secret_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let sk = SigningKey::from_bytes(secret_key);
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .create_signature(&[], |pt| sk.sign(pt).to_bytes().to_vec())
        .build();
    sign1
        .to_tagged_vec()
        .map_err(|e| Error::InvalidInput(format!("COSE encode failed: {e:?}")))
}

/// Verify a tagged COSE_Sign1 EdDSA envelope against `public_key`, returning the
/// payload on success.
pub fn verify_cose(cose: &[u8], public_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let vk = VerifyingKey::from_bytes(public_key)
        .map_err(|e| Error::InvalidInput(format!("invalid public key: {e:?}")))?;
    let sign1 = CoseSign1::from_tagged_slice(cose)
        .or_else(|_| CoseSign1::from_slice(cose))
        .map_err(|e| Error::InvalidInput(format!("COSE decode failed: {e:?}")))?;
    sign1.verify_signature(&[], |sig, pt| {
        let signature = Signature::from_slice(sig)
            .map_err(|e| Error::InvalidInput(format!("malformed signature: {e:?}")))?;
        vk.verify(pt, &signature).map_err(|_| Error::TagMismatch)
    })?;
    sign1
        .payload
        .ok_or_else(|| Error::InvalidInput("COSE envelope has no payload".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed secret key so the test is deterministic; never a real key.
    const SK: [u8; 32] = [7u8; 32];
    const PAYLOAD: &[u8] = br#"{"alg":"com.writerslogic.text-fingerprint.1","value":"deadbeef"}"#;

    #[test]
    fn sign_then_verify_roundtrips() {
        let pk = public_key(&SK);
        let cose = sign_cose(PAYLOAD, &SK).unwrap();
        let recovered = verify_cose(&cose, &pk).unwrap();
        assert_eq!(recovered, PAYLOAD);
    }

    #[test]
    fn signing_is_deterministic() {
        let a = sign_cose(PAYLOAD, &SK).unwrap();
        let b = sign_cose(PAYLOAD, &SK).unwrap();
        assert_eq!(a, b, "Ed25519 over a fixed key must be deterministic");
    }

    #[test]
    fn wrong_public_key_fails() {
        let cose = sign_cose(PAYLOAD, &SK).unwrap();
        let other_pk = public_key(&[9u8; 32]);
        assert_eq!(verify_cose(&cose, &other_pk), Err(Error::TagMismatch));
    }

    #[test]
    fn tampered_payload_fails() {
        let pk = public_key(&SK);
        let mut cose = sign_cose(PAYLOAD, &SK).unwrap();
        // Flip a byte in the middle of the envelope.
        let mid = cose.len() / 2;
        cose[mid] ^= 0x01;
        assert!(verify_cose(&cose, &pk).is_err());
    }
}
