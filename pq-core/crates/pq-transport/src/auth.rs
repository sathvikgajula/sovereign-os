//! Post-handshake DID authentication over QUIC streams.
//!
//! After the 1-RTT PQ-QUIC tunnel is established (using ML-KEM-768 keys only),
//! the ML-DSA-65 identity signature is exchanged over a reliable QUIC stream.
//! This "deferred identity proof" pattern avoids including the 3309-byte
//! Dilithium signature in the ClientHello, preventing MTU fragmentation.

use anyhow::{anyhow, Context, Result};
use pq_crypto::verify_signature;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Maximum size for an identity proof message (generous for Dilithium keys).
const MAX_IDENTITY_PROOF_SIZE: usize = 16384; // 16 KiB

/// Protocol version prefix for identity proof signatures.
const AUTH_PROTOCOL_PREFIX: &[u8] = b"pq-core-auth-v1:";

/// An identity proof sent over the QUIC tunnel after handshake.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityProof {
    /// The sender's DID string (e.g., `did:pqc:<fingerprint>`).
    pub did: String,
    /// The sender's ML-DSA-65 public key, hex-encoded.
    pub public_key_hex: String,
    /// Signature over `AUTH_PROTOCOL_PREFIX || did`, hex-encoded.
    pub signature_hex: String,
}

/// Create an identity proof for transmission.
///
/// Signs the message `"pq-core-auth-v1:<did>"` with the identity's ML-DSA-65 keypair.
pub fn create_identity_proof(did: &str, sign_fn: impl Fn(&[u8]) -> Vec<u8>, pk_bytes: &[u8]) -> IdentityProof {
    let mut message = AUTH_PROTOCOL_PREFIX.to_vec();
    message.extend_from_slice(did.as_bytes());
    let signature = sign_fn(&message);

    IdentityProof {
        did: did.to_string(),
        public_key_hex: hex::encode(pk_bytes),
        signature_hex: hex::encode(&signature),
    }
}

/// Verify a received identity proof.
///
/// Checks the ML-DSA-65 signature over `"pq-core-auth-v1:<did>"` against
/// the provided public key.
pub fn verify_identity_proof(proof: &IdentityProof) -> Result<()> {
    let public_key_bytes = hex::decode(&proof.public_key_hex)
        .context("Invalid hex in public key")?;
    let signature_bytes = hex::decode(&proof.signature_hex)
        .context("Invalid hex in signature")?;

    let mut message = AUTH_PROTOCOL_PREFIX.to_vec();
    message.extend_from_slice(proof.did.as_bytes());

    verify_signature(&message, &signature_bytes, &public_key_bytes)
        .map_err(|e| anyhow!("DID identity verification failed: {e}"))?;

    // Verify the DID fingerprint matches the public key
    let hash = blake3::hash(&public_key_bytes);
    let expected_fingerprint = hex::encode(hash.as_bytes());
    let expected_did = format!("did:pqc:{expected_fingerprint}");

    if proof.did != expected_did {
        return Err(anyhow!(
            "DID mismatch: proof claims {} but public key derives {}",
            proof.did,
            expected_did
        ));
    }

    debug!("Identity proof verified for {}", proof.did);
    Ok(())
}

/// Send an identity proof over a QUIC send stream.
pub async fn send_identity_proof(
    send: &mut quinn::SendStream,
    did: &str,
    sign_fn: impl Fn(&[u8]) -> Vec<u8>,
    pk_bytes: &[u8],
) -> Result<()> {
    let proof = create_identity_proof(did, sign_fn, pk_bytes);
    let payload = serde_json::to_vec(&proof)
        .context("Failed to serialize identity proof")?;

    // Send length-prefixed message
    let len = (payload.len() as u32).to_be_bytes();
    send.write_all(&len).await.context("Failed to send proof length")?;
    send.write_all(&payload).await.context("Failed to send proof payload")?;
    send.finish().context("Failed to finish send stream")?;

    info!("Identity proof sent for {}", proof.did);
    Ok(())
}

/// Receive and verify an identity proof from a QUIC recv stream.
///
/// Returns the verified DID string on success.
pub async fn receive_and_verify_identity(
    recv: &mut quinn::RecvStream,
) -> Result<String> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("Failed to read proof length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_IDENTITY_PROOF_SIZE {
        return Err(anyhow!("Identity proof too large: {len} bytes"));
    }

    // Read payload
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload)
        .await
        .context("Failed to read proof payload")?;

    let proof: IdentityProof = serde_json::from_slice(&payload)
        .context("Failed to deserialize identity proof")?;

    info!("Received identity proof from {}", proof.did);
    verify_identity_proof(&proof)?;
    info!("✓ DID verified: {}", proof.did);

    Ok(proof.did)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_crypto::SigningKeypair;

    #[test]
    fn test_identity_proof_roundtrip() {
        let kp = SigningKeypair::generate();
        let pk_bytes = kp.public_key_bytes();
        let hash = blake3::hash(&pk_bytes);
        let did = format!("did:pqc:{}", hex::encode(hash.as_bytes()));

        let proof = create_identity_proof(&did, |msg| kp.sign(msg), &pk_bytes);
        assert!(verify_identity_proof(&proof).is_ok());
    }

    #[test]
    fn test_identity_proof_bad_signature() {
        let kp = SigningKeypair::generate();
        let pk_bytes = kp.public_key_bytes();
        let hash = blake3::hash(&pk_bytes);
        let did = format!("did:pqc:{}", hex::encode(hash.as_bytes()));

        let mut proof = create_identity_proof(&did, |msg| kp.sign(msg), &pk_bytes);
        // Corrupt the signature
        proof.signature_hex = "deadbeef".repeat(100);
        assert!(verify_identity_proof(&proof).is_err());
    }

    #[test]
    fn test_identity_proof_did_mismatch() {
        let kp = SigningKeypair::generate();
        let pk_bytes = kp.public_key_bytes();
        let fake_did = "did:pqc:0000000000000000000000000000000000000000000000000000000000000000";

        let proof = create_identity_proof(fake_did, |msg| kp.sign(msg), &pk_bytes);
        // Signature will verify but DID won't match public key fingerprint
        assert!(verify_identity_proof(&proof).is_err());
    }
}
