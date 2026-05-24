//! # Sovereign Event — Commit-then-Jitter Causal Integrity Wrapper
//!
//! Encapsulates application payloads with a high-precision timestamp and
//! ML-DSA-65 signature before handoff to the pq-transport Egress Vault.
//! This ensures causal ordering integrity across 5G handoff boundaries.

use anyhow::Result;
use pqc::SigningKeypair;
use serde::{Deserialize, Serialize};
use tracing::info;

/// A causally-sealed application event ready for Egress Vault transmission.
///
/// The "Commit-then-Jitter" model:
/// 1. Capture high-precision local timestamp
/// 2. Hash the payload with BLAKE3
/// 3. Sign {timestamp_ns || payload_hash} with ML-DSA-65
/// 4. Package as SovereignEvent for the Egress Vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignEvent {
    /// High-precision local timestamp in nanoseconds since UNIX epoch.
    pub timestamp_ns: u128,
    /// BLAKE3 hash of the original application payload.
    pub payload_hash: [u8; 32],
    /// ML-DSA-65 detached signature over {timestamp_ns || payload_hash}.
    pub signature: Vec<u8>,
    /// Original application payload.
    pub payload: Vec<u8>,
}

impl SovereignEvent {
    /// Seal an application payload into a SovereignEvent.
    ///
    /// Captures the local high-precision timestamp, computes BLAKE3(payload),
    /// signs {timestamp_ns || payload_hash} with the node's ML-DSA-65 key,
    /// and packages everything into an event ready for Egress Vault handoff.
    pub fn seal(payload: Vec<u8>, signing_key: &SigningKeypair) -> Result<Self> {
        // 1. Capture high-precision timestamp
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();

        // 2. Compute BLAKE3 hash of the payload
        let hash = blake3::hash(&payload);
        let payload_hash: [u8; 32] = *hash.as_bytes();

        // 3. Build the signed commitment: {timestamp_ns || payload_hash}
        let mut commitment = Vec::with_capacity(16 + 32);
        commitment.extend_from_slice(&timestamp_ns.to_le_bytes());
        commitment.extend_from_slice(&payload_hash);

        // 4. Sign with ML-DSA-65
        let signature = signing_key.sign(&commitment);

        info!(
            "[SOVEREIGN_EVENT] Payload sealed (ts={}ns, hash={}, sig_len={})",
            timestamp_ns,
            hex::encode(&payload_hash[..8]),
            signature.len()
        );

        Ok(Self {
            timestamp_ns,
            payload_hash,
            signature,
            payload,
        })
    }

    /// Verify the causal integrity of this event against a known public key.
    pub fn verify(&self, public_key_bytes: &[u8]) -> Result<()> {
        let mut commitment = Vec::with_capacity(16 + 32);
        commitment.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        commitment.extend_from_slice(&self.payload_hash);

        pqc::verify_signature(&commitment, &self.signature, public_key_bytes)?;

        // Also verify payload hash integrity
        let hash = blake3::hash(&self.payload);
        if hash.as_bytes() != &self.payload_hash {
            anyhow::bail!("CAUSAL_INTEGRITY_VIOLATION: payload_hash mismatch");
        }

        Ok(())
    }

    /// Serialize the event to bytes for Egress Vault transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize a SovereignEvent from Egress Vault bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_and_verify() {
        let keypair = SigningKeypair::generate();
        let payload = b"test application payload for 5G handoff".to_vec();

        let event = SovereignEvent::seal(payload.clone(), &keypair).unwrap();

        // Verify timestamp is reasonable (after 2024)
        assert!(event.timestamp_ns > 1_700_000_000_000_000_000);

        // Verify payload hash matches
        let expected_hash = blake3::hash(&payload);
        assert_eq!(&event.payload_hash, expected_hash.as_bytes());

        // Verify signature
        assert!(event.verify(&keypair.public_key_bytes()).is_ok());

        // Verify roundtrip serialization
        let bytes = event.to_bytes().unwrap();
        let restored = SovereignEvent::from_bytes(&bytes).unwrap();
        assert_eq!(restored.timestamp_ns, event.timestamp_ns);
        assert_eq!(restored.payload_hash, event.payload_hash);
        assert_eq!(restored.payload, payload);
    }

    #[test]
    fn test_tampered_payload_fails_verify() {
        let keypair = SigningKeypair::generate();
        let payload = b"original payload".to_vec();

        let mut event = SovereignEvent::seal(payload, &keypair).unwrap();

        // Tamper with payload
        event.payload = b"tampered payload".to_vec();

        // Verify should fail due to hash mismatch
        assert!(event.verify(&keypair.public_key_bytes()).is_err());
    }
}
