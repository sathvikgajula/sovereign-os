//! # (3,5) Reed-Solomon Erasure Coding
//!
//! Shreds application payloads into 5 shards (3 data + 2 parity).
//! Any 3 of 5 shards are sufficient to reconstruct the original payload.
//! Each shard is anchored with an ML-DSA-65 signature.

use anyhow::{anyhow, Result};
use pq_crypto::SigningKeypair;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Number of data shards in the (3,5) RS scheme.
pub const RS_DATA_SHARDS: usize = 3;
/// Number of parity shards in the (3,5) RS scheme.
pub const RS_PARITY_SHARDS: usize = 2;
/// Total shards = data + parity.
pub const RS_TOTAL_SHARDS: usize = RS_DATA_SHARDS + RS_PARITY_SHARDS;

/// A signed erasure-coded shard ready for vault distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedShard {
    /// Shard index (0..4)
    pub index: u8,
    /// The shard data
    pub data: Vec<u8>,
    /// BLAKE3 hash of the original payload (for reassembly identification)
    pub payload_hash: [u8; 32],
    /// ML-DSA-65 signature over {index || shard_data || payload_hash}
    pub signature: Vec<u8>,
    /// Signer's public key bytes
    pub signer_pk: Vec<u8>,
}

impl SignedShard {
    /// Verify the ML-DSA-65 signature anchoring this shard.
    pub fn verify(&self) -> Result<()> {
        let commitment = Self::build_commitment(self.index, &self.data, &self.payload_hash);
        pq_crypto::verify_signature(&commitment, &self.signature, &self.signer_pk)?;
        Ok(())
    }

    fn build_commitment(index: u8, data: &[u8], payload_hash: &[u8; 32]) -> Vec<u8> {
        let mut commitment = Vec::with_capacity(1 + data.len() + 32);
        commitment.push(index);
        commitment.extend_from_slice(data);
        commitment.extend_from_slice(payload_hash);
        commitment
    }
}

/// (3,5) Reed-Solomon erasure coder.
pub struct ErasureCoder {
    rs: ReedSolomon,
}

impl ErasureCoder {
    pub fn new() -> Result<Self> {
        let rs = ReedSolomon::new(RS_DATA_SHARDS, RS_PARITY_SHARDS)
            .map_err(|e| anyhow!("Failed to create RS encoder: {:?}", e))?;
        Ok(Self { rs })
    }

    /// Shred a payload into 5 signed shards (3 data + 2 parity).
    ///
    /// Each shard is signed with the provided ML-DSA-65 key for PQC anchoring.
    pub fn shred(&self, payload: &[u8], signing_key: &SigningKeypair) -> Result<Vec<SignedShard>> {
        // Compute payload hash for reassembly identification
        let payload_hash: [u8; 32] = *blake3::hash(payload).as_bytes();

        // Calculate per-shard size (ceil division)
        let shard_size = (payload.len() + RS_DATA_SHARDS - 1) / RS_DATA_SHARDS;

        // Build data shards with zero-padding
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(RS_TOTAL_SHARDS);
        for i in 0..RS_DATA_SHARDS {
            let start = i * shard_size;
            let end = ((i + 1) * shard_size).min(payload.len());
            let mut shard = vec![0u8; shard_size];
            if start < payload.len() {
                let copy_len = end - start;
                shard[..copy_len].copy_from_slice(&payload[start..end]);
            }
            shards.push(shard);
        }

        // Add empty parity shards
        for _ in 0..RS_PARITY_SHARDS {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode parity shards
        self.rs.encode(&mut shards)
            .map_err(|e| anyhow!("RS encoding failed: {:?}", e))?;

        // Sign each shard with ML-DSA-65
        let mut signed_shards = Vec::with_capacity(RS_TOTAL_SHARDS);
        for (i, shard_data) in shards.into_iter().enumerate() {
            let commitment = SignedShard::build_commitment(i as u8, &shard_data, &payload_hash);
            let signature = signing_key.sign(&commitment);

            signed_shards.push(SignedShard {
                index: i as u8,
                data: shard_data,
                payload_hash,
                signature,
                signer_pk: signing_key.public_key_bytes(),
            });
        }

        info!(
            "[ERASURE] Payload shredded into {} shards (shard_size={}, payload_hash={})",
            RS_TOTAL_SHARDS,
            shard_size,
            hex::encode(&payload_hash[..8])
        );

        Ok(signed_shards)
    }

    /// Reconstruct the original payload from any 3+ of 5 shards.
    ///
    /// `shards` should have 5 slots, with `None` for missing shards.
    /// At least 3 must be `Some`.
    pub fn reconstruct(
        &self,
        shards: &mut [Option<Vec<u8>>],
        original_payload_len: usize,
    ) -> Result<Vec<u8>> {
        if shards.len() != RS_TOTAL_SHARDS {
            return Err(anyhow!(
                "Expected {} shard slots, got {}",
                RS_TOTAL_SHARDS,
                shards.len()
            ));
        }

        let present_count = shards.iter().filter(|s| s.is_some()).count();
        if present_count < RS_DATA_SHARDS {
            return Err(anyhow!(
                "Need at least {} shards for reconstruction, only {} present",
                RS_DATA_SHARDS,
                present_count
            ));
        }

        // Convert to the format reed-solomon-erasure expects
        let mut shard_refs: Vec<Option<Vec<u8>>> = shards.to_vec();

        self.rs.reconstruct(&mut shard_refs)
            .map_err(|e| anyhow!("RS reconstruction failed: {:?}", e))?;

        // Reassemble from data shards
        let mut payload = Vec::with_capacity(original_payload_len);
        for i in 0..RS_DATA_SHARDS {
            if let Some(ref shard) = shard_refs[i] {
                payload.extend_from_slice(shard);
            } else {
                return Err(anyhow!("Data shard {} still missing after reconstruction", i));
            }
        }

        // Trim to original length
        payload.truncate(original_payload_len);

        info!(
            "[ERASURE] Payload reconstructed ({} bytes from {}/{} shards)",
            original_payload_len,
            present_count,
            RS_TOTAL_SHARDS
        );

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shred_and_reconstruct_full() -> Result<()> {
        let coder = ErasureCoder::new()?;
        let signing_key = SigningKeypair::generate();
        let payload = b"The Sovereign Infrastructure erasure coding test payload data!";

        let shards = coder.shred(payload, &signing_key)?;
        assert_eq!(shards.len(), RS_TOTAL_SHARDS);

        // Verify all signatures
        for shard in &shards {
            shard.verify()?;
        }

        // Reconstruct with all shards present
        let mut shard_slots: Vec<Option<Vec<u8>>> = shards.iter()
            .map(|s| Some(s.data.clone()))
            .collect();

        let recovered = coder.reconstruct(&mut shard_slots, payload.len())?;
        assert_eq!(recovered, payload);

        Ok(())
    }

    #[test]
    fn test_reconstruct_with_2_missing() -> Result<()> {
        let coder = ErasureCoder::new()?;
        let signing_key = SigningKeypair::generate();
        let payload = b"Testing erasure recovery with missing shards 0 and 3";

        let shards = coder.shred(payload, &signing_key)?;

        // Drop shards 0 and 3 (one data, one parity)
        let mut shard_slots: Vec<Option<Vec<u8>>> = shards.iter()
            .map(|s| Some(s.data.clone()))
            .collect();
        shard_slots[0] = None;
        shard_slots[3] = None;

        let recovered = coder.reconstruct(&mut shard_slots, payload.len())?;
        assert_eq!(recovered, payload);

        Ok(())
    }

    #[test]
    fn test_reconstruct_fails_with_3_missing() -> Result<()> {
        let coder = ErasureCoder::new()?;
        let signing_key = SigningKeypair::generate();
        let payload = b"Too many shards missing";

        let shards = coder.shred(payload, &signing_key)?;

        let mut shard_slots: Vec<Option<Vec<u8>>> = shards.iter()
            .map(|s| Some(s.data.clone()))
            .collect();
        shard_slots[0] = None;
        shard_slots[1] = None;
        shard_slots[2] = None;

        let result = coder.reconstruct(&mut shard_slots, payload.len());
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_shard_signature_tamper_detection() -> Result<()> {
        let coder = ErasureCoder::new()?;
        let signing_key = SigningKeypair::generate();
        let payload = b"Tamper detection test";

        let mut shards = coder.shred(payload, &signing_key)?;

        // Tamper with shard data
        shards[0].data[0] ^= 0xFF;

        // Signature verification should now fail
        assert!(shards[0].verify().is_err());

        Ok(())
    }
}
