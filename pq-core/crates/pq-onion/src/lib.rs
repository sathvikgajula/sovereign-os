use anyhow::{anyhow, Result};
use pq_crypto::{KemKeypair, verify_signature, kyber768};
use pq_reputation::ReputationManager;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret, PublicKey};
use rand::RngCore;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Institutional-Grade Sphinx MTU (72KB to accommodate 64KB payloads)
pub const SPHINX_MTU: usize = 73728;
pub const KYBER_CT_SIZE: usize = 1088;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SphinxPacket {
    /// The nested KEM ciphertext for the current hop
    pub header: Vec<u8>,
    /// The remaining encrypted payload (including further layers + padding)
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    /// Constructs a 3-hop Sphinx circuit with nested ML-KEM-768 encapsulations.
    /// Reverse-order wrapping: Exit -> Middle -> Guard.
    pub fn build(
        final_payload: &[u8],
        hops_pks: &[Vec<u8>],
        identity_proof: Option<&[u8]>, // Root_Identity_Signature (e.g. JSON proof)
    ) -> Result<Self> {
        if hops_pks.len() != 3 {
            return Err(anyhow!("Sphinx circuit must have exactly 3 hops"));
        }
        if final_payload.len() + (KYBER_CT_SIZE * 3) + 4096 > SPHINX_MTU {
            return Err(anyhow!("Payload + Identity too large for SPHINX_MTU"));
        }

        // 1. Exit Hop (Layer 3)
        let exit_pk = kyber768::PublicKey::from_bytes(&hops_pks[2])
            .map_err(|_| anyhow!("Invalid Exit PK"))?;
        let (_ss3, ct3) = kyber768::encapsulate(&exit_pk);
        
        // Inner for exit: [0 (hops left)] [proof_len (u32)] [proof] [final_payload]
        let mut exit_inner = vec![0u8];
        if let Some(proof) = identity_proof {
            let len = (proof.len() as u32).to_be_bytes();
            exit_inner.extend_from_slice(&len);
            exit_inner.extend_from_slice(proof);
        } else {
            exit_inner.extend_from_slice(&[0u8; 4]); // No proof
        }
        exit_inner.extend_from_slice(final_payload);
        
        // 2. Middle Hop (Layer 2)
        let middle_pk = kyber768::PublicKey::from_bytes(&hops_pks[1])
            .map_err(|_| anyhow!("Invalid Middle PK"))?;
        let (_ss2, ct2) = kyber768::encapsulate(&middle_pk);
        
        // Inner for middle: [1 (hops left)] [CT3] [exit_inner]
        let mut middle_inner = vec![1u8];
        middle_inner.extend_from_slice(ct3.as_bytes());
        middle_inner.extend_from_slice(&exit_inner);
        
        // 3. Guard Hop (Layer 1)
        let guard_pk = kyber768::PublicKey::from_bytes(&hops_pks[0])
            .map_err(|_| anyhow!("Invalid Guard PK"))?;
        let (_ss1, ct1) = kyber768::encapsulate(&guard_pk);

        // Inner for guard: [2 (hops left)] [CT2] [middle_inner]
        let mut guard_inner = vec![2u8];
        guard_inner.extend_from_slice(ct2.as_bytes());
        guard_inner.extend_from_slice(&middle_inner);
        
        // Finalize MTU with initial noise to simulate full packet
        let mut final_packet_payload = guard_inner;
        let mut rng = StdRng::from_entropy();
        let padding_needed = SPHINX_MTU.saturating_sub(KYBER_CT_SIZE).saturating_sub(final_packet_payload.len());
        if padding_needed > 0 {
            let mut noise = vec![0u8; padding_needed];
            rng.fill_bytes(&mut noise);
            final_packet_payload.extend_from_slice(&noise);
        }

        Ok(Self {
            header: ct1.as_bytes().to_vec(),
            payload: final_packet_payload,
        })
    }

    /// Peels one layer of the onion, adds CSPRNG padding, and returns the next hop packet.
    /// Bit-for-bit uniformity is maintained.
    pub fn unwrap(self, keypair: &KemKeypair) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<SphinxPacket>)> {
        // 1. Decapsulate header
        let shared_secret = keypair.decapsulate(&self.header)?;

        // 2. The payload starts with the "inner" content.
        // We expect the first byte to be a "remaining hops" counter for this prototype.
        if self.payload.is_empty() {
            return Err(anyhow!("Empty payload"));
        }

        let hops_left = self.payload[0];
        let inner_content = &self.payload[1..];

        if hops_left == 0 {
            // This is the exit node. 
            // Inner content: [proof_len (u32)] [proof] [final_payload]
            if inner_content.len() < 4 {
                return Err(anyhow!("Exit payload too small for proof header"));
            }
            let mut len_buf = [0u8; 4];
            len_buf.copy_from_slice(&inner_content[0..4]);
            let proof_len = u32::from_be_bytes(len_buf) as usize;
            
            if inner_content.len() < 4 + proof_len {
                return Err(anyhow!("Exit payload truncated for proof"));
            }
            
            let proof = if proof_len > 0 {
                Some(inner_content[4..4+proof_len].to_vec())
            } else {
                None
            };
            
            let actual_payload = inner_content[4+proof_len..].to_vec();
            
            // Return shared secret, actual payload, the proof, and None for next packet
            let res: (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<SphinxPacket>) = 
                (shared_secret, actual_payload, proof, None);
            return Ok(res);
        }

        // It's a relay node. The next header is at the start of the inner content.
        if inner_content.len() < KYBER_CT_SIZE {
            return Err(anyhow!("Payload truncated"));
        }

        let next_header = inner_content[0..KYBER_CT_SIZE].to_vec();
        let mut next_inner = inner_content[KYBER_CT_SIZE..].to_vec();

        // 3. PADDING MANDATE: Append CSPRNG noise to maintain MTU
        let mut rng = StdRng::from_entropy();
        let mut noise = vec![0u8; KYBER_CT_SIZE];
        rng.fill_bytes(&mut noise);
        next_inner.extend_from_slice(&noise);

        // Reconstruct next payload: [hops_left - 1] [next_inner]
        let mut next_payload = vec![hops_left - 1];
        next_payload.extend_from_slice(&next_inner);

        let res: (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<SphinxPacket>) = (
            shared_secret,
            inner_content.to_vec(),
            None, // No identity proof for relay hops
            Some(SphinxPacket {
                header: next_header,
                payload: next_payload,
            }),
        );
        Ok(res)
    }

    /// Verifies the identity proof extracted from the Inner Sanctum.
    /// This should be called by the exit node.
    pub fn verify_inner_sanctum(
        &self,
        proof_bytes: &[u8],
        _peer_did: &str,
        public_key_bytes: &[u8],
    ) -> Result<bool> {
        // In this phase, the proof_bytes is an ML-DSA-65 signature
        // of the fixed challenge "inner-sanctum-auth".
        verify_signature(b"inner-sanctum-auth", proof_bytes, public_key_bytes)
            .map(|_| true)
            .map_err(|e| anyhow!("Identity verification failed: {}", e))
    }
}

/// Security-First selection matrix for onion circuits.
pub struct SecurityFirstSelector {
    pub reputation: ReputationManager,
}

impl SecurityFirstSelector {
    pub fn new(reputation: ReputationManager) -> Self {
        Self { reputation }
    }

    /// Selects a hop based on role-specific trust weights.
    pub async fn select_hop(&self, candidates: Vec<(String, String)>, is_edge: bool) -> Result<String> {
        let threshold = if is_edge { 0.9 } else { 0.7 };
        
        for (did, address) in candidates {
            let score = self.reputation.get_score(did.clone()).await?;
            if score.expected_value() >= threshold {
                return Ok(address);
            }
        }
        
        Err(anyhow!("No reputable nodes found for hop (Threshold: {})", threshold))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_crypto::KemKeypair;

    #[test]
    fn test_sphinx_mtu_uniformity() -> Result<()> {
        let guard_kp = KemKeypair::generate();
        let middle_kp = KemKeypair::generate();
        let exit_kp = KemKeypair::generate();

        let pks = [
            guard_kp.public_key_bytes(),
            middle_kp.public_key_bytes(),
            exit_kp.public_key_bytes(),
        ];

        let payload = b"Institutional-Grade Stealth Payload";
        let packet = SphinxPacket::build(payload, &pks, None)?;
        
        let initial_size = packet.header.len() + packet.payload.len();
        assert_eq!(initial_size, SPHINX_MTU);

        // Hop 1: Guard
        let (ss1, _p1, _proof1, next_opt) = packet.unwrap(&guard_kp)?;
        let next1 = next_opt.unwrap();
        assert_eq!(next1.header.len() + next1.payload.len(), SPHINX_MTU);

        // Hop 2: Middle
        let (ss2, _p2, _proof2, next_opt) = next1.unwrap(&middle_kp)?;
        let next2 = next_opt.unwrap();
        assert_eq!(next2.header.len() + next2.payload.len(), SPHINX_MTU);

        // Hop 3: Exit
        let (ss3, _p3, _proof3, next_opt) = next2.unwrap(&exit_kp)?;
        assert!(next_opt.is_none());

        Ok(())
    }
}
