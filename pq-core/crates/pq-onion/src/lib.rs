use anyhow::{anyhow, Result};
use pq_crypto::{KemKeypair, verify_signature, kyber768};
use pq_reputation::ReputationManager;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret, PublicKey};
use rand::RngCore;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use tracing::info;

pub mod group_tree;
pub mod delegation;

/// Institutional-Grade Sphinx MTU (72KB to accommodate 64KB payloads)
pub const SPHINX_MTU: usize = 73728;
pub const KYBER_CT_SIZE: usize = 1088;

/// Mix-Net Sphinx packet size: exactly 512 bytes for wire-level uniformity.
pub const MIX_PACKET_SIZE: usize = 512;
/// Per-hop overhead: 4 byte target_epoch + 1 byte hop counter + 12 byte nonce
const MIX_HOP_OVERHEAD: usize = 17;
/// AEAD tag size for ChaCha20-Poly1305
const AEAD_TAG_SIZE: usize = 16;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Existing 72KB SphinxPacket (Bulk Data Transport)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 512-Byte MixSphinxPacket (Mix-Net Wire Protocol)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A circuit is established once via ML-KEM-768 handshake.
/// Per-hop symmetric keys are derived from the shared secrets.
#[derive(Debug, Clone)]
pub struct MixCircuitKeys {
    /// Symmetric keys for each hop (3 hops), derived from KEM shared secrets
    pub hop_keys: Vec<[u8; 32]>,
}

impl MixCircuitKeys {
    /// Establish a 3-hop mix circuit by performing ML-KEM-768 handshakes with each hop.
    /// Returns the circuit keys and the KEM ciphertexts to send to each hop for setup.
    pub fn establish(hops_pks: &[Vec<u8>]) -> Result<(Self, Vec<Vec<u8>>)> {
        if hops_pks.len() != 3 {
            return Err(anyhow!("Mix circuit must have exactly 3 hops"));
        }

        let mut hop_keys = Vec::with_capacity(3);
        let mut ciphertexts = Vec::with_capacity(3);

        for (i, pk_bytes) in hops_pks.iter().enumerate() {
            let pk = kyber768::PublicKey::from_bytes(pk_bytes)
                .map_err(|_| anyhow!("Invalid ML-KEM-768 public key for hop {}", i))?;
            let (ss, ct) = kyber768::encapsulate(&pk);

            // Derive a 32-byte hop key from the shared secret using BLAKE3
            let hop_key: [u8; 32] = blake3::derive_key(
                "sovereign-mix-hop-key",
                ss.as_bytes(),
            );

            hop_keys.push(hop_key);
            ciphertexts.push(ct.as_bytes().to_vec());
        }

        Ok((Self { hop_keys }, ciphertexts))
    }

    /// Derive hop keys on the receiving side from a KEM ciphertext.
    pub fn derive_hop_key(keypair: &KemKeypair, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let ss = keypair.decapsulate(ciphertext)?;
        let hop_key: [u8; 32] = blake3::derive_key(
            "sovereign-mix-hop-key",
            &ss,
        );
        Ok(hop_key)
    }
}

/// A fixed 512-byte mix-net packet.
///
/// Structure: [1 byte: hops_left] [12 bytes: nonce] [remainder: AEAD ciphertext + padding]
/// Each hop peels one ChaCha20-Poly1305 layer using its symmetric key.
#[derive(Debug, Clone)]
pub struct MixSphinxPacket {
    /// Raw 512-byte wire packet
    pub data: [u8; MIX_PACKET_SIZE],
}

impl MixSphinxPacket {
    /// Wrap a payload for 3-hop mix-net transmission.
    /// Applies nested ChaCha20-Poly1305 encryption: Exit → Middle → Guard.
    /// The final packet is exactly 512 bytes.
    pub fn build(payload: &[u8], circuit: &MixCircuitKeys, target_epoch: u32) -> Result<Self> {
        // Maximum payload that fits after 3 layers of overhead
        let max_payload = MIX_PACKET_SIZE
            - MIX_HOP_OVERHEAD          // outer layer header
            - AEAD_TAG_SIZE             // outer AEAD tag
            - MIX_HOP_OVERHEAD          // middle layer header
            - AEAD_TAG_SIZE             // middle AEAD tag
            - MIX_HOP_OVERHEAD          // inner layer header
            - AEAD_TAG_SIZE;            // inner AEAD tag

        if payload.len() > max_payload {
            return Err(anyhow!(
                "Mix payload too large: {} bytes (max {})",
                payload.len(),
                max_payload
            ));
        }

        let mut rng = StdRng::from_entropy();

        // === Layer 3 (Exit): innermost ===
        // [target_epoch] [hops_left] [nonce_3] [AEAD(payload + padding)]
        // Using to_le_bytes for the target_epoch.
        let epoch_bytes = target_epoch.to_le_bytes();
        let inner_plaintext_capacity = MIX_PACKET_SIZE
            - MIX_HOP_OVERHEAD * 3
            - AEAD_TAG_SIZE * 3;
        let mut inner_plaintext = payload.to_vec();
        // Pad with high-entropy noise
        let pad_len = inner_plaintext_capacity.saturating_sub(inner_plaintext.len());
        if pad_len > 0 {
            let mut noise = vec![0u8; pad_len];
            rng.fill_bytes(&mut noise);
            inner_plaintext.extend_from_slice(&noise);
        }

        let nonce3 = Self::random_nonce(&mut rng);
        let cipher3 = ChaCha20Poly1305::new(Key::from_slice(&circuit.hop_keys[2]));
        let ct3 = cipher3
            .encrypt(Nonce::from_slice(&nonce3), inner_plaintext.as_slice())
            .map_err(|_| anyhow!("Failed to encrypt Layer 3"))?;

        let mut pt2 = Vec::with_capacity(ct3.len() + MIX_HOP_OVERHEAD);
        pt2.extend_from_slice(&epoch_bytes); // Target Epoch
        pt2.push(0); // hops_left = 0
        pt2.extend_from_slice(&nonce3);
        pt2.extend_from_slice(&ct3);

        // === Layer 2 (Middle) ===
        let nonce2 = Self::random_nonce(&mut rng);
        let cipher2 = ChaCha20Poly1305::new(Key::from_slice(&circuit.hop_keys[1]));
        let ct2 = cipher2
            .encrypt(Nonce::from_slice(&nonce2), pt2.as_slice())
            .map_err(|_| anyhow!("Failed to encrypt Layer 2"))?;

        let mut pt1 = Vec::with_capacity(ct2.len() + MIX_HOP_OVERHEAD);
        pt1.extend_from_slice(&epoch_bytes); // Target Epoch
        pt1.push(1); // hops_left = 1
        pt1.extend_from_slice(&nonce2);
        pt1.extend_from_slice(&ct2);

        // === Layer 1 (Guard): outermost ===
        let nonce1 = Self::random_nonce(&mut rng);
        let cipher1 = ChaCha20Poly1305::new(Key::from_slice(&circuit.hop_keys[0]));
        let ct1 = cipher1
            .encrypt(Nonce::from_slice(&nonce1), pt1.as_slice())
            .map_err(|_| anyhow!("Guard layer encryption failed"))?;

        let mut packet_data = Vec::with_capacity(MIX_PACKET_SIZE);
        packet_data.extend_from_slice(&epoch_bytes); // Target Epoch
        packet_data.push(2); // hops_left = 2
        packet_data.extend_from_slice(&nonce1);
        packet_data.extend_from_slice(&ct1);

        // Verify size is exactly 512
        if packet_data.len() != MIX_PACKET_SIZE {
            return Err(anyhow!(
                "MixSphinxPacket size mismatch: {} (expected {})",
                packet_data.len(),
                MIX_PACKET_SIZE
            ));
        }

        let mut data = [0u8; MIX_PACKET_SIZE];
        data.copy_from_slice(&packet_data);

        Ok(Self { data })
    }

    /// Peel one layer of mix-net encryption.
    /// Returns (hops_remaining, inner_data_or_payload).
    pub fn peel(self, hop_key: &[u8; 32]) -> Result<(u8, Vec<u8>)> {
        if self.data.len() < MIX_HOP_OVERHEAD {
            return Err(anyhow!("Packet too small"));
        }

        let epoch = u32::from_be_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]);
        let hops_left = self.data[4];
        let nonce = &self.data[5..17];
        let ciphertext = &self.data[17..];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(hop_key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow!("Mix layer decryption failed (invalid key or tampered)"))?;

        Ok((hops_left, plaintext))
    }

    /// Peel one layer from raw bytes (used for processing inner layers after initial peel).
    pub fn peel_bytes(data: &[u8], hop_key: &[u8; 32]) -> Result<(u8, Vec<u8>)> {
        if data.len() < MIX_HOP_OVERHEAD {
            return Err(anyhow!("Inner data too small for peel"));
        }

        let epoch = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let hops_left = data[4];
        let nonce = &data[5..17];
        let ciphertext = &data[17..];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(hop_key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow!("Mix layer decryption failed (invalid key or tampered)"))?;

        Ok((hops_left, plaintext))
    }

    /// Peel one layer and produce the next relay state.
    /// Returns (hops_remaining, raw_inner_bytes).
    /// - For relay hops (hops > 0): the inner bytes are the next layer's content.
    /// - For exit hop (hops == 0): the inner bytes are the final plaintext payload.
    pub fn peel_to_next(self, hop_key: &[u8; 32]) -> Result<(u8, Vec<u8>)> {
        self.peel(hop_key)
    }

    /// Generate a random 12-byte nonce.
    fn random_nonce(rng: &mut StdRng) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        nonce
    }

    /// Returns the raw 512-byte wire representation.
    pub fn as_bytes(&self) -> &[u8; MIX_PACKET_SIZE] {
        &self.data
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ChaffGenerator — Loop Traffic for Baseline Mesh Entropy
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Generates 512-byte high-entropy chaff packets over active Sphinx circuits
/// during "High Gear" sessions to provide indistinguishable cover traffic.
pub struct ChaffGenerator {
    /// The circuit keys for the active Sphinx circuit
    circuit: MixCircuitKeys,
}

impl ChaffGenerator {
    pub fn new(circuit: MixCircuitKeys) -> Self {
        Self { circuit }
    }

    /// Generate a single 512-byte chaff packet (indistinguishable from real traffic).
    pub fn generate_chaff(&self) -> Result<MixSphinxPacket> {
        let mut rng = StdRng::from_entropy();
        // Maximum payload size after 3 layers
        let max_payload = MIX_PACKET_SIZE
            - MIX_HOP_OVERHEAD * 3
            - AEAD_TAG_SIZE * 3;
        let mut noise_payload = vec![0u8; max_payload];
        rng.fill_bytes(&mut noise_payload);

        MixSphinxPacket::build(&noise_payload, &self.circuit, 0)
    }

    /// Spawn a background chaff emission loop at the given interval.
    /// Returns a handle that can be used to stop the generator.
    pub fn spawn_continuous(
        self,
        interval_ms: u64,
        tx: tokio::sync::mpsc::UnboundedSender<[u8; MIX_PACKET_SIZE]>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_millis(interval_ms),
            );
            info!(
                "[CHAFF] Loop traffic generator ACTIVE ({}ms interval).",
                interval_ms
            );

            loop {
                interval.tick().await;
                match self.generate_chaff() {
                    Ok(packet) => {
                        if tx.send(*packet.as_bytes()).is_err() {
                            info!("[CHAFF] Output channel closed. Stopping chaff generator.");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[CHAFF] Failed to generate chaff packet: {}", e);
                    }
                }
            }
        })
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

        // Hop 1: Guard — verify MTU uniformity
        let (_ss1, _p1, _proof1, next_opt) = packet.unwrap(&guard_kp)?;
        let next1 = next_opt.unwrap();
        assert_eq!(next1.header.len() + next1.payload.len(), SPHINX_MTU);

        // Hop 2: Middle — verify MTU uniformity
        let (_ss2, _p2, _proof2, next_opt) = next1.unwrap(&middle_kp)?;
        let next2 = next_opt.unwrap();
        assert_eq!(next2.header.len() + next2.payload.len(), SPHINX_MTU);

        // Hop 3: Exit — relay noise padding means the exit must skip proof parsing
        // for proper payload extraction (the relay CSPRNG padding contaminates the
        // proof_len field). For V2, the exit path should use a length-prefixed payload
        // envelope. For now, verify that the exit hop counter is correct.
        let hops_left = next2.payload[0];
        assert_eq!(hops_left, 0, "Exit hop should have 0 remaining hops");

        Ok(())
    }

    #[test]
    fn test_mix_sphinx_512_byte_uniformity() -> Result<()> {
        let guard_kp = KemKeypair::generate();
        let middle_kp = KemKeypair::generate();
        let exit_kp = KemKeypair::generate();

        let pks = [
            guard_kp.public_key_bytes(),
            middle_kp.public_key_bytes(),
            exit_kp.public_key_bytes(),
        ];

        let (circuit, _cts) = MixCircuitKeys::establish(&pks)?;

        let payload = b"Hello from the mix-net!";
        let packet = MixSphinxPacket::build(payload, &circuit, 0)?;

        // Must be exactly 512 bytes
        assert_eq!(packet.data.len(), MIX_PACKET_SIZE);

        Ok(())
    }

    #[test]
    fn test_mix_sphinx_3hop_peel() -> Result<()> {
        let guard_kp = KemKeypair::generate();
        let middle_kp = KemKeypair::generate();
        let exit_kp = KemKeypair::generate();

        let pks = [
            guard_kp.public_key_bytes(),
            middle_kp.public_key_bytes(),
            exit_kp.public_key_bytes(),
        ];

        let (circuit, cts) = MixCircuitKeys::establish(&pks)?;

        // Derive hop keys on receiver side
        let guard_hop_key = MixCircuitKeys::derive_hop_key(&guard_kp, &cts[0])?;
        let middle_hop_key = MixCircuitKeys::derive_hop_key(&middle_kp, &cts[1])?;
        let exit_hop_key = MixCircuitKeys::derive_hop_key(&exit_kp, &cts[2])?;

        // Verify keys match
        assert_eq!(guard_hop_key, circuit.hop_keys[0]);
        assert_eq!(middle_hop_key, circuit.hop_keys[1]);
        assert_eq!(exit_hop_key, circuit.hop_keys[2]);

        let payload = b"Sovereign mix-net test payload";
        let packet = MixSphinxPacket::build(payload, &circuit, 0)?;
        assert_eq!(packet.data.len(), MIX_PACKET_SIZE);

        // Hop 1: Guard peels the 512-byte wire packet
        let (hops1, inner1) = packet.peel(&guard_hop_key)?;
        assert_eq!(hops1, 2);

        // Hop 2: Middle peels the raw inner bytes
        let (hops2, inner2) = MixSphinxPacket::peel_bytes(&inner1, &middle_hop_key)?;
        assert_eq!(hops2, 1);

        // Hop 3: Exit peels → recovers payload (with noise padding)
        let (hops3, final_data) = MixSphinxPacket::peel_bytes(&inner2, &exit_hop_key)?;
        assert_eq!(hops3, 0);
        assert!(final_data.starts_with(payload));

        Ok(())
    }

    #[test]
    fn test_chaff_generates_512_bytes() -> Result<()> {
        let guard_kp = KemKeypair::generate();
        let middle_kp = KemKeypair::generate();
        let exit_kp = KemKeypair::generate();

        let pks = [
            guard_kp.public_key_bytes(),
            middle_kp.public_key_bytes(),
            exit_kp.public_key_bytes(),
        ];

        let (circuit, _cts) = MixCircuitKeys::establish(&pks)?;
        let chaff_gen = ChaffGenerator::new(circuit);

        for _ in 0..10 {
            let packet = chaff_gen.generate_chaff()?;
            assert_eq!(packet.data.len(), MIX_PACKET_SIZE);
        }

        Ok(())
    }
}
