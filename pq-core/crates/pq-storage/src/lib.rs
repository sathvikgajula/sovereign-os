use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use moka::future::Cache;
use pq_crypto::{verify_signature};
use pq_reputation::ReputationManager;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, error};

pub mod drg;

pub const CHUNK_SIZE: usize = 66560; // 65KB (64KB data + AEAD overhead)

/// Institutional-Grade Ephemeral Storage
pub struct EphemeralStore {
    /// RAM-based chunk cache with 5-minute TTL
    cache: Cache<[u8; 32], Vec<u8>>,
    reputation: ReputationManager,
}

impl EphemeralStore {
    pub fn new(reputation: ReputationManager) -> Self {
        let cache = Cache::builder()
            .max_capacity(1024) // 1024 * 64KB = 64MB RAM limit
            .time_to_live(Duration::from_secs(300))
            .build();
        
        Self { cache, reputation }
    }

    /// Stores a 64KB chunk in RAM.
    pub async fn store_chunk(&self, cid: [u8; 32], data: Vec<u8>) -> Result<()> {
        if data.len() > CHUNK_SIZE {
            return Err(anyhow!("Chunk exceeds 64KB limit"));
        }
        self.cache.insert(cid, data).await;
        Ok(())
    }

    /// The "Purge-First" Eviction Sequence.
    /// 1. Verify MAC (ChaCha20-Poly1305)
    /// 2. Evict IMMEDIATELY from RAM
    /// 3. Asynchronously update reputation ledger
    pub async fn handle_kill_signal(
        &self,
        cid: [u8; 32],
        key: &[u8; 32],
        nonce_bytes: &[u8; 12],
        aad: &[u8],
        encrypted_receipt: &[u8],
        peer_did: String,
        public_key_bytes: &[u8],
    ) -> Result<()> {
        // STEP 1: Verify (Validate ChaCha20-Poly1305 MAC)
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(nonce_bytes);
        let payload = Payload {
            msg: encrypted_receipt,
            aad,
        };
        
        // This validates the integrity of the receipt before we do anything.
        let decrypted_receipt = cipher
            .decrypt(nonce, payload)
            .map_err(|_| anyhow!("Invalid Kill Signal MAC. Rejection triggered."))?;

        // STEP 2: Evict (INSTANTLY drop from Moka RAM cache)
        self.cache.remove(&cid).await;
        info!("[STORAGE] Chunk Evicted | CID: {}", hex::encode(cid));

        // STEP 3: Account (Asynchronously dispatch ML-DSA-65 verify and reputation update)
        let rep = self.reputation.clone();
        let cid_hex = hex::encode(cid);
        let pk = public_key_bytes.to_vec();
        
        tokio::task::spawn(async move {
            // Verify the ML-DSA-65 signature inside the decrypted receipt
            // Expecting receipt format: [Signature (2420 bytes)] [Original_CID (32 bytes)]
            if decrypted_receipt.len() < 2420 + 32 {
                error!("[REPUTATION] Malformed receipt data for {}", cid_hex);
                return;
            }
            
            let signature = &decrypted_receipt[0..2420];
            let signed_cid = &decrypted_receipt[2420..2452];
            
            if signed_cid != cid.as_slice() {
                error!("[REPUTATION] Receipt CID mismatch for {}", cid_hex);
                return;
            }

            match verify_signature(signed_cid, signature, &pk) {
                Ok(_) => {
                    // Update alpha score to clear bandwidth vouchers
                    if let Err(e) = rep.update_score(peer_did.clone(), true).await {
                        error!("[REPUTATION] Failed to commit payout for {}: {}", peer_did, e);
                    } else {
                        info!("[REPUTATION] Payout Committed | Peer: {}", peer_did);
                    }
                }
                Err(e) => {
                    error!("[SECURITY] Invalid ML-DSA-65 receipt for {}: {}", cid_hex, e);
                }
            }
        });

        Ok(())
    }

    pub async fn get_chunk(&self, cid: &[u8; 32]) -> Option<Vec<u8>> {
        self.cache.get(cid).await
    }

    /// Retrieve all CIDs in the cache for dashboard visualization.
    pub async fn get_inventory(&self) -> Vec<String> {
        self.cache
            .iter()
            .map(|(cid, _)| hex::encode(*cid))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_crypto::{SigningKeypair};
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_purge_first_eviction() -> Result<()> {
        let db_path = PathBuf::from("/tmp/rep_storage_test.db");
        let _ = std::fs::remove_file(&db_path);
        let rep = ReputationManager::new(db_path).await?;
        let store = EphemeralStore::new(rep);

        let cid = [0xAA; 32];
        let data = vec![0xBB; 64];
        store.store_chunk(cid, data.clone()).await?;

        // Prepare Kill Signal
        let key = [0xCC; 32];
        let nonce = [0xDD; 12];
        let aad = b"kill-signal-aad";
        
        let signing_kp = SigningKeypair::generate();
        let signature = signing_kp.sign(&cid);
        let mut receipt = signature.clone();
        receipt.extend_from_slice(&cid);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let encrypted_receipt = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: &receipt, aad }).unwrap();

        // Execution
        store.handle_kill_signal(
            cid,
            &key,
            &nonce,
            aad,
            &encrypted_receipt,
            "did:pqc:test_peer".to_string(),
            &signing_kp.public_key_bytes()
        ).await?;

        // Verify Eviction
        assert!(store.get_chunk(&cid).await.is_none(), "Chunk was not immediately evicted!");

        // Wait for async reputation update
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        Ok(())
    }
}
