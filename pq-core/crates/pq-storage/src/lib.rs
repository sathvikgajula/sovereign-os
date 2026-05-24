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
pub mod vault;
pub mod sync;

use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct PqShard {
    pub cid: String,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

pub const CHUNK_SIZE: usize = 66560; // 65KB (64KB data + AEAD overhead)

/// Institutional-Grade Ephemeral Storage
pub struct EphemeralStore {
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

    pub async fn store_chunk(&self, cid: [u8; 32], data: Vec<u8>) -> Result<()> {
        if data.len() > CHUNK_SIZE {
            return Err(anyhow!("Chunk exceeds 64KB limit"));
        }
        self.cache.insert(cid, data).await;
        Ok(())
    }

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
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(nonce_bytes);
        let payload = Payload {
            msg: encrypted_receipt,
            aad,
        };
        
        let decrypted_receipt = cipher
            .decrypt(nonce, payload)
            .map_err(|_| anyhow!("Invalid Kill Signal MAC. Rejection triggered."))?;

        self.cache.remove(&cid).await;
        info!("[STORAGE] Chunk Evicted | CID: {}", hex::encode(cid));

        let rep = self.reputation.clone();
        let cid_hex = hex::encode(cid);
        let pk = public_key_bytes.to_vec();
        
        tokio::task::spawn(async move {
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

    pub async fn get_inventory(&self) -> Vec<String> {
        self.cache
            .iter()
            .map(|(cid, _)| hex::encode(*cid))
            .collect()
    }
}

use tokio_rusqlite::Connection;
use std::path::PathBuf;

/// Persistent Shard Database using tokio-rusqlite.
#[derive(Clone)]
pub struct PqDatabase {
    conn: Connection,
}

impl PqDatabase {
    /// Opens the SQLite database in WAL mode and initializes the shard table.
    pub async fn open(base_path: PathBuf) -> Result<Self> {
        let db_path = base_path.join("shards.db");
        let conn = Connection::open(db_path).await
            .map_err(|e| anyhow!("Failed to open shards.db: {}", e))?;
        
        // Use WAL mode for high-concurrency 5G transport
        conn.call(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 CREATE TABLE IF NOT EXISTS shards (
                    cid BLOB PRIMARY KEY,
                    data BLOB,
                    timestamp INTEGER
                 );"
            ).map_err(|e| e.into())
        }).await.map_err(|e| anyhow!("Failed to initialize shard table in WAL mode: {}", e))?;

        info!("[STORAGE] SQLite Anchored | Mode: WAL | Path: {:?}", base_path);

        Ok(Self { conn })
    }

    /// Commits an incoming shard to the persistent storage (Asynchronous).
    pub async fn save_shard(&self, cid: [u8; 32], data: Vec<u8>) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        self.conn.call(move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO shards (cid, data, timestamp) VALUES (?1, ?2, ?3)",
                rusqlite::params![&cid, &data, timestamp],
            ).map_err(|e| e.into())
        }).await.map_err(|e| anyhow!("Failed to persist shard to SQLite: {}", e))?;
        
        Ok(())
    }

    /// Retrieves all persisted shards for cache restoration (Asynchronous).
    pub async fn get_all_shards(&self) -> Result<Vec<PqShard>> {
        self.conn.call(|conn| {
            let mut stmt = conn.prepare("SELECT cid, data, timestamp FROM shards ORDER BY timestamp DESC")?;
            let rows = stmt.query_map([], |row| {
                let cid: Vec<u8> = row.get(0)?;
                let data: Vec<u8> = row.get(1)?;
                let timestamp: u64 = row.get(2)?;
                Ok(PqShard {
                    cid: hex::encode(cid),
                    data,
                    timestamp,
                })
            })?;

            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        }).await.map_err(|e| anyhow!("Failed to query shards: {}", e))
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

    #[tokio::test]
    async fn test_pq_database_persistence() -> Result<()> {
        let base_path = PathBuf::from("/tmp/node_test_async");
        let _ = std::fs::remove_dir_all(&base_path);
        std::fs::create_dir_all(&base_path).unwrap();
        
        let db = PqDatabase::open(base_path).await?;
        let cid = [0x11; 32];
        let data = vec![0x22; 100];
        
        db.save_shard(cid, data.clone()).await?;
        
        let shards = db.get_all_shards().await?;
        assert_eq!(shards.len(), 1);
        assert_eq!(hex::decode(&shards[0].cid).unwrap(), cid);
        assert_eq!(shards[0].data, data);
        Ok(())
    }
}
