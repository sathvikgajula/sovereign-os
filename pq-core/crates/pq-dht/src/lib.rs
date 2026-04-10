use anyhow::Result;
use blake3::Hasher;
use pq_reputation::ReputationManager;

pub const K_BUCKET_SIZE: usize = 20;

#[derive(Clone, Debug)]
pub struct PeerRecord {
    pub did: String,
    pub address: String,
    pub xor_distance: [u8; 32],
}

pub struct TrustGatedDht {
    local_did_hash: [u8; 32],
    // 256 buckets for 256-bit XOR distances
    pub buckets: Vec<Vec<PeerRecord>>,
    pub reputation: ReputationManager,
}

impl TrustGatedDht {
    pub fn new(local_did: &str, reputation: ReputationManager) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(local_did.as_bytes());
        let local_did_hash: [u8; 32] = hasher.finalize().into();

        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(Vec::with_capacity(K_BUCKET_SIZE));
        }

        Self {
            local_did_hash,
            buckets,
            reputation,
        }
    }

    /// Measures XOR distance between local node and a target peer DID.
    pub fn xor_distance(&self, target_did: &str) -> ([u8; 32], usize) {
        let mut hasher = Hasher::new();
        hasher.update(target_did.as_bytes());
        let target_hash: [u8; 32] = hasher.finalize().into();

        let mut distance = [0u8; 32];
        let mut leading_zeros = 0;
        let mut found_one = false;
        
        for i in 0..32 {
            distance[i] = self.local_did_hash[i] ^ target_hash[i];
            
            if !found_one {
                if distance[i] == 0 {
                    leading_zeros += 8;
                } else {
                    leading_zeros += distance[i].leading_zeros() as usize;
                    found_one = true;
                }
            }
        }
        
        let bucket_index = 255 - leading_zeros.min(255);
        (distance, bucket_index)
    }

    /// The Gatekeeper Logic: Attempt to insert a node into the K-Bucket table.
    /// ONLY nodes with E[R] >= 0.7 are allowed.
    pub async fn attempt_insert_node(&mut self, did: String, address: String) -> Result<bool> {
        // 1. HARD GATE: Query Reputation Manager
        let score = self.reputation.get_score(did.clone()).await?;
        if score.expected_value() < 0.7 {
            // Violently reject the node
            anyhow::bail!("HARD GATE REJECTION: Peer {} expected reputation score ({:.3}) is below index admission threshold (0.7)", did, score.expected_value());
        }

        // 2. Insert into the K-Bucket
        let (distance, bucket_index) = self.xor_distance(&did);
        let bucket = &mut self.buckets[bucket_index];

        // Replace if exists
        for record in bucket.iter_mut() {
            if record.did == did {
                record.address = address;
                return Ok(true);
            }
        }

        // Add if space exists
        if bucket.len() < K_BUCKET_SIZE {
            bucket.push(PeerRecord {
                did,
                address,
                xor_distance: distance,
            });
            return Ok(true);
        }

        Ok(false) // Bucket full
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_dht_hard_gate_rejection() -> Result<()> {
        let db_path = PathBuf::from("/tmp/rep_test_dht.db");
        let _ = std::fs::remove_file(&db_path);
        
        let rep = ReputationManager::new(db_path.clone()).await?;
        
        // Initial reputation is 0.5 (1.0 / 2.0). 
        // Our constraint drops anything < 0.7.
        // Therefore, any new peer with no positive interaction is INSTANTLY blocked from our DHT routing table!
        
        let mut dht = TrustGatedDht::new("did:pqc:local", rep.clone());
        
        let peer_did = "did:pqc:untested".to_string();
        
        let result = dht.attempt_insert_node(peer_did.clone(), "127.0.0.1:0".to_string()).await;
        assert!(result.is_err(), "Untested node was allowed into DHT! Hard gate failure.");
        assert_eq!(dht.buckets.iter().map(|b| b.len()).sum::<usize>(), 0);

        // Subsidize node
        rep.update_score(peer_did.clone(), true).await?; // alpha = 2.0, beta = 1.0 (E = 0.66) -- STILL BLOCKED!
        let result = dht.attempt_insert_node(peer_did.clone(), "127.0.0.1:0".to_string()).await;
        assert!(result.is_err());
        
        rep.update_score(peer_did.clone(), true).await?; // alpha = 3.0, beta = 1.0 (E = 0.75) -- ACCEPTED!
        let result = dht.attempt_insert_node(peer_did.clone(), "127.0.0.1:0".to_string()).await;
        assert!(result.is_ok(), "High trust peer was blocked from DHT!");
        assert_eq!(dht.buckets.iter().map(|b| b.len()).sum::<usize>(), 1);

        Ok(())
    }
}
