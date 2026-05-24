//! # Receipt Tracker — The Sender's Burden
//!
//! Monitors delivery receipts stored in deterministic Vaults.
//! If a receipt isn't found within 24 hours, automatically triggers
//! re-distribution of shards to the next epoch's Vaults.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// 24-hour receipt timeout in seconds.
const RECEIPT_TIMEOUT_SECS: u64 = 24 * 3600;

/// Tracks a single delivery's receipt status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryRecord {
    /// BLAKE3 hash of the original payload
    pub payload_hash: [u8; 32],
    /// Vault IDs where shards were deposited
    pub shard_vault_ids: Vec<[u8; 32]>,
    /// Unix timestamp when shards were deposited
    pub deposited_at: u64,
    /// The epoch at which shards were distributed
    pub epoch: u64,
    /// Whether a receipt has been confirmed
    pub receipt_confirmed: bool,
    /// Shared secret used for vault ID computation (for re-distribution)
    pub shared_secret: Vec<u8>,
    /// Epoch duration in seconds
    pub epoch_duration_secs: u64,
    /// Number of redistribution attempts
    pub redistribution_count: u32,
}

/// Manages the lifecycle of shard delivery receipts.
pub struct ReceiptTracker {
    /// Active deliveries indexed by payload hash
    deliveries: HashMap<[u8; 32], DeliveryRecord>,
    /// Maximum redistribution attempts before giving up
    max_redistributions: u32,
}

impl ReceiptTracker {
    pub fn new() -> Self {
        Self {
            deliveries: HashMap::new(),
            max_redistributions: 3,
        }
    }

    /// Register a new delivery for tracking.
    pub fn register_delivery(
        &mut self,
        payload_hash: [u8; 32],
        shard_vault_ids: Vec<[u8; 32]>,
        shared_secret: Vec<u8>,
        epoch: u64,
        epoch_duration_secs: u64,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let record = DeliveryRecord {
            payload_hash,
            shard_vault_ids,
            deposited_at: now,
            epoch,
            receipt_confirmed: false,
            shared_secret,
            epoch_duration_secs,
            redistribution_count: 0,
        };

        self.deliveries.insert(payload_hash, record);
        info!(
            "[RECEIPT] Delivery registered (hash={}, epoch={})",
            hex::encode(&payload_hash[..8]),
            epoch
        );

        Ok(())
    }

    /// Confirm receipt of a delivery.
    pub fn confirm_receipt(&mut self, payload_hash: &[u8; 32]) -> Result<()> {
        let record = self.deliveries.get_mut(payload_hash)
            .ok_or_else(|| anyhow!("No delivery found for hash"))?;

        record.receipt_confirmed = true;
        info!(
            "[RECEIPT] Delivery CONFIRMED (hash={})",
            hex::encode(&payload_hash[..8])
        );

        Ok(())
    }

    /// Check all pending deliveries for 24-hour timeout.
    /// Returns a list of payload hashes that need re-distribution.
    pub fn check_timeouts(&self) -> Result<Vec<[u8; 32]>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let mut expired = Vec::new();

        for (hash, record) in &self.deliveries {
            if record.receipt_confirmed {
                continue;
            }
            if record.redistribution_count >= self.max_redistributions {
                warn!(
                    "[RECEIPT] Delivery {} exceeded max redistributions ({}). Abandoned.",
                    hex::encode(&hash[..8]),
                    self.max_redistributions
                );
                continue;
            }
            if now.saturating_sub(record.deposited_at) >= RECEIPT_TIMEOUT_SECS {
                info!(
                    "[RECEIPT] Delivery {} TIMED OUT after 24h. Queuing for re-distribution.",
                    hex::encode(&hash[..8])
                );
                expired.push(*hash);
            }
        }

        Ok(expired)
    }

    /// Mark a delivery as redistributed to the next epoch.
    pub fn mark_redistributed(
        &mut self,
        payload_hash: &[u8; 32],
        new_vault_ids: Vec<[u8; 32]>,
        new_epoch: u64,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let record = self.deliveries.get_mut(payload_hash)
            .ok_or_else(|| anyhow!("No delivery found for hash"))?;

        record.shard_vault_ids = new_vault_ids;
        record.epoch = new_epoch;
        record.deposited_at = now;
        record.redistribution_count += 1;

        info!(
            "[RECEIPT] Delivery {} redistributed to epoch {} (attempt #{})",
            hex::encode(&payload_hash[..8]),
            new_epoch,
            record.redistribution_count
        );

        Ok(())
    }

    /// Get a delivery record by payload hash.
    pub fn get_delivery(&self, payload_hash: &[u8; 32]) -> Option<&DeliveryRecord> {
        self.deliveries.get(payload_hash)
    }

    /// Remove confirmed deliveries to free memory.
    pub fn gc_confirmed(&mut self) -> usize {
        let before = self.deliveries.len();
        self.deliveries.retain(|_, record| !record.receipt_confirmed);
        let removed = before - self.deliveries.len();
        if removed > 0 {
            info!("[RECEIPT] GC: removed {} confirmed deliveries", removed);
        }
        removed
    }

    /// Number of active (unconfirmed) deliveries.
    pub fn pending_count(&self) -> usize {
        self.deliveries.values().filter(|r| !r.receipt_confirmed).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_confirm() -> Result<()> {
        let mut tracker = ReceiptTracker::new();
        let hash = [0xAA; 32];
        let vaults = vec![[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]];

        tracker.register_delivery(hash, vaults, vec![0x99; 32], 100, 3600)?;
        assert_eq!(tracker.pending_count(), 1);

        tracker.confirm_receipt(&hash)?;
        assert_eq!(tracker.pending_count(), 0);

        let removed = tracker.gc_confirmed();
        assert_eq!(removed, 1);

        Ok(())
    }

    #[test]
    fn test_timeout_detection() -> Result<()> {
        let mut tracker = ReceiptTracker::new();
        let hash = [0xBB; 32];
        let vaults = vec![[0x11; 32]];

        tracker.register_delivery(hash, vaults, vec![0x99; 32], 100, 3600)?;

        // Manually age the delivery past 24h
        if let Some(record) = tracker.deliveries.get_mut(&hash) {
            record.deposited_at = 0; // Unix epoch = ancient
        }

        let expired = tracker.check_timeouts()?;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], hash);

        Ok(())
    }

    #[test]
    fn test_redistribution_tracking() -> Result<()> {
        let mut tracker = ReceiptTracker::new();
        let hash = [0xCC; 32];
        let vaults = vec![[0x11; 32]];

        tracker.register_delivery(hash, vaults, vec![0x99; 32], 100, 3600)?;

        let new_vaults = vec![[0xAA; 32]];
        tracker.mark_redistributed(&hash, new_vaults, 101)?;

        let record = tracker.get_delivery(&hash).unwrap();
        assert_eq!(record.epoch, 101);
        assert_eq!(record.redistribution_count, 1);

        Ok(())
    }

    #[test]
    fn test_max_redistribution_limit() -> Result<()> {
        let mut tracker = ReceiptTracker::new();
        let hash = [0xDD; 32];
        let vaults = vec![[0x11; 32]];

        tracker.register_delivery(hash, vaults, vec![0x99; 32], 100, 3600)?;

        // Exhaust redistribution attempts
        for i in 0..3 {
            tracker.mark_redistributed(&hash, vec![[0x11; 32]], 101 + i)?;
        }

        // Manually age past 24h
        if let Some(record) = tracker.deliveries.get_mut(&hash) {
            record.deposited_at = 0;
        }

        // Should NOT appear in timeouts (exceeded max redistributions)
        let expired = tracker.check_timeouts()?;
        assert_eq!(expired.len(), 0);

        Ok(())
    }
}
