use crate::vault::DeterministicMapper;
use anyhow::Result;
use std::cmp;
use tracing::{info, warn};

/// Maximum number of epochs to retrospectively search.
pub const MAX_SWEEP_EPOCHS: u64 = 4;

/// VaultSynchronizer manages queries for Vault IDs across previously disconnected epochs.
pub struct VaultSynchronizer {
    /// In a production scenario, this operates against an SQLite backing store.
    /// Simulated here in-memory for the 2.0-RC1 context.
    epoch_sync_cursor: u64,
}

impl VaultSynchronizer {
    pub fn new(initial_cursor: u64) -> Self {
        Self {
            epoch_sync_cursor: initial_cursor,
        }
    }

    /// Retrieve the current epoch cursor.
    pub fn cursor(&self) -> u64 {
        self.epoch_sync_cursor
    }

    /// Executed upon Wake (e.g. OS "BackgroundAppRefresh").
    /// Generates the list of `[u8; 32]` Vault IDs to issue PIR queries for,
    /// clamping the sweep window to `MAX_SWEEP_EPOCHS` to prevent Sync Storms.
    pub fn sweep_epochs(
        &mut self,
        shared_secret: &[u8],
        current_epoch: u64,
        shard_count: u32,
    ) -> Result<Vec<[u8; 32]>> {
        if self.epoch_sync_cursor >= current_epoch {
            // No missed epochs. Just query the current epoch if needed.
            self.epoch_sync_cursor = current_epoch;
            return Ok(vec![]);
        }

        // Clamp the sweep so we never evaluate more than MAX_SWEEP_EPOCHS ago
        let latest_allowed_start = current_epoch.saturating_sub(MAX_SWEEP_EPOCHS);
        let sweep_start = cmp::max(self.epoch_sync_cursor, latest_allowed_start);

        if self.epoch_sync_cursor < sweep_start {
            warn!(
                "[SYNC] Long blackout detected. Clamping sync sweep from E_{} to E_{}",
                self.epoch_sync_cursor, sweep_start
            );
        } else {
            info!(
                "[SYNC] Submarine Wake: Sweeping epochs E_{} to E_{}",
                sweep_start, current_epoch
            );
        }

        let mut query_vault_ids = Vec::new();

        // Include current_epoch in the sweep
        for epoch in sweep_start..=current_epoch {
            for i in 0..shard_count {
                let v_id = DeterministicMapper::compute_vault_id_at_epoch(shared_secret, epoch, i)?;
                query_vault_ids.push(v_id);
            }
        }

        // Fast-forward cursor
        self.epoch_sync_cursor = current_epoch;

        Ok(query_vault_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sweep_clamps_to_max_epochs() {
        let mut sync = VaultSynchronizer::new(10);
        
        let secret = b"my-shared-secret";
        let current_epoch = 20;

        // E_last = 10, E_current = 20. Diff is 10 epochs.
        // It should clamp to max(10, 20-4) = 16.
        // So it sweeps 16, 17, 18, 19, 20 (5 epochs total inclusive).
        
        let ids = sync.sweep_epochs(secret, current_epoch, 3).unwrap();
        // 5 epochs * 3 shards = 15 total PIR queries
        assert_eq!(ids.len(), 15);
        
        // Assert the cursor was updated correctly to current epoch
        assert_eq!(sync.cursor(), 20);
    }
    
    #[test]
    fn test_sweep_no_clamp_needed() {
        let mut sync = VaultSynchronizer::new(18);
        
        let secret = b"my-shared-secret";
        let current_epoch = 20;
        
        // E_last = 18, E_current = 20.
        // Sweeps 18, 19, 20.
        let ids = sync.sweep_epochs(secret, current_epoch, 3).unwrap();
        assert_eq!(ids.len(), 9); 
        assert_eq!(sync.cursor(), 20);
    }
}
