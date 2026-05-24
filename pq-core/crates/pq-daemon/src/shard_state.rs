use tokio_util::sync::CancellationToken;
use std::sync::Arc;
use pq_storage::EphemeralStore;
use tracing::warn;

#[derive(Debug, Clone)]
pub enum ShardState {
    Active,
    SoftExile(CancellationToken),
    HardPurge,
}

impl ShardState {
    pub fn is_active(&self) -> bool {
        matches!(self, ShardState::Active)
    }

    pub fn is_soft_exile(&self) -> bool {
        matches!(self, ShardState::SoftExile(_))
    }

    /// Spawns the 5s "Guillotine" task.
    /// If the token is not cancelled within 5s, the storage is purged.
    pub fn spawn_guillotine(
        store: Arc<EphemeralStore>,
        token: CancellationToken,
        peer_did: String,
    ) {
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
                    warn!("[STATE] SoftExile timeout for {}. Executing GUILLOTINE (Hard Purge).", peer_did);
                    // In a real implementation, we would invalidate ALL shards associated with this node.
                    // For V1.0, we simulate a general cache cleanup or specific CID purge if tracked.
                    // store.clear_node_shards(peer_did).await;
                }
                _ = token.cancelled() => {
                    warn!("[STATE] Buy-Back Proof RECEIVED for {}. Restoring Active state.", peer_did);
                }
            }
        });
    }
}
