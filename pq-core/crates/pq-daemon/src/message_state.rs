use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::info;

/// Airborne physical message states representing the lifecycle of Sovereign OS communications
/// exposed to the Tauri UI dashboard.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageState {
    /// Payload erasure-coded, shards signed, ready for vault distribution
    Sealed,
    /// Shards successfully confirmed in the Deterministic Rendezvous Vaults
    Vaulted,
    /// Receipt pulled from Vault confirming the recipient reconstructed the message
    Reconstructed,
}

#[derive(Debug, Clone)]
pub struct MessageEvent {
    pub payload_hash: String,
    pub state: MessageState,
    pub timestamp_ms: u64,
    pub shard_count: u8,
}

pub struct MessageStateTracker {
    tx: broadcast::Sender<MessageEvent>,
}

impl MessageStateTracker {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(100);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MessageEvent> {
        self.tx.subscribe()
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub fn mark_sealed(&self, payload_hash: &str, shard_count: u8) {
        let event = MessageEvent {
            payload_hash: payload_hash.to_string(),
            state: MessageState::Sealed,
            timestamp_ms: Self::now_ms(),
            shard_count,
        };
        info!("[UX STATE] Message SEALED: {}", payload_hash);
        let _ = self.tx.send(event);
    }

    pub fn mark_vaulted(&self, payload_hash: &str, shard_count: u8) {
        let event = MessageEvent {
            payload_hash: payload_hash.to_string(),
            state: MessageState::Vaulted,
            timestamp_ms: Self::now_ms(),
            shard_count,
        };
        info!("[UX STATE] Message VAULTED: {}", payload_hash);
        let _ = self.tx.send(event);
    }

    pub fn mark_reconstructed(&self, payload_hash: &str) {
        let event = MessageEvent {
            payload_hash: payload_hash.to_string(),
            state: MessageState::Reconstructed,
            timestamp_ms: Self::now_ms(),
            shard_count: 0, // Ignored here
        };
        info!("[UX STATE] Message RECONSTRUCTED: {}", payload_hash);
        let _ = self.tx.send(event);
    }
}

impl Default for MessageStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_message_state_flow() {
        let tracker = MessageStateTracker::new();
        let mut rx = tracker.subscribe();

        // Simulate lifecycle
        let hash = "deadbeef";
        tracker.mark_sealed(hash, 5);
        tracker.mark_vaulted(hash, 5);
        tracker.mark_reconstructed(hash);

        // Verify broadcast events
        let ev1 = rx.recv().await.unwrap();
        assert_eq!(ev1.state, MessageState::Sealed);
        
        let ev2 = rx.recv().await.unwrap();
        assert_eq!(ev2.state, MessageState::Vaulted);

        let ev3 = rx.recv().await.unwrap();
        assert_eq!(ev3.state, MessageState::Reconstructed);
    }
}
