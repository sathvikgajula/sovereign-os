use crate::canary::CanaryAuditor;
use pq_reputation::ReputationManager;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

/// The Orchestrator manages the background lifecycles of the Sovereign Mesh.
pub struct SovereignOrchestra {
    reputation: Arc<ReputationManager>,
    auditor: CanaryAuditor,
}

impl SovereignOrchestra {
    pub fn new(reputation: Arc<ReputationManager>) -> Self {
        let auditor = CanaryAuditor::new(reputation.clone());
        Self { reputation, auditor }
    }

    /// Spawns the background surveillance loop (Automated Canary Auditing).
    pub async fn start_background_audit(self) {
        info!("[ORCHESTRA] Background surveillance loop started (60s intervals).");
        let mut audit_interval = interval(Duration::from_secs(60));

        loop {
            audit_interval.tick().await;
            info!("[AUDITOR] Initiating autonomous trust mesh audit...");

            match self.reputation.get_all_scores().await {
                Ok(scores) => {
                    // Audit "Neutral" nodes discovered via signaling
                    let neutral_nodes: Vec<_> = scores.into_iter()
                        .filter(|s| s.expected_value() >= 0.4 && s.expected_value() <= 0.6)
                        .collect();

                    for node in neutral_nodes {
                        info!("[AUDITOR] Selected neutral relay for audit: {}", node.peer_did);
                        // In a real scenario, we'd fetch the peer's PKs from DHT/Nostr
                        // For the audit, we simulate with dummy PKs
                        let dummy_pks = [vec![0u8; 32], vec![0u8; 32], vec![0u8; 32]];
                        if let Err(e) = self.auditor.audit_relay(node.peer_did, &dummy_pks).await {
                             warn!("[AUDITOR] Audit cycle failed for node: {}", e);
                        }
                    }
                }
                Err(e) => warn!("[ORCHESTRA] Failed to fetch peers from ledger: {}", e),
            }
        }
    }
}
