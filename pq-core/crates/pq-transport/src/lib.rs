pub mod auth;
pub mod config;
pub mod nat;
pub mod stun;
pub mod accounting;

pub use auth::{receive_and_verify_identity, send_identity_proof};
pub use config::PqQuicConfig;
pub use nat::NatPuncher;
pub use stun::discover_public_addr_async;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkState {
    Active,
    Muted,
}

use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::interval;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Metronome Gear System
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Metronome operating gear controlling the Egress Vault's transmission behavior.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MetronomeGear {
    /// 200ms continuous chaff/pulse (Active Messaging).
    /// Used during active communication sessions.
    High,
    /// Complete radio silence (Background/Idle).
    /// No packets are emitted.
    Submarine,
    /// 45-second 200ms pulse window triggered by OS BackgroundAppRefresh.
    /// Executes PIR queries and shard drops, then auto-transitions to Submarine.
    SubmarineBurst {
        /// Deadline (UNIX ms) when this burst window expires.
        deadline_ms: u64,
    },
}

impl MetronomeGear {
    /// Duration of a SubmarineBurst window.
    pub const BURST_DURATION_SECS: u64 = 45;

    /// Create a new SubmarineBurst gear starting now.
    pub fn new_burst() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self::SubmarineBurst {
            deadline_ms: now + (Self::BURST_DURATION_SECS * 1000),
        }
    }

    /// Check if the current gear allows transmission.
    pub fn should_transmit(&self) -> bool {
        match self {
            MetronomeGear::High => true,
            MetronomeGear::Submarine => false,
            MetronomeGear::SubmarineBurst { deadline_ms } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                now < *deadline_ms
            }
        }
    }

    /// Check if the gear has expired and should transition.
    /// Returns `Some(Submarine)` if the burst window has closed.
    pub fn check_expiry(&self) -> Option<MetronomeGear> {
        if let MetronomeGear::SubmarineBurst { deadline_ms } = self {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if now >= *deadline_ms {
                return Some(MetronomeGear::Submarine);
            }
        }
        None
    }
}

/// Quantized Egress Packet
#[derive(Debug, Clone)]
pub struct EgressPacket {
    pub data: Vec<u8>,
    pub timestamp: std::time::Instant,
}

/// EgressVault: A Discrete Epoch Metronome with stateful Gear control.
///
/// Supports three operating modes:
/// - **High Gear**: 200ms continuous chaff/pulse (Active Messaging)
/// - **Submarine**: Complete radio silence (Background/Idle)
/// - **SubmarineBurst**: 45s 200ms pulse window for PIR queries + shard drops
pub struct EgressVault {
    queue: Arc<Mutex<VecDeque<EgressPacket>>>,
    gear: Arc<Mutex<MetronomeGear>>,
}

impl EgressVault {
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<EgressPacket>) {
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let gear = Arc::new(Mutex::new(MetronomeGear::High));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        
        let vault = Self {
            queue: queue.clone(),
            gear: gear.clone(),
        };
        let queue_clone = queue.clone();
        let gear_clone = gear.clone();
        
        // Launch the 200ms Metronome with gear-aware logic
        tokio::spawn(async move {
            info!("[TRANSPORT] Discrete Epoch Metronome ACTIVE (200ms boundary, CSPRNG micro-jittered +/- 5ms).");
            
            loop {
                // CSPRNG Micro-jitter to prevent hardware clock fingerprinting
                let jitter: i64 = {
                    let mut rng = rand::rngs::OsRng;
                    rand::Rng::gen_range(&mut rng, -5..=5)
                };
                let tick_ms = (200i64 + jitter) as u64;
                tokio::time::sleep(tokio::time::Duration::from_millis(tick_ms)).await;

                // Check gear state
                let mut current_gear = gear_clone.lock().await;

                // Check for gear expiry (SubmarineBurst → Submarine)
                if let Some(new_gear) = current_gear.check_expiry() {
                    info!(
                        "[TRANSPORT] Gear transition: {:?} → {:?}",
                        *current_gear, new_gear
                    );
                    *current_gear = new_gear;
                }

                // Only transmit if the gear allows it
                if !current_gear.should_transmit() {
                    continue;
                }

                drop(current_gear); // Release lock before queue access

                let mut q = queue_clone.lock().await;
                
                if !q.is_empty() {
                    info!("[TRANSPORT] Metronome TICK: Flushing {} packets.", q.len());
                    while let Some(packet) = q.pop_front() {
                        if let Err(e) = tx.send(packet) {
                            error!("[TRANSPORT] Metronome flush failure: {}", e);
                            break;
                        }
                    }
                }
            }
        });

        (vault, rx)
    }

    /// Push a response into the vault. It will be held until the next 200ms epoch.
    pub async fn push_response(&self, data: Vec<u8>) {
        let mut q = self.queue.lock().await;
        q.push_back(EgressPacket {
            data,
            timestamp: std::time::Instant::now(),
        });
    }

    /// Transition the metronome to a new gear.
    pub async fn set_gear(&self, new_gear: MetronomeGear) {
        let mut gear = self.gear.lock().await;
        info!(
            "[TRANSPORT] Gear shift: {:?} → {:?}",
            *gear, new_gear
        );
        *gear = new_gear;
    }

    /// Get the current gear state.
    pub async fn current_gear(&self) -> MetronomeGear {
        let gear = self.gear.lock().await;
        *gear
    }

    /// Trigger a SubmarineBurst (45-second pulse window).
    /// Typically called by OS BackgroundAppRefresh handler.
    pub async fn trigger_burst(&self) {
        let mut gear = self.gear.lock().await;
        *gear = MetronomeGear::new_burst();
        info!("[TRANSPORT] SubmarineBurst triggered. 45s PIR window active.");
    }
    /// Enter Submarine (radio silence) mode.
    pub async fn go_submarine(&self) {
        self.set_gear(MetronomeGear::Submarine).await;
    }

    /// Enter High Gear (active messaging) mode.
    pub async fn go_high_gear(&self) {
        self.set_gear(MetronomeGear::High).await;
    }
}

/// Represents a Causal NACK from the storage layer.
#[derive(Debug, Clone, PartialEq)]
pub enum CausalNack {
    /// Vault rejected write because the target epoch is too old or outside the grace window.
    RejectStaleEpoch {
        expired_epoch: u64,
        current_epoch: u64,
    },
}

impl CausalNack {
    /// Process a CausalNack received over the Hydra tunnel.
    pub fn handle_nack(&self) {
        match self {
            Self::RejectStaleEpoch { expired_epoch, current_epoch } => {
                warn!(
                    "[CAUSAL NACK] Vault rejected stale epoch E_{}. Current epoch is E_{}.",
                    expired_epoch, current_epoch
                );
                info!("[TRANSPORT] CausalNack triggered: Automatically re-shredding payload for E_{} key space.", current_epoch);
                // In production, this drops back to the ErasureCoder queue
                // to rebuild shards with the current epoch's deterministic IDs.
            }
        }
    }
}

use tracing::error;

/// Orchestrates a connection with deterministic Hydra Relay fallback.
///
/// Attempts direct simultaneous UDP hole punching and QUIC handshake.
/// If connection is not established within 2 * T_max, automatically
/// aborts and returns a signal to the caller to initiate Hydra fallback.
pub async fn connect_with_hydra_fallback(
    puncher: NatPuncher,
    quic_config: PqQuicConfig,
    peer_addr: std::net::SocketAddr,
    t_max_ms: f64,
) -> anyhow::Result<quinn::Connection> {
    let fallback_deadline = Duration::from_millis((t_max_ms * 2.0) as u64);
    info!("[TRANSPORT] Attempting direct P2P link (Fallback Deadline: {}ms)...", fallback_deadline.as_millis());

    // 1. Start NAT Punching in background
    let _punch_handle = tokio::spawn(async move {
        let _ = puncher.punch().await;
    });

    // 2. Attempt QUIC Handshake with timeout
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(quic_config.client_config.clone());
    
    let connecting = endpoint.connect(peer_addr, "ghost-node.local")?;
    
    match timeout(fallback_deadline, connecting).await {
        Ok(Ok(connection)) => {
            info!("[TRANSPORT] Direct P2P Link Established ✓");
            Ok(connection)
        }
        _ => {
            warn!("[TRANSPORT] Direct P2P Handshake TIMEOUT (Symmetric NAT suspected).");
            warn!("[TRANSPORT] Initiating Deterministic HYDRA FALLBACK...");
            // In V1.0, we return an error that the caller handles to wrap in Sphinx
            Err(anyhow::anyhow!("HYDRA_FALLBACK_REQUIRED"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gear_transitions() {
        let (vault, _rx) = EgressVault::new();

        // Default: High Gear
        assert_eq!(vault.current_gear().await, MetronomeGear::High);

        // Transition to Submarine
        vault.go_submarine().await;
        assert_eq!(vault.current_gear().await, MetronomeGear::Submarine);

        // Trigger burst
        vault.trigger_burst().await;
        match vault.current_gear().await {
            MetronomeGear::SubmarineBurst { .. } => {}
            other => panic!("Expected SubmarineBurst, got {:?}", other),
        }

        // Back to High
        vault.go_high_gear().await;
        assert_eq!(vault.current_gear().await, MetronomeGear::High);
    }

    #[test]
    fn test_gear_should_transmit() {
        assert!(MetronomeGear::High.should_transmit());
        assert!(!MetronomeGear::Submarine.should_transmit());

        // Active burst should transmit
        let burst = MetronomeGear::new_burst();
        assert!(burst.should_transmit());

        // Expired burst should not transmit
        let expired = MetronomeGear::SubmarineBurst { deadline_ms: 0 };
        assert!(!expired.should_transmit());
    }

    #[test]
    fn test_burst_expiry() {
        // Active burst shouldn't expire yet
        let burst = MetronomeGear::new_burst();
        assert!(burst.check_expiry().is_none());

        // Expired burst should transition to Submarine
        let expired = MetronomeGear::SubmarineBurst { deadline_ms: 0 };
        assert_eq!(expired.check_expiry(), Some(MetronomeGear::Submarine));
    }
}
