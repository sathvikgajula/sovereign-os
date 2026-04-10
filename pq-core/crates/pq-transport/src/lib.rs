//! # pq-transport
//!
//! Post-quantum secure transport layer for pq-core.
//! Provides PQ-QUIC configuration, STUN discovery, NAT punching,
//! and post-handshake DID authentication.

pub mod auth;
pub mod config;
pub mod nat;
pub mod stun;
pub mod accounting;

pub use auth::{receive_and_verify_identity, send_identity_proof};
pub use config::PqQuicConfig;
pub use nat::NatPuncher;
pub use stun::discover_public_addr_async;

use tokio::time::{timeout, Duration};
use tracing::{info, warn};

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
