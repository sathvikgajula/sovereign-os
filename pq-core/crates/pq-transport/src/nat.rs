//! NAT hole-punching via simultaneous UDP probes.
//!
//! Sends a burst of UDP packets to the peer's STUN-mapped address
//! for exactly 2 seconds to punch through NAT firewalls.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{self, Duration, Instant};
use tracing::{debug, info};

/// NAT hole-punching service.
///
/// Fires UDP "probe" packets at a peer's STUN-mapped address to create
/// bidirectional NAT mappings, enabling direct P2P communication.
pub struct NatPuncher {
    /// The local UDP socket (should be the same one used for STUN).
    socket: UdpSocket,
    /// The peer's STUN-mapped public address.
    peer_addr: SocketAddr,
}

/// Magic bytes identifying a pq-core NAT punch probe.
const PUNCH_MAGIC: &[u8] = b"PQ-PUNCH-v1";

impl NatPuncher {
    /// Create a new NAT puncher.
    ///
    /// The `local_socket` should be the same one used for STUN discovery
    /// to preserve the NAT mapping.
    pub fn new(local_socket: std::net::UdpSocket, peer_addr: SocketAddr) -> Result<Self> {
        // Convert std socket to tokio socket
        local_socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(local_socket)
            .context("Failed to convert UDP socket to async")?;
        Ok(Self { socket, peer_addr })
    }

    /// Execute simultaneous UDP hole punching for exactly 2 seconds.
    ///
    /// Sends probe packets at 100ms intervals and listens for incoming probes.
    /// Returns true if a probe was received from the peer (punch succeeded).
    pub async fn punch(&self) -> Result<bool> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut probe_count: u32 = 0;
        let mut received_probe = false;
        let mut recv_buf = [0u8; 64];

        info!(
            "NAT punch: sending probes to {} for 2 seconds (v1.0 25ms calibration)",
            self.peer_addr
        );

        while Instant::now() < deadline {
            // Send a probe
            match self.socket.send_to(PUNCH_MAGIC, self.peer_addr).await {
                Ok(n) => {
                    probe_count += 1;
                    debug!("Probe #{probe_count} sent ({n} bytes) to {}", self.peer_addr);
                }
                Err(e) => {
                    debug!("Probe send failed: {e}");
                }
            }

            // Try to receive a probe (v1.0 calibration: 25ms interval)
            match time::timeout(Duration::from_millis(25), self.socket.recv_from(&mut recv_buf))
                .await
            {
                Ok(Ok((n, from))) => {
                    if n >= PUNCH_MAGIC.len() && &recv_buf[..PUNCH_MAGIC.len()] == PUNCH_MAGIC {
                        info!("NAT punch: received probe from {from}");
                        received_probe = true;
                    } else {
                        debug!("Received non-probe packet from {from} ({n} bytes)");
                    }
                }
                Ok(Err(e)) => {
                    debug!("Recv error during punch: {e}");
                }
                Err(_) => {
                    // Timeout — expected, continue punching
                }
            }
        }

        info!(
            "NAT punch complete: sent {probe_count} probes, received_probe={received_probe}"
        );
        Ok(received_probe)
    }

    /// Consume the puncher and return the underlying tokio UDP socket.
    ///
    /// The socket is now "punched" and ready for QUIC binding.
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }

    /// Get the local address of the puncher's socket.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().context("Failed to get local address")
    }
}
