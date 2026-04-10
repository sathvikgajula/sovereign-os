//! STUN-based public address discovery.
//!
//! Queries public STUN servers to determine the node's externally-visible
//! IP address and UDP port for NAT traversal.

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};
use tracing::{info, warn};

/// STUN servers to query simultaneously.
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.twilio.com:3478",
];

/// Create a new UDP socket with SO_REUSEADDR and SO_REUSEPORT.
pub fn create_reusable_socket() -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    
    socket.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())?;
    
    let udp_socket: UdpSocket = socket.into();
    udp_socket.set_nonblocking(false)?;
    // Set a reasonable timeout for STUN queries
    udp_socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    udp_socket.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    Ok(udp_socket)
}

/// Discover public address asynchronously via concurrent STUN requests.
pub async fn discover_public_addr_async() -> Result<(SocketAddr, std::net::UdpSocket)> {
    let local_socket = create_reusable_socket().context("Failed to bind reusable UDP socket")?;
    let local_addr = local_socket.local_addr()?;
    info!("Concurrent STUN probe from local address: {local_addr}");

    let mut join_set = tokio::task::JoinSet::new();

    for &server_str in STUN_SERVERS {
        let socket_clone = local_socket.try_clone().context("Failed to clone socket")?;
        
        // We use spawn_blocking because stunclient is synchronous
        join_set.spawn_blocking(move || -> Result<SocketAddr> {
            try_stun_query(&socket_clone, server_str)
        });
    }

    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(Ok(public_addr)) => {
                info!("STUN discovery succeeded: {public_addr}");
                return Ok((public_addr, local_socket));
            }
            Ok(Err(e)) => {
                warn!("STUN query failed: {e}");
            }
            Err(e) => {
                warn!("STUN task paniced: {e}");
            }
        }
    }

    warn!("STUN discovery failed, falling back to local address (dev mode)");
    let mut local_addr = local_socket.local_addr()?;
    if local_addr.ip().is_unspecified() {
        local_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    }
    Ok((local_addr, local_socket))
}

/// Attempt a single STUN binding request.
fn try_stun_query(socket: &UdpSocket, server_str: &str) -> Result<SocketAddr> {
    let server_addr: SocketAddr = server_str
        .parse()
        .or_else(|_| {
            use std::net::ToSocketAddrs;
            server_str
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow::anyhow!("DNS resolution failed for {server_str}"))
        })
        .context("Failed to parse STUN server address")?;

    let client = stunclient::StunClient::new(server_addr);
    let external_addr = client
        .query_external_address(socket)
        .context("STUN binding request failed")?;

    Ok(external_addr)
}
