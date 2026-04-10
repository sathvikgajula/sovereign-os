use anyhow::{Context, Result};
use arti_client::TorClient;
use std::net::SocketAddr;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::{SocksCmd, SocksReply};
use tracing::{error, info};

/// A localized SOCKS5 proxy that bridges TCP traffic through a TorClient.
pub struct TorSocksProxy {
    listener: TcpListener,
    tor_client: TorClient<PreferredRuntime>,
}

impl TorSocksProxy {
    /// Create a new proxy bound to the given address.
    pub async fn new(
        addr: SocketAddr,
        tor_client: TorClient<PreferredRuntime>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr).await
            .with_context(|| format!("Failed to bind SOCKS5 proxy to {}", addr))?;
        
        info!("SOCKS5 Proxy Bridge listening on {}", addr);
        Ok(Self { listener, tor_client })
    }

    /// Start the proxy accept loop.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    let tor_client = self.tor_client.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks_connection(stream, tor_client).await {
                            error!("SOCKS Proxy error for {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("SOCKS Proxy accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_socks_connection(
    mut client_stream: TcpStream,
    tor_client: TorClient<PreferredRuntime>,
) -> Result<()> {
    use tor_socksproto::{SocksProxyHandshake, Buffer, NextStep, Handshake as _};
    
    // 1. Handle SOCKS5 Handshake (v0.28)
    let mut handshake = SocksProxyHandshake::new();
    let mut buffer = Buffer::new();
    
    let request = loop {
        match handshake.step(&mut buffer).map_err(|e| anyhow::anyhow!("SOCKS handshake error: {}", e))? {
            NextStep::Send(data) => {
                client_stream.write_all(&data).await?;
            }
            NextStep::Recv(mut recv_step) => {
                let n = client_stream.read(recv_step.buf()).await?;
                if n == 0 { return Err(anyhow::anyhow!("Connection closed by peer during handshake")); }
                recv_step.note_received(n);
            }
            NextStep::Finished(finished) => {
                let (output, _remaining) = finished.into_output_and_vec();
                break output;
            }
        }
    };

    if request.command() != SocksCmd::CONNECT {
        return Err(anyhow::anyhow!("Unsupported SOCKS command: {:?}", request.command()));
    }

    let target_addr = format!("{}:{}", request.addr(), request.port());
    info!("Proxying connection to {}", target_addr);

    // 2. Connect via Tor
    match tor_client.connect(&target_addr).await {
        Ok(mut tor_stream) => {
            // Success response
            let response = request.reply(tor_socksproto::SocksStatus::SUCCEEDED, None)
                .map_err(|e| anyhow::anyhow!("Failed to encode SOCKS success response: {}", e))?;
            client_stream.write_all(&response).await?;

            // 3. Relay traffic
            copy_bidirectional(&mut client_stream, &mut tor_stream).await?;
        }
        Err(e) => {
            error!("Tor connect failed to {}: {}", target_addr, e);
            let response = request.reply(tor_socksproto::SocksStatus::GENERAL_FAILURE, None)
                .map_err(|e| anyhow::anyhow!("Failed to encode SOCKS failure response: {}", e))?;
            client_stream.write_all(&response).await?;
        }
    }

    Ok(())
}
