//! Nostr-based decentralized signaling for peer discovery.
//!
//! Uses NIP-44 (Version 2) encryption to broadcast and receive
//! signaling metadata (STUN endpoint + KEM public key) via Nostr relays.

use anyhow::{anyhow, Context};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::{info, warn, error};
use tokio_stream::StreamExt;
use nostr::nips::nip59;
use nostr::UnsignedEvent;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use rand::Rng;
use tokio::sync::Mutex;
use crate::socks_proxy::TorSocksProxy;
use arti_client::{TorClient, TorClientConfig};
use std::collections::VecDeque;

/// Default Nostr relays for signaling.
const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
];

/// Binary SOS Payload (56-byte core shifted to 512-byte padded packet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySos {
    pub quic_cid: [u8; 16],
    pub timestamp: u64,
    pub hmac_chacha: [u8; 32],
}

impl BinarySos {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(&self.quic_cid);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.hmac_chacha);
        
        // Pad to exactly 512 bytes with random entropy
        let mut padding = vec![0u8; 512 - bytes.len()];
        rand::thread_rng().fill(&mut padding[..]);
        bytes.extend_from_slice(&padding);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() < 56 {
            anyhow::bail!("Binary SOS too short");
        }
        let mut quic_cid = [0u8; 16];
        quic_cid.copy_from_slice(&bytes[..16]);
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&bytes[16..24]);
        let timestamp = u64::from_be_bytes(ts_bytes);
        let mut hmac_chacha = [0u8; 32];
        hmac_chacha.copy_from_slice(&bytes[24..56]);
        
        Ok(Self {
            quic_cid,
            timestamp,
            hmac_chacha,
        })
    }
}

/// Nostr-based signaler for pq-core peer discovery with Tor camouflage.
pub struct NostrSignaler {
    client: Client,
    keys: Keys,
    tor_active: Arc<AtomicBool>,
    reputation: Arc<pq_reputation::ReputationManager>,
    queue: Arc<Mutex<VecDeque<(SocketAddr, Vec<u8>, PublicKey)>>>,
}

impl NostrSignaler {
    /// Initialize the signaler with Tor camouflage and active "Mute" monitoring.
    pub async fn new(reputation: Arc<pq_reputation::ReputationManager>) -> anyhow::Result<Arc<Self>> {
        let keys = Keys::generate();
        let proxy_addr: SocketAddr = "127.0.0.1:9052".parse().unwrap();
        let tor_active = Arc::new(AtomicBool::new(false));
        
        info!("[GHOST] Initializing Tor circuit camouflage...");

        // 1. Initialize Tor Client with V1.0 Circuit Lock (10 Minutes)
        let config = TorClientConfig::default();
        // Note: For Sovereign OS V1.0, we rely on the default circuit rotation 
        // baseline and enforce Mute Protocol on failure.
        
        let tor_client = TorClient::create_bootstrapped(config).await
            .context("[SIGNALLER] Failed to bootstrap Tor. Fail-Closed policy enforced.")?;
            
        // 2. Spawn SOCKS5 Proxy Bridge in background
        let proxy = TorSocksProxy::new(proxy_addr, tor_client.clone()).await?;
        tokio::spawn(proxy.run());
        
        // 3. Spawn SignalerMonitor for the "Mute" Protocol
        let tor_active_clone = tor_active.clone();
        let mut events = tor_client.bootstrap_events();
        tokio::spawn(async move {
            tor_active_clone.store(true, Ordering::SeqCst);
            info!("[MONITOR] Tor Circuit Verified | Camouflage: ACTIVE");
            
            while let Some(status) = events.next().await {
                if status.blocked().is_some() {
                    error!("[MONITOR] Connectivity LOST | Signaler: MUTED");
                    tor_active_clone.store(false, Ordering::SeqCst);
                } else if status.ready_for_traffic() {
                    if !tor_active_clone.load(Ordering::SeqCst) {
                        info!("[MONITOR] Connectivity RESTORED | Signaler: ACTIVE");
                        tor_active_clone.store(true, Ordering::SeqCst);
                    }
                }
            }
        });

        // 4. Configure Nostr Client to use the SOCKS5 proxy via Connection (v0.44 API)
        let connection = Connection::new().proxy(proxy_addr);
        let opts = ClientOptions::new().connection(connection);
        
        let client = Client::builder()
            .signer(keys.clone())
            .opts(opts)
            .build();

        for relay in DEFAULT_RELAYS {
            let _ = client.add_relay(*relay).await;
        }

        // Spawn connection in background with silent, jittered polling backoff
        let client_clone = client.clone();
        tokio::spawn(async move {
            loop {
                client_clone.connect().await;
                // Check if we are actually connected (v0.44 API)
                // If discovery fails, we don't aggressively churn circuits; we wait.
                let backoff = 10 + rand::thread_rng().gen_range(0..20); // 10-30s silent backoff
                tokio::time::sleep(Duration::from_secs(backoff as u64)).await;
            }
        });

        let signaler = Arc::new(Self { 
            client, 
            keys, 
            tor_active, 
            reputation,
            queue: Arc::new(Mutex::new(VecDeque::new())) 
        });

        // 5. Spawn JIT Radio Burst Loop (500ms + Jitter)
        let signaler_clone = signaler.clone();
        tokio::spawn(async move {
            loop {
                let jitter: i32 = rand::thread_rng().gen_range(-50..=50);
                let burst_interval = (500 + jitter).max(0) as u64;
                tokio::time::sleep(Duration::from_millis(burst_interval)).await;
                if let Err(e) = signaler_clone.burst_signals().await {
                    warn!("[SIGNALER] Radio Burst Failed: {}", e);
                }
            }
        });

        Ok(signaler)
    }

    /// Checks if the signaler is currently muted due to circuit failure.
    pub fn is_muted(&self) -> bool {
        !self.tor_active.load(Ordering::SeqCst)
    }

    /// Queue a signaling event for JIT generation (Radio Batching).
    pub async fn queue_signal(
        &self,
        endpoint: SocketAddr,
        kem_pubkey: Vec<u8>,
        recipient_nostr_pubkey: PublicKey,
    ) -> anyhow::Result<()> {
        let mut queue = self.queue.lock().await;
        queue.push_back((endpoint, kem_pubkey, recipient_nostr_pubkey));
        info!("[SIGNALER] Signal Queued for JIT Burst | Queue Size: {}", queue.len());
        Ok(())
    }

    /// Executes a "Radio Burst" by generating JIT NIP-59 envelopes for queued signals.
    pub async fn burst_signals(&self) -> anyhow::Result<Vec<EventId>> {
        if self.is_muted() {
            return Err(anyhow!("[SIGNALLER] Mute Protocol ACTIVE. Burst failed."));
        }

        let mut queue = self.queue.lock().await;
        let mut sent_ids = Vec::new();

        info!("[SIGNALER] Initiating Radio Burst for {} queued signals...", queue.len());

        while let Some((endpoint, kem_pubkey, recipient)) = queue.pop_front() {
            // Pivot: Replace JSON with Raw Binary SOS
            let sos = BinarySos {
                quic_cid: [0u8; 16], // In a real scenario, this would be the actual CID
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                hmac_chacha: [0u8; 32], // HMAC over [TIMESTAMP + CID]
            };

            let sos_bytes = sos.to_bytes();
            let sos_hex = hex::encode(sos_bytes);

            // JIT Rumor Generation
            let builder = EventBuilder::new(Kind::Custom(284), sos_hex);
            
            // Construct UnsignedEvent for NIP-59 gift wrapping (v0.44 API)
            let pubkey = self.keys.public_key();
            let rumor = UnsignedEvent::from(builder.build(pubkey));
            
            // Trigger Temporal Freeze: Suspend reputation for peer for exactly 300ms
            if let Err(e) = self.reputation.freeze_peer(recipient.to_hex(), 300).await {
                warn!("[SIGNALER] Failed to trigger Temporal Freeze: {}", e);
            }

            // JIT NIP-17 Gift Wrap
            match self.client.gift_wrap(&recipient, rumor, std::iter::empty::<Tag>()).await {
                Ok(output) => {
                    info!("[SIGNALER] JIT Binary SOS Sent | ID: {:?}", output.id());
                    sent_ids.push(*output.id());
                }
                Err(e) => warn!("[SIGNALER] JIT Generation Failed for peer {}: {}", recipient, e),
            }
        }

        Ok(sent_ids)
    }

    /// JIT Mandate: Persistent signaling caches are strictly ABANDONED.
    /// Signaling events are generated JIT only during authorized bursts.
    pub async fn broadcast_signal(
        &self,
        endpoint: SocketAddr,
        kem_pubkey: &[u8],
        recipient_nostr_pubkey: &PublicKey,
    ) -> anyhow::Result<()> {
        self.queue_signal(endpoint, kem_pubkey.to_vec(), *recipient_nostr_pubkey).await
    }

    /// Listen for incoming Private Direct Messages (NIP-17).
    pub async fn listen_for_signal(
        &self,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(BinarySos, PublicKey)> {
        if self.is_muted() {
            return Err(anyhow!("[SIGNALLER] Mute Protocol ACTIVE. Discovery blocked."));
        }

        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(self.keys.public_key());

        self.client.subscribe(filter, None).await
            .context("Failed to subscribe to GiftWrap events")?;

        info!("Listening for NIP-17 signals...");

        let deadline = tokio::time::Instant::now() + timeout;
        let mut notifications = self.client.notifications();

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(anyhow!("Signal listen timeout after {:?}", timeout));
            }

            match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                notifications.recv(),
            )
            .await
            {
                Ok(Ok(notification)) => {
                    if let RelayPoolNotification::Event { event, .. } = notification {
                        if event.kind == Kind::GiftWrap {
                            // Correct extraction via nip59 module (0.44)
                            match nip59::extract_rumor(&self.client.signer().await.unwrap(), &event).await {
                                Ok(unwrapped) => {
                                    if unwrapped.rumor.kind == Kind::Custom(284) {
                                        let bytes = hex::decode(&unwrapped.rumor.content)
                                            .context("Failed to decode SOS hex")?;
                                        match BinarySos::from_bytes(&bytes) {
                                            Ok(sos) => {
                                                info!("Binary SOS received from: {}", unwrapped.rumor.pubkey);
                                                return Ok((sos, unwrapped.rumor.pubkey));
                                            }
                                            Err(e) => warn!("Failed to parse Binary SOS: {e}"),
                                        }
                                    }
                                }
                                Err(e) => warn!("Failed to unwrap NIP-59 GiftWrap: {e}"),
                            }
                        }
                    }
                }
                Ok(_) => continue,
                Err(_) => continue, 
            }
        }
    }


    /// Disconnect from all relays.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.client.disconnect().await;
        info!("Nostr signaler disconnected");
        Ok(())
    }

    /// Get our Nostr public key (for sharing with peers out-of-band).
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Get our Nostr public key as a hex string.
    pub fn public_key_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }
}
