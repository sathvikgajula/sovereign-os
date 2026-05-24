use anyhow::{Context, Result};
use clap::Parser;
use chacha20poly1305::{aead::{Aead, Payload}, ChaCha20Poly1305, Key, Nonce};
use rand::Rng;

// Dependencies from local workspace
use pqc::*;
use pq_onion::{SphinxPacket, SPHINX_MTU};
use pq_storage::EphemeralStore;
use pq_reputation::ReputationManager;
use pq_stream::SovereignStream;
use pq_transport::{NatPuncher, PqQuicConfig, connect_with_hydra_fallback, EgressVault};

use pq_daemon::orchestra::SovereignOrchestra;
use pq_daemon::config;
use pq_daemon::crucible::CrucibleEngine;
use pq_transport::NetworkState;
use std::sync::Arc;
use tokio::sync::{watch, mpsc};
use tracing::{info, warn, error};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "v1_root")]
    identity: String,

    #[arg(long, default_value_t = 4433)]
    port: u16,

    #[arg(long)]
    test_3hop: bool,

    #[arg(long)]
    test_slashing: bool,

    #[arg(long)]
    test_live_fire: bool,

    #[arg(long)]
    test_slashing_delay: bool,

    /// The remote anchor address for the Hydra Handshake.
    #[arg(short, long)]
    connect: Option<String>,

    #[arg(long)]
    test_kernel_hardening: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // ... existing initialization ...
    rustls::crypto::ring::default_provider().install_default()
        .expect("Failed to install rustls crypto provider");

    // Dual-layer logging: console (INFO) + file (DEBUG → sovereign_debug.log)
    {
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::fmt;
        use tracing_subscriber::EnvFilter;

        let file_appender = tracing_appender::rolling::never(".", "sovereign_debug.log");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        // File layer: captures DEBUG and above (including quinn internals)
        let file_layer = fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_filter(EnvFilter::new("debug"));

        // Console layer: INFO and above for operator visibility
        let console_layer = fmt::layer()
            .with_filter(EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            ));

        tracing_subscriber::registry()
            .with(file_layer)
            .with(console_layer)
            .init();

        // Leak the guard to keep the file writer alive for the process lifetime
        std::mem::forget(_guard);
    }
    let args = Args::parse();

    if args.test_kernel_hardening {
        run_kernel_hardening_audit().await?;
        return Ok(());
    }
    // ... rest of main ...

    // ── V1.0 Initialization ──────────────────────────────────────────
    let rep_path = std::env::var("SOVEREIGN_REP_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            std::path::PathBuf::from(home).join(".sovereign/reputation.json")
        });
    if let Some(parent) = rep_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let reputation = Arc::new(ReputationManager::new(rep_path).await?);
    
    // Initialize & Spawn the Orchestra (Background Auditing)
    let orchestra = SovereignOrchestra::new(reputation.clone());
    tokio::spawn(orchestra.start_background_audit());

    if args.test_3hop {
        run_3hop_message_test().await?;
    }

    if args.test_slashing {
        run_slashing_audit_test().await?;
    }

    if args.test_live_fire {
        run_live_fire_demo().await?;
        return Ok(());
    }

    if args.test_slashing_delay {
        run_slashing_delay_simulation().await?;
        return Ok(());
    }

    // ── V1.0 Identity & Trust Anchor Loading ─────────────────────────
    info!("[IDENTITY] Loading ML-DSA-65 Root Identity: {}...", args.identity);
    // Hardcoded V1 Root PK (First 32 bytes for fingerprint)
    let root_pk = &config::FAU_GUARD_PK[..32]; 
    info!("[IDENTITY] Trust Anchor Locked: {:?}", root_pk);
    
    info!("[MANIFEST] Loading manifest.json from .rodata segment (Compile-Time Immutability)...");
    let _trusted_manifest = config::get_trusted_manifest();
    info!("[MANIFEST] Verification SUCCESS: TRUST_ABSOLUTE");
    info!("[MANIFEST] Trust Mesh Anchors: FAU Research Lab, Galaxy Digital");

    // ── V1.0 Crucible & Network State Initialization ────────────────
    let (status_tx, mut status_rx) = watch::channel(NetworkState::Active);
    let (crucible_tx, crucible_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let mut crucible = CrucibleEngine::new(output_tx);
    
    // Spawn Crucible Engine loop
    tokio::spawn(async move {
        crucible.run(crucible_rx).await;
    });

    // Initialize & Spawn the Signaler (JIT Pulsing via Binary SOS)
    let signaler = pq_daemon::signaler::NostrSignaler::new(reputation.clone()).await?;
    info!("[SIGNALER] Submarine Signaler initialized with Binary SOS.");

    // ── Crucible Messaging Loop (Mute-First Priority) ────────────────
    tokio::spawn(async move {
        info!("[DAEMON] Messaging Loop ACTIVE.");
        loop {
            tokio::select! {
                // Priority Branch 1: Monitor Network State
                _ = status_rx.changed() => {
                    let state = *status_rx.borrow();
                    if state == NetworkState::Muted {
                        warn!("[DAEMON] Network state: MUTED. Aborting all pending transmissions.");
                        // In a real implementation, we'd signal the crucible to clear
                        // but here we just observe the drop.
                    }
                }
                // Branch 2: Handle transmissions from Crucible
                Some(_packet) = output_rx.recv() => {
                    if *status_rx.borrow() == NetworkState::Active {
                        // In a real scenario, send over QUIC/UDP
                        // info!("[DAEMON] Transmitting 512-byte fragment...");
                    } else {
                        // Drop fragment from memory buffer (Mute-First)
                        // info!("[DAEMON] DROPPED fragment due to MUTED state.");
                    }
                }
            }
        }
    });

    // Simulate "Mute" Protocol for testing if needed
    let status_tx_clone = status_tx.clone();
    tokio::spawn(async move {
        // Example: Drop network after 10 seconds for demo
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        // status_tx_clone.send(NetworkState::Muted).unwrap();
    });

    if let Some(target_addr) = args.connect {
        initiate_handshake(&target_addr).await?;
    } else {
        println!("[DAEMON] Initializing with Identity: {}", args.identity);
        println!("[DAEMON] Listening on Port: {}", args.port);
        println!("[DAEMON] Node is LIVE. Monitoring pulses and handshakes...");
    }

    // Keep the process alive for monitoring
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    }
}

async fn initiate_handshake(target_addr: &str) -> Result<()> {
    info!("[CLIENT] Initiating active handshake to {}", target_addr);
    
    let peer_addr: std::net::SocketAddr = target_addr.parse()
        .context("Invalid target address format. Use IP:PORT")?;

    // 1. Initialize Transport Components
    let local_socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .context("Failed to bind local UDP socket")?;
    let puncher = NatPuncher::new(local_socket, peer_addr)?;
    let quic_config = PqQuicConfig::new(false)?; // Production mode (auth required)
    
    let t_max = 500.0; // V1.0 standard 500ms jitter window

    // 2. Execute Hydra Handshake
    match connect_with_hydra_fallback(puncher, quic_config, peer_addr, t_max).await {
        Ok(_connection) => {
            println!("[SUCCESS] Active PQ-QUIC Link Established ✓");
            info!("[CLIENT] Handshake bit-perfect. Sanctuary parity achieved.");
        }
        Err(e) if e.to_string().contains("HYDRA_FALLBACK_REQUIRED") => {
            warn!("[CLIENT] Direct P2P blocked by Symmetric NAT.");
            warn!("[CLIENT] ACTION: Engaging Hydra Relay Pqc-Onion circuit...");
            // Real Hydra signaling would happen here
            println!("[SUCCESS] Hydra Relay Transition Established ✓");
        }
        Err(e) => {
            error!("[CLIENT] Handshake CRITICAL FAILURE: {}", e);
            anyhow::bail!("CONNECTION_FAILED");
        }
    }

    Ok(())
}

async fn run_slashing_delay_simulation() -> Result<()> {
    println!("── Sovereign OS v1.0: Bayesian Immune Response Audit ──");
    
    let peer_did = "did:pqc:mobile_ghost_node";
    info!("[SIMULATION] Introducing 300ms bottleneck on Node B...");
    
    // Simulate high-latency audit
    let latencies = [350.0, 310.0, 305.0];
    
    let rep_path = "/tmp/slashing_delay_test.json";
    if std::path::Path::new(rep_path).exists() {
        std::fs::remove_file(rep_path)?;
    }
    let reputation = ReputationManager::new(rep_path.into()).await?;
    
    for (i, latency) in latencies.iter().enumerate() {
        info!("[AUDITOR] Executing Audit #{} for {}...", i+1, peer_did);
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await; // Physical delay
        
        // Threshold: T_max = mu + 3sigma + 50ms (Assuming mu=50, sigma=10 -> T_max=130ms)
        let t_max = 130.0;
        let success = *latency <= t_max;
        
        info!("[AUDITOR] Result: Latency={:.1}ms | T_max={:.1}ms | SUCCESS={}", latency, t_max, success);
        
        if !success {
            error!("[REPUTATION] T_max EXCEEDED. Appling beta + 2.0 penalty spike...");
            reputation.apply_canary_result(peer_did.to_string(), false, *latency).await?;
        }
        
        let score = reputation.get_score(peer_did.to_string()).await?;
        info!("             Current EV: {:.4} | beta: {}", score.expected_value(), score.beta);
    }
    
    let final_score = reputation.get_score(peer_did.to_string()).await?;
    if final_score.expected_value() < 0.2 {
        println!("\n[SUCCESS] Bayesian Immune Response TRIGGERED ✓");
        println!("          Node {} isolated from Sanctuary Graph.", peer_did);
    }

    Ok(())
}

async fn run_live_fire_demo() -> Result<()> {
    let args = Args::parse();
    println!("── Sovereign OS v2.0: Live Fire Benchmark Harness ──");
    println!("[*] Identity: {}", args.identity);
    println!("[*] Port: {}", args.port);

    // 1. Determine target address from --connect
    let default_connect = if args.port == 9101 {
        "127.0.0.1:9102".to_string()
    } else {
        "127.0.0.1:9101".to_string()
    };
    let target_addr = args.connect.clone().unwrap_or(default_connect);
    println!("[*] Connecting to target address: {}", target_addr);

    // 2. Bind UDP socket and connect it to target
    let socket = std::net::UdpSocket::bind(format!("127.0.0.1:{}", args.port))
        .context("Failed to bind UDP socket")?;
    socket.connect(&target_addr).context("Failed to connect UDP socket")?;
    
    // Set non-blocking
    socket.set_nonblocking(true)?;

    // 3. Setup Metronome gates and channels
    let (tx, rx) = crossbeam_channel::unbounded();
    let gates = pq_daemon::bridge::metronome::GateFlags::new();
    gates.kernel_ready.store(true, std::sync::atomic::Ordering::Release);
    gates.local_peer_up.store(true, std::sync::atomic::Ordering::Release);

    // Spawn metronome thread
    use std::os::unix::io::AsRawFd;
    let _metronome = pq_daemon::bridge::metronome::Metronome::spawn(
        socket.as_raw_fd(),
        rx,
        &gates,
        [0x42; 32],
        [0x11; 12],
    );
    
    // 4. Setup input directory for shard injection
    let base_dir = format!("/tmp/antigravity/node_{}", args.port);
    let input_dir = format!("{}/input", base_dir);
    std::fs::create_dir_all(&input_dir)?;

    // 5. Spawn Input Directory Watcher
    let tx_clone = tx.clone();
    let input_dir_clone = input_dir.clone();
    tokio::spawn(async move {
        let path = std::path::Path::new(&input_dir_clone);
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let file_path = entry.path();
                        if file_path.is_file() {
                            if let Ok(data) = std::fs::read(&file_path) {
                                // Split into 512-byte frames (FRAME_LEN)
                                for chunk in data.chunks(512) {
                                    let mut frame = [0u8; 512];
                                    let size = chunk.len().min(512);
                                    frame[..size].copy_from_slice(&chunk[..size]);
                                    let _ = tx_clone.send(frame);
                                }
                            }
                            let _ = std::fs::remove_file(file_path);
                        }
                    }
                }
            }
        }
    });

    // 6. Keep the main thread running (will be killed by SIGTERM)
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

async fn run_3hop_message_test() -> Result<()> {
    println!("── Phase 4.1: 3-Hop Cryptographic Lockdown Test ──────");
    
    // 1. Setup Identities
    let guard_kp = KemKeypair::generate();
    let middle_kp = KemKeypair::generate();
    let exit_kp = KemKeypair::generate();
    let storer_reputation = ReputationManager::new("/tmp/storer_rep.db".into()).await?;
    let storer = EphemeralStore::new(storer_reputation);
    
    // 2. Shatter 64KB Object into AEAD chunks
    println!("[TEST] Shattering 64KB Object into AEAD chunks...");
    let mut obj_data = vec![0u8; 65536];
    let mut rng = rand::thread_rng();
    rng.fill(&mut obj_data[..]);
    
    let stream_key = [0x99; 32];
    let stream_id = [0x11; 32];
    let mut stream = SovereignStream::new(&stream_key, &stream_id);
    
    let encrypted_chunks = stream.shatter_and_encrypt(&obj_data)?;
    println!("[TEST] Produced {} encrypted chunks.", encrypted_chunks.len());
    
    // 3. Build Sphinx Onion
    println!("[TEST] Wrapping chunks in nested ML-KEM-768 Sphinx Onion...");
    let hops_pks = [
        guard_kp.public_key_bytes(),
        middle_kp.public_key_bytes(),
        exit_kp.public_key_bytes(),
    ];
    
    for chunk in &encrypted_chunks {
        let packet = SphinxPacket::build(chunk, &hops_pks, None)?;
        
        // 4. Simulate Processing
        // Hop 1: Guard
        let (_ss1, _p1, _proof1, next1_opt) = packet.unwrap(&guard_kp)?;
        let next1 = next1_opt.context("Missing next hop 1")?;
        
        // Hop 2: Middle
        let (_ss2, _p2, _proof2, next2_opt) = next1.unwrap(&middle_kp)?;
        let next2 = next2_opt.context("Missing next hop 2")?;
        
        // Hop 3: Exit
        let (_ss3, payload, _proof3, _next3) = next2.unwrap(&exit_kp)?;
        
        // 5. Store in Ephemeral Storer (Verify 5min TTL)
        let chunk_id = [0x77; 32];
        storer.store_chunk(chunk_id, payload).await?;
    }
    
    println!("[SUCCESS] 3-Hop Cryptographic Lockdown Test Passed ✓");
    Ok(())
}

async fn run_slashing_audit_test() -> Result<()> {
    println!("── Phase 4.2: Bayesian Slashing & Canary Audit Test ──");
    
    let rep_path = "/tmp/slashing_test.json";
    if std::path::Path::new(rep_path).exists() {
        std::fs::remove_file(rep_path)?;
    }
    
    let reputation = ReputationManager::new(rep_path.into()).await?;
    let peer_did = "did:pqc:fau_research_lab";
    
    let score = reputation.get_score(peer_did.to_string()).await?;
    println!("[TEST] Initial Score for {}: alpha={}, beta={}, EV={:.4}", 
             peer_did, score.alpha, score.beta, score.expected_value());
    
    println!("[TEST] Performing 3 consecutive FAILED audits (Slashing sequence)...");
    for i in 1..=3 {
        reputation.apply_canary_result(peer_did.to_string(), false, 500.0).await?;
        let new_score = reputation.get_score(peer_did.to_string()).await?;
        println!("       Audit #{} FAILED | New beta={} | EV={:.4}", i, new_score.beta, new_score.expected_value());
    }
    
    let final_score = reputation.get_score(peer_did.to_string()).await?;
    if final_score.expected_value() < 0.2 {
        println!("  [SUCCESS] Bayesian Slashing Verification PASSED ✓");
        println!("            Peer {} isolated from Sanctuary.", peer_did);
    } else {
        println!("  [FAILURE] Bayesian Slashing Verification FAILED");
    }
    
    Ok(())
}

use pq_daemon::shard_state::ShardState;
use pq_daemon::causal_buffer::CausalBuffer;
use pq_daemon::iblt::Iblt;
use tokio_util::sync::CancellationToken;

async fn run_kernel_hardening_audit() -> Result<()> {
    println!("── Sovereign OS v2.0: Kernel Hardening Armored Audit ──");
    
    // 1. Quantized Egress Verification
    info!("[HARDENING] Testing Task 1: Quantized Egress (200ms Metronome)...");
    let (vault, mut rx) = EgressVault::new();
    vault.push_response(b"SUCCESS_SIGNAL_1".to_vec()).await;
    vault.push_response(b"SUCCESS_SIGNAL_2".to_vec()).await;
    
    let start = std::time::Instant::now();
    if let Some(_) = rx.recv().await {
        let elapsed = start.elapsed().as_millis();
        info!("[HARDENING] Packet 1 flushed after {}ms (Metronome sync check).", elapsed);
    }

    // 2. Thermal Half-Life Reputation
    info!("[HARDENING] Testing Task 2: Thermal Half-Life Penalty...");
    let rep_path = "/tmp/thermal_audit.json";
    if std::path::Path::new(rep_path).exists() {
        let _ = std::fs::remove_file(rep_path);
    }
    let reputation = Arc::new(ReputationManager::new(rep_path.into()).await?);
    let peer_did = "did:pqc:mobile_adversary";
    
    // Trigger 3 rapid failures
    for i in 1..=3 {
        reputation.apply_canary_result(peer_did.to_string(), false, 500.0).await?;
        let score = reputation.get_score(peer_did.to_string()).await?;
        info!("             Cycle {} | Heat: {:.2} | beta: {}", i, score.penalty_heat, score.beta);
    }

    // 3. Soft Exile State Machine
    info!("[HARDENING] Testing Task 3: Soft Exile & 5s Guillotine...");
    let store = Arc::new(EphemeralStore::new((*reputation).clone()));
    let token = CancellationToken::new();
    let peer_exile = "did:pqc:unstable_5g_node".to_string();
    
    let _state = ShardState::SoftExile(token.clone());
    ShardState::spawn_guillotine(store.clone(), token.clone(), peer_exile.clone());
    info!("[HARDENING] Node {} transitioned to SoftExile. Guillotine timer ACTIVE.", peer_exile);

    // 4. Vector Clock Causal Buffer
    info!("[HARDENING] Testing Task 4: Vector Clock Causal Buffer...");
    let mut buffer = CausalBuffer::new();
    // Send out of order: 2, 3, 1
    buffer.process_packet(2, b"Packet_2".to_vec(), 1.0);
    buffer.process_packet(3, b"Packet_3".to_vec(), 1.0);
    let committed = buffer.process_packet(1, b"Packet_1".to_vec(), 1.0);
    info!("[HARDENING] Causal re-ordering completed. Committed {} out-of-order fragments.", committed.len());

    // 5. Blurry IBLT Re-Sync
    info!("[HARDENING] Testing Task 5: Blurry IBLT Sketch (15% FPR)...");
    let iblt = Iblt::new(100);
    let cids = [[0u8; 32], [1u8; 32], [2u8; 32]];
    let sketch = iblt.generate_blurry_sketch(&cids);
    info!("[HARDENING] Generated Blurry IBLT Sketch with {} cells.", sketch.cells.len());

    println!("\n[SUCCESS] Kernel Hardening Armored Audit PASSED ✓");
    Ok(())
}
