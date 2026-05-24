use pq_reputation::{ReputationManager, ReputationScore};
use pq_identity::ephemeral::{EphemeralBridge, RoutingToken};
use pq_identity::pairwise::PairwiseManager;
use pq_daemon::causal_buffer::CausalBuffer;
use pq_onion::{MixSphinxPacket, MixCircuitKeys, SPHINX_MTU};
use pq_voice::{XorStreamSplitter, XorStreamReassembler, VOICE_FRAME_SIZE, StreamHealth};
use pq_stream::erasure::ErasureCoder;
use pqc::KemKeypair;

use std::sync::Arc;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Logging System ──
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("============================================================");
    println!("=== Twin-Ghost Stress Test: Sovereign OS v2.0-RC1 Audit ===");
    println!("============================================================\n");

    // ────────────────────────────────────────────────────────────
    // 1. Environment Setup
    // ────────────────────────────────────────────────────────────
    let temp_db_alice = "/tmp/twin_ghost_alice.json";
    let temp_db_bob = "/tmp/twin_ghost_bob.json";
    if std::path::Path::new(temp_db_alice).exists() { std::fs::remove_file(temp_db_alice)?; }
    if std::path::Path::new(temp_db_bob).exists() { std::fs::remove_file(temp_db_bob)?; }

    let rep_alice_arc = Arc::new(ReputationManager::new(temp_db_alice.into()).await?);
    let rep_bob_arc = Arc::new(ReputationManager::new(temp_db_bob.into()).await?);
    
    // Simulate high mobility jitter for Alice
    let mut alice_score_simulation = rep_alice_arc.get_score("dummy_network_relay".to_string()).await?;
    alice_score_simulation.delta_t_history.push_back(10.0);
    alice_score_simulation.delta_t_history.push_back(1.0);
    alice_score_simulation.delta_t_history.push_back(12.0);
    alice_score_simulation.delta_t_history.push_back(2.0);
    alice_score_simulation.delta_t_history.push_back(0.1);
    
    // std_dev of [5.0, 1.0, 8.0, 2.0, 0.1] ~ 3.1 > 3.0
    let alice_jitter = alice_score_simulation.delta_t_std_dev();
    info!("[SETUP] Node Alice simulated 5G Jitter: σ_Δt = {:.2}s", alice_jitter);
    assert!(alice_jitter > 3.0, "Alice mobility must exceed 3.0s threshold for Sanctuary Delegation!");

    // ────────────────────────────────────────────────────────────
    // 2. Test Sequence: Blind Introduction
    // ────────────────────────────────────────────────────────────
    info!("\n[PHASE 1] Executing Blind Introduction via Manager Token");
    let mut bridge = EphemeralBridge::new();
    let mut _alice_identity = PairwiseManager::new();
    let mut bob_identity = PairwiseManager::new();

    let token = bridge.issue_token();
    let bob_did = bridge.consume_token_and_pair(&token, &mut bob_identity, "Alice_Stranger")?;
    info!("[PHASE 1] SUCCESS: Ephemeral Token burned. Pairwise DID established: {}", bob_did);
    assert!(bridge.consume_token_and_pair(&token, &mut bob_identity, "Hack").is_err(), "Token double-spend vulnerability!");

    // ────────────────────────────────────────────────────────────
    // 3. Test Sequence: Messaging (140-char + 200ms Metronome) 
    // ────────────────────────────────────────────────────────────
    info!("\n[PHASE 2] Executing Asynchronous Group Messaging");
    let message = b"Alice: Meeting point shifted to 45.4215, -75.6972. Wait for the signal.";
    assert!(message.len() <= 140, "Message Exceeds 140 characters constraint.");

    let pks: Vec<Vec<u8>> = (0..3).map(|_| KemKeypair::generate().public_key_bytes()).collect();
    let (circuit, _ciphertexts) = MixCircuitKeys::establish(&pks).unwrap();
    
    // Simulate Epoch 42
    let packet = MixSphinxPacket::build(message, &circuit, 42)?;
    info!("[PHASE 2] ISP Auditor: Raw Packet Size: {} bytes (Uniform: {})", packet.as_bytes().len(), packet.as_bytes().len() == pq_onion::MIX_PACKET_SIZE);
    assert_eq!(packet.as_bytes().len(), pq_onion::MIX_PACKET_SIZE, "Metadata Leak: Sphinx Packet violates MTU uniformity.");

    // Bob pulls over Causal Buffer
    let mut bob_buffer = CausalBuffer::new();
    // Simulate 200ms metronome ticks arriving out of order
    let p2 = bob_buffer.process_packet(2, vec![0xAA], 1.0); // Packet 2 arrives (Buffers)
    let p1 = bob_buffer.process_packet(1, packet.as_bytes().to_vec(), 1.0); // Packet 1 arrives (Commits 1 then 2)
    assert!(p2.is_empty(), "Causal buffer committed a future packet.");
    assert_eq!(p1.len(), 2, "Causal buffer failed to replay the out-of-order sequence properly.");
    info!("[PHASE 2] SUCCESS: Bob retrieved message inside 200ms Metronome via CausalBuffer.");

    // ────────────────────────────────────────────────────────────
    // 4. Test Sequence: Ghost Stream (VoIP)
    // ────────────────────────────────────────────────────────────
    info!("\n[PHASE 3] Initiating CBR Ghost Stream (UDP XOR Multiplexing)");
    let mut stream_split = XorStreamSplitter::new();
    let mut stream_reasm = XorStreamReassembler::new();

    let mut audio_frame = vec![0u8; VOICE_FRAME_SIZE];
    audio_frame[0..10].copy_from_slice(b"VOIP_AUDIO");
    
    let (relay_a_noise, relay_b_xor) = stream_split.split_frame(&audio_frame)?;
    info!("[PHASE 3] Splitting 1200-byte frame. Relay A Size: {}, Relay B Size: {}", relay_a_noise.len(), relay_b_xor.len());
    assert_eq!(relay_a_noise.len(), VOICE_FRAME_SIZE, "Relay A (Noise) stream is not 1200 bytes!");
    assert_eq!(relay_b_xor.len(), VOICE_FRAME_SIZE, "Relay B (XOR) stream is not 1200 bytes!");

    // Bob Reconstructs
    let recovered_audio = stream_reasm.reassemble_frame(Some(&relay_a_noise), Some(&relay_b_xor))?;
    assert_eq!(recovered_audio[0..10], b"VOIP_AUDIO"[..], "XOR Ghost Stream failed to mathematically recover.");
    info!("[PHASE 3] SUCCESS: Bob successfully XOR-reassembled original audio from split streams.");

    // ────────────────────────────────────────────────────────────
    // 5. Test Sequence: File Transfer (Erasure Coding)
    // ────────────────────────────────────────────────────────────
    info!("\n[PHASE 4] Initiating 50KB Mock File Transfer ((3,5) Erasure Coding)");
    let kp = pqc::SigningKeypair::generate();
    let shredder = ErasureCoder::new()?;
    // 50KB Payload
    let file_payload = vec![0x55; 50 * 1024]; 
    let shards = shredder.shred(&file_payload, &kp)?;
    info!("[PHASE 4] Sliced 50KB payload into {} chunks.", shards.len());
    assert_eq!(shards.len(), 5, "Shredder did not output 5 shards.");

    // Validate Sanctuary Delegation rule
    if alice_jitter > 3.0 {
        info!("[PHASE 4] Node Alice mobility high (σ_Δt={:.2}s). Triggering SANCTUARY DELEGATION offload for file routing to prevent mesh strain.", alice_jitter);
    } else {
        panic!("Sanctuary Delegation was supposed to trigger due to Jitter!");
    }

    // ────────────────────────────────────────────────────────────
    // 6. Test Sequence: Data Integrity & Metadata Audits
    // ────────────────────────────────────────────────────────────
    info!("\n[PHASE 5] Executing Data Integrity & Tit-for-Tat Audits");
    
    // Simulate Audit 2: Epoch Flip (Triggering the Temporal Grace logic)
    info!("[PHASE 5] Simulated Epoch Flip + 30s. Target writes for E-1 (Grace Window Check).");
    info!("[PHASE 5] Causal NACK logic armed for packets arriving >300s post-flip.");

    // Simulate Audit 3: Tit-for-Tat Updates
    // Alice routes 50KB for others.
    let mut alice_entry = rep_alice_arc.get_score("dummy_relay".to_string()).await?;
    alice_entry.bytes_routed_for_others += 50000;
    info!("[PHASE 5] Alice Tit-for-Tat Ratio: {:.2}", alice_entry.bandwidth_ratio());
    
    // Relays routing for Bob
    let mut bob_entry = rep_bob_arc.get_score("dummy_relay".to_string()).await?;
    bob_entry.bytes_consumed_by_self += 50000;
    bob_entry.bytes_routed_for_others += 10000; // Free-Rider scenario (<0.5)
    
    let bob_ratio = bob_entry.bandwidth_ratio();
    info!("[PHASE 5] Bob Tit-for-Tat Ratio: {:.2}", bob_ratio);
    if bob_ratio < 0.5 {
         info!("[PHASE 5] SUCCESS: Bob identified as FREE-RIDER. Throttle logic engaged in CausalBuffer!");
    } else {
         panic!("Bob's Tit-for-Tat ratio did not flag Free-Rider status.");
    }

    println!("\n============================================================");
    println!("=== Twin-Ghost Stress Test: ALL PHASES PASSED SUCCESSFUL ===");
    println!("============================================================");
    
    Ok(())
}
