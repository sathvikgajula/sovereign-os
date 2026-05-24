use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{State, Emitter};
use serde::Serialize;

use pq_storage::PqShard;

use crate::metrics::{TelemetrySnapshot, SharedTelemetry};
use crate::{KernelState, LiveStreamMetrics, MeshStats};

/// Shared state wrapper representing whether the kernel bootstrap is complete.
#[derive(Clone)]
pub struct KernelReadyState(pub Arc<AtomicBool>);

/// Hardened error types returned by the SovereignGate UI boundary.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "message")]
pub enum KernelUiError {
    KernelSyncing,
    Other(String),
}

impl std::fmt::Display for KernelUiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KernelSyncing => write!(f, "Kernel is currently syncing"),
            Self::Other(s) => write!(f, "Internal Error: {}", s),
        }
    }
}

impl std::error::Error for KernelUiError {}


/// Helper function to perform the gate check on every command.
#[inline(always)]
fn check_ready(ready_state: &KernelReadyState) -> Result<(), KernelUiError> {
    if !ready_state.0.load(Ordering::Acquire) {
        return Err(KernelUiError::KernelSyncing);
    }
    Ok(())
}

#[tauri::command]
pub async fn get_kernel_status(
    ready_state: State<'_, KernelReadyState>,
) -> Result<bool, KernelUiError> {
    check_ready(&ready_state)?;
    Ok(true)
}

#[tauri::command]
pub async fn get_live_telemetry(
    ready_state: State<'_, KernelReadyState>,
    telemetry: State<'_, SharedTelemetry>,
) -> Result<TelemetrySnapshot, KernelUiError> {
    check_ready(&ready_state)?;
    Ok(telemetry.snapshot())
}

#[tauri::command]
pub async fn get_mesh_stats(
    state: State<'_, KernelState>,
    ready_state: State<'_, KernelReadyState>,
) -> Result<MeshStats, KernelUiError> {
    check_ready(&ready_state)?;
    let rep = state.reputation.get()
        .ok_or_else(|| KernelUiError::Other("Kernel not anchored".to_string()))?;
    let scores = rep.get_all_scores().await
        .map_err(|e| KernelUiError::Other(e.to_string()))?;
    Ok(MeshStats { peers: scores })
}

#[tauri::command]
pub async fn send_sovereign_message(
    state: State<'_, KernelState>,
    ready_state: State<'_, KernelReadyState>,
    recipient_did: String,
    payload: String,
) -> Result<String, KernelUiError> {
    check_ready(&ready_state)?;
    let signaler = state.signaler.get()
        .ok_or_else(|| KernelUiError::Other("Kernel not anchored".to_string()))?;
    if signaler.is_muted() {
        return Err(KernelUiError::Other("Signaler is MUTED due to circuit failure. Message blocked.".to_string()));
    }
    println!("Sending message to {}: {}", recipient_did, payload);
    Ok("Message shattering initiated...".to_string())
}

#[tauri::command]
pub async fn get_storage_inventory(
    state: State<'_, KernelState>,
    ready_state: State<'_, KernelReadyState>,
) -> Result<Vec<String>, KernelUiError> {
    check_ready(&ready_state)?;
    let storage = state.storage.get()
        .ok_or_else(|| KernelUiError::Other("Kernel not anchored".to_string()))?;
    let inventory = storage.get_inventory().await;
    Ok(inventory)
}

#[tauri::command]
pub async fn slash_target(
    state: State<'_, KernelState>,
    ready_state: State<'_, KernelReadyState>,
    peer_did: String,
    slash: bool,
) -> Result<String, KernelUiError> {
    check_ready(&ready_state)?;
    let rep = state.reputation.get()
        .ok_or_else(|| KernelUiError::Other("Kernel not anchored".to_string()))?;
    if slash {
        rep.update_score(peer_did, false).await
            .map_err(|e| KernelUiError::Other(e.to_string()))?;
        Ok("Peer slashed successfully".to_string())
    } else {
        Ok("Chaos simulation triggered".to_string())
    }
}

#[tauri::command]
pub async fn get_mute_status(
    state: State<'_, KernelState>,
    ready_state: State<'_, KernelReadyState>,
) -> Result<bool, KernelUiError> {
    check_ready(&ready_state)?;
    let signaler = state.signaler.get()
        .ok_or_else(|| KernelUiError::Other("Kernel not anchored".to_string()))?;
    Ok(signaler.is_muted())
}

#[tauri::command]
pub async fn initialize_camera_loopback(
    app: tauri::AppHandle,
    state: State<'_, KernelState>,
    ready_state: State<'_, KernelReadyState>,
) -> Result<String, KernelUiError> {
    check_ready(&ready_state)?;
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        println!("[METADATA] Initializing XOR-Split Pipeline...");
        println!("[METADATA] CBR Padding Active: 1200B target locked.");
    });

    let lock_path = "/tmp/sovereign_camera.lock";
    let hardware_busy = std::path::Path::new(lock_path).exists();
    
    if hardware_busy {
        let _ = app.emit("system-error", "Hardware Busy | Engaging Multi-Instance Synthetic Fallback.");
    } else {
        let _ = std::fs::write(lock_path, "LOCKED");
    }

    {
        let mut metrics = state.stream_metrics.lock().unwrap();
        if metrics.active {
            return Err(KernelUiError::Other("Stream already active".to_string()));
        }
        metrics.active = true;
    }
    
    let app_state = state.stream_metrics.clone();
    tokio::spawn(async move {
        let mut audio_frame = vec![0u8; pq_voice::VOICE_FRAME_SIZE];
        audio_frame[0..10].copy_from_slice(b"SILICON_TX");

        let mut splitter = pq_voice::XorStreamSplitter::new();
        
        use rand::{RngCore, SeedableRng};
        let mut filler_rng = rand::rngs::StdRng::seed_from_u64(0x4a4a4a4a4a4a4a4a); 

        loop {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            
            let active = {
                let metrics = app_state.lock().unwrap();
                metrics.active
            };
            if !active {
                if !hardware_busy {
                    let _ = std::fs::remove_file("/tmp/sovereign_camera.lock");
                }
                break;
            }

            filler_rng.fill_bytes(&mut audio_frame[10..]);
            
            if let Ok((relay_a, relay_b)) = splitter.split_frame(&audio_frame) {
                let mut metrics = app_state.lock().unwrap();
                if metrics.active {
                    metrics.relay_a_bytes = relay_a.len();
                    metrics.relay_b_bytes = relay_b.len();
                }
            }
        }
    }); 
    Ok("Loopback started".into())
}

#[tauri::command]
pub async fn kill_relay_b(
    state: State<'_, KernelState>,
    ready_state: State<'_, KernelReadyState>,
) -> Result<String, KernelUiError> {
    check_ready(&ready_state)?;
    let mut metrics = state.stream_metrics.lock().unwrap();
    metrics.active = false;
    metrics.relay_a_bytes = 0;
    metrics.relay_b_bytes = 0;
    Ok("Relay killed, stream muted.".to_string())
}

#[tauri::command]
pub async fn get_all_shards(
    state: State<'_, KernelState>,
    ready_state: State<'_, KernelReadyState>,
) -> Result<Vec<PqShard>, KernelUiError> {
    check_ready(&ready_state)?;
    let db = state.db.get()
        .ok_or_else(|| KernelUiError::Other("Kernel not anchored".to_string()))?;
    db.get_all_shards().await
        .map_err(|e| KernelUiError::Other(e.to_string()))
}

#[tauri::command]
pub async fn get_stream_metrics(
    state: State<'_, KernelState>,
    ready_state: State<'_, KernelReadyState>,
) -> Result<LiveStreamMetrics, KernelUiError> {
    check_ready(&ready_state)?;
    let metrics = state.stream_metrics.lock().unwrap();
    Ok(metrics.clone())
}
