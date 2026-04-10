use pq_reputation::{ReputationManager, ReputationScore};
use pq_storage::{EphemeralStore};
use std::sync::Arc;
use tauri::State;
use serde::Serialize;
use anyhow::{Result};

#[derive(Serialize)]
pub struct MeshStats {
    pub peers: Vec<ReputationScore>,
}

pub struct AppState {
    pub reputation: Arc<ReputationManager>,
    pub storage: Arc<EphemeralStore>,
}

#[tauri::command]
async fn get_mesh_stats(state: State<'_, AppState>) -> Result<MeshStats, String> {
    let scores = state.reputation.get_all_scores().await
        .map_err(|e| e.to_string())?;
    Ok(MeshStats { peers: scores })
}

#[tauri::command]
async fn send_sovereign_message(
    state: State<'_, AppState>,
    recipient_did: String,
    payload: String,
) -> Result<String, String> {
    if state.signaler.is_muted() {
        return Err("Signaler is MUTED due to circuit failure. Message blocked.".to_string());
    }
    // Phase 5: Implement 64KB shattering + Sphinx 3-hop routing
    println!("Sending message to {}: {}", recipient_did, payload);
    Ok("Message shattering initiated...".to_string())
}

#[tauri::command]
async fn get_storage_inventory(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let inventory = state.storage.get_inventory().await;
    Ok(inventory)
}

#[tauri::command]
async fn trigger_chaos_simulation(
    state: State<'_, AppState>,
    peer_did: String,
    slash: bool,
) -> Result<String, String> {
    if slash {
        // Manually decrease reputation (Bayesian Beta increment)
        state.reputation.update_score(peer_did, false).await
            .map_err(|e| e.to_string())?;
        Ok("Peer slashed successfully".to_string())
    } else {
        Ok("Chaos simulation triggered".to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize the shared state
    // In a real scenario, we would use proper paths.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (reputation, storage, signaler) = rt.block_on(async {
        let reputation = ReputationManager::new("/Users/max/.gemini/antigravity/reputation.json".into()).await.unwrap();
        let storage = EphemeralStore::new(reputation.clone());
        let signaler = NostrSignaler::new().await.unwrap();
        (Arc::new(reputation), Arc::new(storage), Arc::new(signaler))
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            reputation,
            storage,
            signaler,
        })
        .invoke_handler(tauri::generate_handler![
            get_mesh_stats,
            send_sovereign_message,
            get_storage_inventory,
            trigger_chaos_simulation,
            get_mute_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
