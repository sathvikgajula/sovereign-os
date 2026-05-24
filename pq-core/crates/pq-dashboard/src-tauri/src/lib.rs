pub mod metrics;
pub mod commands;

use pq_reputation::{ReputationManager, ReputationScore};
use pq_identity::PqIdentity;
use pq_storage::{EphemeralStore, PqDatabase};
use pq_daemon::signaler::NostrSignaler;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{Manager, Emitter};
use serde::Serialize;
use tracing::{info, error};
use tokio::net::TcpStream;
use tokio::time::{interval, Duration};
use tokio::sync::OnceCell;
use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;
use thread_priority::*;
use spin_sleep::LoopHelper;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::hint::black_box;

#[derive(Serialize)]
pub struct MeshStats {
    pub peers: Vec<ReputationScore>,
}

#[derive(Serialize, Clone, Default)]
pub struct LiveStreamMetrics {
    pub active: bool,
    pub relay_a_bytes: usize,
    pub relay_b_bytes: usize,
    pub ingress_mbps: f64,
    pub egress_mbps: f64,
}

/// The "Gold Master" Managed State Struct.
/// Uses OnceCell for atomic, asynchronous component anchoring.
pub struct KernelState {
    pub identity: OnceCell<Arc<PqIdentity>>,
    pub db: OnceCell<PqDatabase>,
    pub reputation: OnceCell<Arc<ReputationManager>>,
    pub storage: OnceCell<Arc<EphemeralStore>>,
    pub signaler: OnceCell<Arc<NostrSignaler>>,
    pub tor_client: OnceCell<Arc<TorClient<PreferredRuntime>>>,
    pub physical_bridge: OnceCell<Arc<pq_daemon::bridge::PhysicalBridge>>,
    pub stream_metrics: Arc<std::sync::Mutex<LiveStreamMetrics>>,
}

impl Default for KernelState {
    fn default() -> Self {
        Self {
            identity: OnceCell::new(),
            db: OnceCell::new(),
            reputation: OnceCell::new(),
            storage: OnceCell::new(),
            signaler: OnceCell::new(),
            tor_client: OnceCell::new(),
            physical_bridge: OnceCell::new(),
            stream_metrics: Arc::new(std::sync::Mutex::new(Default::default())),
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    
    let port = std::env::var("PROCESS_PORT")
        .or_else(|_| std::env::var("PORT"))
        .unwrap_or_else(|_| "4321".to_string());
    
    if !port.chars().all(|c| c.is_alphanumeric()) {
        panic!("CRITICAL: Invalid PORT environment variable: '{}'", port);
    }

    info!("[SYSTEM] INITIALIZING GOLD MASTER KERNEL | PORT: {}", port);

    // Instantiate Shared Gated States & Telemetry page
    let kernel_ready = Arc::new(AtomicBool::new(false));
    let ready_state = commands::KernelReadyState(kernel_ready.clone());

    let telemetry = Arc::new(metrics::AtomicTelemetry::new());
    let shared_telemetry = metrics::SharedTelemetry(telemetry.clone());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(KernelState::default())
        .manage(ready_state)
        .manage(shared_telemetry)
        .setup(move |app| {
             let app_handle = app.handle().clone();
             let port_clone = port.clone();

             let bootstrap_ready = kernel_ready.clone();

             // 1. ASYNCHRONOUS BOOTSTRAP (Kernel Anchoring)
             tauri::async_runtime::spawn(async move {
                  let base_dir = std::env::var("SOVEREIGN_DATA_DIR")
                      .unwrap_or_else(|_| {
                          let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                          format!("{}/.sovereign/nodes/node_{}", home, port_clone)
                      });
                  let base_path = std::path::PathBuf::from(&base_dir);
                  std::fs::create_dir_all(&base_path).expect("Failed to create node directory");

                  let state = app_handle.state::<KernelState>();

                  // Identity
                  let identity = PqIdentity::init(base_path.clone());
                  state.identity.set(Arc::new(identity)).ok();

                  // Database (Non-Blocking WAL Mode)
                  let db = PqDatabase::open(base_path.clone()).await.expect("Failed to open SQLite");
                  state.db.set(db).ok();

                  // Reputation
                  let reputation_path = base_path.join("reputation.json");
                  let reputation = ReputationManager::new(reputation_path).await.expect("Reputation init failed");
                  let reputation = Arc::new(reputation);
                  state.reputation.set(reputation.clone()).ok();

                  // Ephemeral Storage
                  let storage = EphemeralStore::new((*reputation).clone());
                  state.storage.set(Arc::new(storage)).ok();

                  // Nostr Signaler + Tor Client
                  let signaler = NostrSignaler::new(reputation).await.expect("Signaler init failed");
                  state.signaler.set(signaler).ok();

                  // Physical Bridge
                  let bridge = pq_daemon::bridge::PhysicalBridge::new(port_clone.parse().unwrap_or(4321))
                      .expect("Physical Bridge init failed");
                  state.physical_bridge.set(Arc::new(bridge)).ok();

                  info!("[SYSTEM] Kernel Anchored. IPC Bridge Unlocked.");
                  bootstrap_ready.store(true, Ordering::Release);
                  app_handle.emit("kernel_ready", ()).ok();
             });

             // 2. THE JITTER ASSASSIN (Preemptive Metronome)
             // Native thread with priority elevation to ensure microsecond-accurate firing
             let telemetry_metronome = telemetry.clone();
             std::thread::Builder::new()
                 .name("jitter-assassin".into())
                 .spawn_with_priority(ThreadPriority::Max, move |result| {
                     if result.is_ok() {
                         info!("[ASSASSIN] Priority Elevation: MAX | Metronome: ACTIVE");
                     } else {
                         error!("[ASSASSIN] Priority Elevation FAILED. Jitter may exceed 500us.");
                     }

                     #[cfg(target_os = "macos")]
                     {
                         info!("[ASSASSIN] Platform: macOS | Policy: TIME_CONSTRAINT");
                     }

                     // 1. PIN TO CORE 0
                     let core_ids = core_affinity::get_core_ids().unwrap_or_default();
                     if let Some(core) = core_ids.first() {
                         core_affinity::set_for_current(*core);
                         info!("[ULTRA] Jitter Assassin pinned to Core 0");
                     }

                     // 2. ELEVATE TO REAL-TIME PRIORITY
                     if let Err(e) = set_current_thread_priority(ThreadPriority::Max) {
                         error!("[ULTRA] Failed to set RT priority: {:?}", e);
                     } else {
                         info!("[ULTRA] Jitter Assassin elevated to RT Priority");
                     }

                     // 3. ZERO-ALLOCATION PREPARATION
                     let mut jitter_rng = ChaCha12Rng::from_entropy();
                     let mut payload_warm = [0u8; 1024]; // L1/L2 Cache warming buffer
                     
                     let mut loop_helper = LoopHelper::builder()
                         .report_interval_s(0.5)
                         .build_with_target_rate(5.0); // 5.0 Hz = 200ms pulses

                     let mut tick_count: u64 = 0;

                     loop {
                         loop_helper.loop_start();

                         // 4. CACHE WARMING PHASE
                         // Spin for 1ms before the tick to ensure Core 0 is awake and cache is hot
                         let warm_start = std::time::Instant::now();
                         while warm_start.elapsed() < std::time::Duration::from_millis(1) {
                             black_box(&mut payload_warm);
                             std::hint::spin_loop();
                         }

                         // 5. JITTER WASH (Hardware Fingerprint Eradication)
                         // Apply Δ ∈ [-2000μs, +2000μs] to bury crystal drift
                         let delta_us: i64 = jitter_rng.gen_range(-2000..=2000);
                         let interval_us = (200_000i64 + delta_us) as u64;
                         
                         // 6. HOT PATH: UPDATE ATOMIC TELEMETRY PAGE
                         // Absolutely zero heap allocations or event emissions occur inside this real-time metronome context
                         tick_count += 1;
                         let sample = metrics::MetronomeSample {
                             epoch: tick_count,
                             clock_skew_us: delta_us,
                             egress_queue_depth: (tick_count % 4), // Simulation payload
                             real_frames_sent: tick_count,
                             decoy_frames_sent: tick_count * 2,
                         };
                         telemetry_metronome.publish_from_metronome(sample);

                         // Sleep until next jittered interval
                         spin_sleep::sleep(std::time::Duration::from_micros(interval_us));
                     }
                 })
                 .expect("Failed to spawn Jitter Assassin");

             // 3. SOVEREIGN UI TELEMETRY PUMP
             // Low-priority native thread that reads telemetry snapshots and broadcasts them
             let app_handle_pump = app.handle().clone();
             let telemetry_pump = telemetry.clone();
             std::thread::Builder::new()
                 .name("sovereign-ui-telemetry-pump".into())
                 .spawn_with_priority(ThreadPriority::Min, move |result| {
                     if result.is_ok() {
                         info!("[PUMP] sovereign-ui-telemetry-pump priority set to MIN");
                     } else {
                         error!("[PUMP] Failed to configure telemetry pump thread priority");
                     }

                     loop {
                         std::thread::sleep(std::time::Duration::from_millis(250));

                         // Pull a sequence-validated consistent snapshot
                         let snapshot = telemetry_pump.snapshot();

                         // Broadcast snapshot to frontend UI via event emission
                         let _ = app_handle_pump.emit("telemetry_tick", snapshot);
                     }
                 })
                 .expect("Failed to spawn sovereign-ui-telemetry-pump thread");

             // 4. Local Mesh Discovery (Laboratory Heartbeat)
             let app_handle_discovery = app.handle().clone();
             tauri::async_runtime::spawn(async move {
                  let mut ticker = interval(Duration::from_secs(2));
                  loop {
                      ticker.tick().await;
                      for target_port in [4321, 4322] {
                          let addr = format!("127.0.0.1:{}", target_port);
                          if TcpStream::connect(&addr).await.is_ok() {
                              app_handle_discovery.emit("local-peer-up", target_port).ok();
                          }
                      }
                  }
             });

             Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_kernel_status,
            commands::get_live_telemetry,
            commands::get_mesh_stats,
            commands::send_sovereign_message,
            commands::get_storage_inventory,
            commands::slash_target,
            commands::get_mute_status,
            commands::initialize_camera_loopback,
            commands::get_stream_metrics,
            commands::kill_relay_b,
            commands::get_all_shards
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
