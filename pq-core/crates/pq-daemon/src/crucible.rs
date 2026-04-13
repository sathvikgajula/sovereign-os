use std::collections::VecDeque;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use rand::Rng;
use tracing::info;

pub const CRUCIBLE_TICK_MS: u64 = 33;
pub const CRUCIBLE_PACKET_SIZE: usize = 512;

pub struct CrucibleEngine {
    buffer: VecDeque<Vec<u8>>,
    tx_out: mpsc::UnboundedSender<Vec<u8>>,
}

impl CrucibleEngine {
    pub fn new(tx_out: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            buffer: VecDeque::new(),
            tx_out,
        }
    }

    /// Queue a 512-byte fragment for transmission.
    pub fn queue_fragment(&mut self, data: Vec<u8>) {
        if data.len() > CRUCIBLE_PACKET_SIZE {
            // In a real scenario, we'd fragment here, but for this mission
            // we assume the caller provides 512-byte chunks.
            self.buffer.push_back(data[..CRUCIBLE_PACKET_SIZE].to_vec());
        } else {
            self.buffer.push_back(data);
        }
    }

    /// Clear the buffer (Mute-First Logic).
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
        info!("[CRUCIBLE] Transmission buffer cleared (MUTED).");
    }

    /// Start the rhythmic micro-burst loop.
    pub async fn run(mut self, mut rx_in: mpsc::UnboundedReceiver<Vec<u8>>) {
        let mut interval = interval(Duration::from_millis(CRUCIBLE_TICK_MS));
        info!("[CRUCIBLE] Rhythmic Micro-Burst loop active (33ms ticks).");

        loop {
            tokio::select! {
                Some(data) = rx_in.recv() => {
                    self.queue_fragment(data);
                }
                _ = interval.tick() => {
                    let packet = if let Some(fragment) = self.buffer.pop_front() {
                        fragment
                    } else {
                        // Generate 512-byte packet of high-entropy noise
                        let mut noise = vec![0u8; CRUCIBLE_PACKET_SIZE];
                        rand::thread_rng().fill(&mut noise[..]);
                        noise
                    };
                    
                    if let Err(_) = self.tx_out.send(packet) {
                        break;
                    }
                }
            }
        }
    }
}
