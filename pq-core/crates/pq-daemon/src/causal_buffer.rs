use std::collections::BTreeMap;
use tracing::{info, warn};

/// Maximum number of out-of-order packets buffered to prevent RAM overflow
/// during extended 5G blackouts that exceed the Monotonic Horizon window.
const DEFAULT_MAX_BUFFER_SIZE: usize = 10_000;

pub struct CausalBuffer {
    /// The latest committed vector clock tick
    pub committed_tick: u64,
    /// Out-of-order packet buffer
    buffer: BTreeMap<u64, Vec<u8>>,
    /// Monotonic Horizon threshold (Max allowed future tick)
    horizon_threshold: u64,
    /// Maximum buffer size to prevent RAM overflow during 5G blackouts
    max_buffer_size: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PacketPriority {
    High,
    Low,
}

impl CausalBuffer {
    pub fn new() -> Self {
        Self {
            committed_tick: 0,
            buffer: BTreeMap::new(),
            horizon_threshold: 50,
            max_buffer_size: DEFAULT_MAX_BUFFER_SIZE,
        }
    }

    /// Create a CausalBuffer with a custom maximum buffer size.
    pub fn with_max_buffer(max_buffer_size: usize) -> Self {
        Self {
            committed_tick: 0,
            buffer: BTreeMap::new(),
            horizon_threshold: 50,
            max_buffer_size,
        }
    }

    /// Process an incoming packet with a vector clock tick.
    /// Incorporates Free-Rider Throttle logic dropping low priority packets
    /// when the buffer exceeds 90% capacity.
    pub fn process_packet(&mut self, tick: u64, payload: Vec<u8>, bandwidth_ratio: f64) -> Vec<Vec<u8>> {
        let priority = if bandwidth_ratio < 0.5 {
            PacketPriority::Low
        } else {
            PacketPriority::High
        };

        let current_capacity = self.buffer.len() as f64 / self.max_buffer_size as f64;
        if priority == PacketPriority::Low && current_capacity > 0.90 {
            warn!("[THROTTLE] Free-Rider detected (ratio: {:.2}). Dropping packets to preserve Sanctuary stability.", bandwidth_ratio);
            return Vec::new();
        }

        // 1. Monotonic Horizon Check (Future Flooding DoS Protection)
        if tick > self.committed_tick + self.horizon_threshold {
            warn!("[CAUSAL] FUTURE_FLOODING detected (Tick: {}, Committed: {}). Dropping packet.", tick, self.committed_tick);
            return Vec::new();
        }

        // 2. Reject already committed ticks
        if tick <= self.committed_tick {
            warn!("[CAUSAL] LATE_PACKET or REPLAY detected (Tick: {}). Dropping.", tick);
            return Vec::new();
        }

        // 3. Panic Safety: Evict oldest buffered entries if at capacity
        //    This prevents RAM overflow if a 5G blackout lasts longer than
        //    the configured Monotonic Horizon window.
        while self.buffer.len() >= self.max_buffer_size {
            if let Some((&oldest_tick, _)) = self.buffer.iter().next() {
                warn!(
                    "[CAUSAL] BUFFER_OVERFLOW: Evicting oldest tick {} (buffer={}/{}).",
                    oldest_tick, self.buffer.len(), self.max_buffer_size
                );
                self.buffer.remove(&oldest_tick);
                // Advance committed_tick past evicted entries to maintain consistency
                if oldest_tick == self.committed_tick + 1 {
                    self.committed_tick = oldest_tick;
                }
            } else {
                break;
            }
        }

        // 4. Buffer out-of-order packet
        self.buffer.insert(tick, payload);

        // 5. Extract consecutive sequence starting from committed_tick + 1
        let mut committed_packets = Vec::new();
        while let Some(next_payload) = self.buffer.remove(&(self.committed_tick + 1)) {
            self.committed_tick += 1;
            committed_packets.push(next_payload);
        }

        if !committed_packets.is_empty() {
            info!("[CAUSAL] Committed {} packets. New Horizon: {}.", committed_packets.len(), self.committed_tick);
        }

        committed_packets
    }

    /// Returns the current number of buffered (uncommitted) packets.
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_order() {
        let mut buffer = CausalBuffer::new();
        
        let out = buffer.process_packet(1, vec![10], 1.0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], vec![10]);
        assert_eq!(buffer.committed_tick, 1);

        let out2 = buffer.process_packet(2, vec![20], 1.0);
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0], vec![20]);
        assert_eq!(buffer.committed_tick, 2);
    }

    #[test]
    fn test_out_of_order() {
        let mut buffer = CausalBuffer::new();
        
        // Receive tick 3 before 1 and 2
        let out = buffer.process_packet(3, vec![30], 1.0);
        assert_eq!(out.len(), 0); // Buffered
        assert_eq!(buffer.committed_tick, 0);

        // Receive tick 2
        let out2 = buffer.process_packet(2, vec![20], 1.0);
        assert_eq!(out2.len(), 0); // Buffered
        assert_eq!(buffer.committed_tick, 0);

        // Receive tick 1 -> Unlocks 1, 2, 3
        let out3 = buffer.process_packet(1, vec![10], 1.0);
        assert_eq!(out3.len(), 3);
        assert_eq!(out3[0], vec![10]);
        assert_eq!(out3[1], vec![20]);
        assert_eq!(out3[2], vec![30]);
        assert_eq!(buffer.committed_tick, 3);
    }

    #[test]
    fn test_future_flooding() {
        let mut buffer = CausalBuffer::new();
        // Exceeds horizon threshold of 50
        let out = buffer.process_packet(100, vec![99], 1.0);
        assert_eq!(out.len(), 0);
        assert_eq!(buffer.buffer.len(), 0); // Dropped
    }
}
