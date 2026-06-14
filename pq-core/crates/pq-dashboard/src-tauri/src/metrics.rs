use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use serde::{Serialize, Deserialize};

/// Thread-safe shared telemetry handle.
#[derive(Clone)]
pub struct SharedTelemetry(pub Arc<AtomicTelemetry>);

impl std::ops::Deref for SharedTelemetry {
    type Target = AtomicTelemetry;
    
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


/// Telemetry metrics sample produced by the high-priority metronome context.
#[derive(Debug, Clone, Copy)]
pub struct MetronomeSample {
    pub epoch: u64,
    pub clock_skew_us: i64,
    pub egress_queue_depth: u64,
    pub real_frames_sent: u64,
    pub decoy_frames_sent: u64,
}

/// A transactionally consistent, sequence-validated snapshot of telemetry metrics,
/// suitable for serialization and transmission to the frontend UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub seq: u64,
    pub epoch: u64,
    pub clock_skew_us: i64,
    pub egress_queue_depth: u64,
    pub real_frames_sent: u64,
    pub decoy_frames_sent: u64,
}

/// A sequence-locked atomic telemetry storage page.
/// Enables lock-free writes from the real-time metronome context (single writer)
/// and lock-free reads from the UI background thread without any Mutex lock contention.
#[repr(C, align(64))]
pub struct AtomicTelemetry {
    pub seq: AtomicU64,
    pub epoch: AtomicU64,
    pub clock_skew_us: AtomicI64,
    pub egress_queue_depth: AtomicU64,
    pub real_frames_sent: AtomicU64,
    pub decoy_frames_sent: AtomicU64,
}

impl Default for AtomicTelemetry {
    fn default() -> Self {
        Self {
            seq: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
            clock_skew_us: AtomicI64::new(0),
            egress_queue_depth: AtomicU64::new(0),
            real_frames_sent: AtomicU64::new(0),
            decoy_frames_sent: AtomicU64::new(0),
        }
    }
}

impl AtomicTelemetry {
    /// Creates a new, zero-initialized telemetry storage page.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes a new metrics sample from the high-priority metronome context.
    /// This uses a sequence-lock algorithm to guarantee that readers can detect
    /// if a read was concurrent with this write.
    ///
    /// Since the metronome context is the single writer, we use Ordering::Release
    /// to sequence the modifications and Ordering::Relaxed for the intermediate fields.
    #[inline(always)]
    pub fn publish_from_metronome(&self, sample: MetronomeSample) {
        // 1. Increment seq to odd (indicates write in progress).
        // Release ordering ensures that this increment is not reordered after the field writes.
        self.seq.fetch_add(1, Ordering::Release);

        // 2. Write relaxed fields.
        self.epoch.store(sample.epoch, Ordering::Relaxed);
        self.clock_skew_us.store(sample.clock_skew_us, Ordering::Relaxed);
        self.egress_queue_depth.store(sample.egress_queue_depth, Ordering::Relaxed);
        self.real_frames_sent.store(sample.real_frames_sent, Ordering::Relaxed);
        self.decoy_frames_sent.store(sample.decoy_frames_sent, Ordering::Relaxed);

        // 3. Increment seq to even (indicates write complete).
        // Release ordering ensures all field writes are visible before the sequence becomes even.
        self.seq.fetch_add(1, Ordering::Release);
    }

    /// Obtains a transactionally consistent snapshot of the telemetry metrics.
    /// Spins internally using `std::hint::spin_loop()` if a write collision is detected,
    /// ensuring zero locking overhead on the writer.
    #[inline]
    pub fn snapshot(&self) -> TelemetrySnapshot {
        loop {
            // 1. Read seq counter first.
            let seq1 = self.seq.load(Ordering::Acquire);

            // If seq is odd, a write is currently in progress. Spin and retry.
            if seq1 % 2 != 0 {
                std::hint::spin_loop();
                continue;
            }

            // 2. Copy all fields using Relaxed ordering.
            let epoch = self.epoch.load(Ordering::Relaxed);
            let clock_skew_us = self.clock_skew_us.load(Ordering::Relaxed);
            let egress_queue_depth = self.egress_queue_depth.load(Ordering::Relaxed);
            let real_frames_sent = self.real_frames_sent.load(Ordering::Relaxed);
            let decoy_frames_sent = self.decoy_frames_sent.load(Ordering::Relaxed);

            // 3. Re-read seq counter.
            let seq2 = self.seq.load(Ordering::Acquire);

            // If the sequence counter did not change, the data is consistent.
            if seq1 == seq2 {
                return TelemetrySnapshot {
                    seq: seq1,
                    epoch,
                    clock_skew_us,
                    egress_queue_depth,
                    real_frames_sent,
                    decoy_frames_sent,
                };
            }

            // Collision detected (writer modified fields during read). Spin and retry.
            std::hint::spin_loop();
        }
    }
}
