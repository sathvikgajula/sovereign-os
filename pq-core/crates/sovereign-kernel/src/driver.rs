//! Abstract driver boundaries for heap-free 512-byte frame egress.

use sovereign_frame::FRAME_LEN;

/// Driver-level error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverError {
    DeviceNotReady,
    TransmitBusy,
    HardwareFault,
}

/// Transmit path for virtio-net or physical NIC — zero heap on `send_frame`.
pub trait NetTx {
    /// Queue one 512-byte metronome frame for egress.
    fn send_frame(&self, frame: &[u8; FRAME_LEN]) -> Result<(), DriverError>;
}

/// Monotonic timer for metronome pacing without `std::time`.
pub trait Timer {
    /// Nanoseconds since an arbitrary boot epoch.
    fn monotonic_ns(&self) -> u64;

    /// Spin or sleep until `deadline_ns` (platform-specific).
    fn sleep_until(&self, deadline_ns: u64);
}
