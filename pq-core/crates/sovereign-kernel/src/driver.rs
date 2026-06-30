//! Abstract driver boundaries for heap-free 512-byte frame egress and ingress.

use sovereign_frame::FRAME_LEN;

/// Maximum virtio-net RX buffer size (must match `virtio::queue::RX_BUF_LEN`).
pub const RX_FRAME_CAP: usize = 1526;

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

/// Receive path for virtio-net or physical NIC — zero heap on `poll_rx`.
///
/// # Invariants
/// - Frames are borrowed slices into static virtqueue buffers; valid only for the
///   duration of the `handler` closure.
/// - Alignment: virtio-net buffers are 512-byte aligned slots in a `#[repr(C, align(16))]` queue.
/// - Deterministic: `poll_rx` is non-blocking and bounded by virtqueue depth.
/// - Caller recycles buffers implicitly when `handler` returns (driver returns descriptor to avail).
pub trait NetRx {
    /// Poll completed RX descriptors and deliver each frame to `handler`.
    ///
    /// `handler` receives `(frame_bytes, device_reported_len)`. Bytes include the
    /// 12-byte virtio-net header when the device supplies it.
    ///
    /// Returns the number of frames delivered (0 if the used ring is empty).
    fn poll_rx<F>(&self, handler: F) -> Result<usize, DriverError>
    where
        F: FnMut(&[u8], usize);
}

/// Monotonic timer for metronome pacing without `std::time`.
pub trait Timer {
    /// Nanoseconds since an arbitrary boot epoch.
    fn monotonic_ns(&self) -> u64;

    /// Spin or sleep until `deadline_ns` (platform-specific).
    fn sleep_until(&self, deadline_ns: u64);
}
