//! Bare-metal microkernel: VirtIO egress + allocation-free metronome loop.

#![no_std]

pub mod boot;
pub mod dma;
pub mod driver;
pub mod entry;
pub mod mmu;
#[cfg(target_os = "none")]
pub mod net;
pub mod timer;
pub mod uart;
pub mod virtio;

pub use driver::{DriverError, NetRx, NetTx, RX_FRAME_CAP, Timer};
pub use sovereign_frame::{run_loop, Egress, FRAME_LEN, MetronomeTimer, PendingWrite, TickOutcome};
pub use timer::TscTimer;
pub use virtio::{VirtioEgress, VirtioNet};
