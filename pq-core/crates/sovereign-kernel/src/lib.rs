//! Bare-metal microkernel: VirtIO egress + allocation-free metronome loop.

#![no_std]

pub mod boot;
pub mod driver;
pub mod entry;
pub mod timer;
pub mod uart;
pub mod virtio;

pub use driver::{DriverError, NetTx, Timer};
pub use sovereign_frame::{run_loop, Egress, FRAME_LEN, MetronomeTimer, PendingWrite, TickOutcome};
pub use timer::TscTimer;
pub use virtio::{VirtioEgress, VirtioNet};
