//! Allocation-free bare-metal metronome loop.

use crate::{PendingWrite, FRAME_LEN, TickOutcome};

/// Frame egress sink — implemented by VirtIO-net and user-space bridges.
pub trait Egress {
    type Error;
    fn transmit(&self, frame: &[u8; FRAME_LEN]) -> Result<(), Self::Error>;
}

/// Monotonic timer for pacing without `std::time`.
pub trait MetronomeTimer {
    fn monotonic_ns(&self) -> u64;
    fn sleep_until(&self, deadline_ns: u64);
}

const TICK_NS: u64 = 200_000_000; // 200 ms — matches Mach RT period

/// Build a heartbeat frame tagging the metronome epoch.
#[inline(always)]
pub fn heartbeat_frame(epoch: u64) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[..8].copy_from_slice(&epoch.to_le_bytes());
    frame[8..16].copy_from_slice(b"SOVOS\0\0");
    frame[16] = 0xA5; // magic cover-traffic marker
    frame
}

#[inline(always)]
fn tick<E: Egress>(egress: &E, pending: &mut PendingWrite, epoch: u64) -> TickOutcome {
    if pending.is_active() {
        return drain_pending(egress, pending);
    }

    let frame = heartbeat_frame(epoch);
    pending.activate(&frame);
    drain_pending(egress, pending)
}

#[inline(always)]
fn drain_pending<E: Egress>(egress: &E, pending: &mut PendingWrite) -> TickOutcome {
    if pending.remaining_len() == FRAME_LEN {
        let frame = pending.remaining();
        let mut full = [0u8; FRAME_LEN];
        full.copy_from_slice(&frame[..FRAME_LEN]);
        match egress.transmit(&full) {
            Ok(()) => pending.clear(),
            Err(_) => return TickOutcome::Ok,
        }
    }
    TickOutcome::Ok
}

/// Bare-metal metronome — zero heap; spins forever transmitting heartbeat frames.
pub fn run_loop<E: Egress, T: MetronomeTimer>(egress: &E, timer: &T) -> ! {
    let mut pending = PendingWrite::new();
    let mut epoch: u64 = 0;

    loop {
        let _ = tick(egress, &mut pending, epoch);
        epoch = epoch.wrapping_add(1);

        let deadline = timer.monotonic_ns().wrapping_add(TICK_NS);
        timer.sleep_until(deadline);
    }
}
