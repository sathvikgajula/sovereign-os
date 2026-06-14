//! TSC-calibrated monotonic timer for bare-metal metronome pacing.

use sovereign_hal::arch::{cpu_pause, read_timestamp};

#[cfg(target_arch = "aarch64")]
use sovereign_hal::arch::read_timestamp_freq_hz;
use sovereign_frame::MetronomeTimer;

/// Raw timestamp-counter timer (identity-mapped pseudo-nanoseconds).
pub struct TscTimer {
    base: u64,
    /// Scale ticks → ns (default 1:1 until calibrated against HPET).
    ns_per_tick: u64,
}

impl TscTimer {
    pub fn calibrate() -> Self {
        let base = read_timestamp();
        #[cfg(target_arch = "aarch64")]
        let ns_per_tick = 1_000_000_000 / read_timestamp_freq_hz();
        #[cfg(target_arch = "x86_64")]
        let ns_per_tick = 1;
        Self {
            base,
            ns_per_tick,
        }
    }
}

impl MetronomeTimer for TscTimer {
    fn monotonic_ns(&self) -> u64 {
        read_timestamp()
            .saturating_sub(self.base)
            .saturating_mul(self.ns_per_tick)
    }

    fn sleep_until(&self, deadline_ns: u64) {
        while self.monotonic_ns() < deadline_ns {
            cpu_pause();
        }
    }
}

impl crate::driver::Timer for TscTimer {
    fn monotonic_ns(&self) -> u64 {
        MetronomeTimer::monotonic_ns(self)
    }

    fn sleep_until(&self, deadline_ns: u64) {
        MetronomeTimer::sleep_until(self, deadline_ns)
    }
}
