/// Fallback timestamp when no arch-specific counter is available.
#[inline(always)]
pub fn read_timestamp() -> u64 {
    0
}

#[inline(always)]
pub fn cpu_pause() {
    core::hint::spin_loop();
}
