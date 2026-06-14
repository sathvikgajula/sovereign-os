/// Read the CPU timestamp counter (TSC).
#[inline(always)]
pub fn read_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Hint to the CPU that the current core is spinning.
#[inline(always)]
pub fn cpu_pause() {
    unsafe { core::arch::x86_64::_mm_pause() };
}
