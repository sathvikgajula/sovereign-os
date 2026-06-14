/// Read the virtual counter register (CNTVCT_EL0).
#[inline(always)]
pub fn read_timestamp() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {0}, cntvct_el0", out(reg) val, options(nomem, nostack));
    }
    val
}

/// Counter frequency in Hz (CNTFRQ_EL0) — used to convert ticks → nanoseconds.
#[inline(always)]
pub fn read_timestamp_freq_hz() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {0}, cntfrq_el0", out(reg) val, options(nomem, nostack));
    }
    val.max(1)
}

/// AArch64 has no `_mm_pause`; use the portable spin hint.
#[inline(always)]
pub fn cpu_pause() {
    core::hint::spin_loop();
}
