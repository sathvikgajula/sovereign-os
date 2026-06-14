//! PL011 UART @ 0x0900_0000 on QEMU `virt` — optional bare-metal debug output.

#[cfg(target_arch = "aarch64")]
const UART0_BASE: usize = 0x0900_0000;

#[cfg(target_arch = "aarch64")]
const UART_DR: usize = UART0_BASE;

#[cfg(target_arch = "aarch64")]
const UART_FR: usize = UART0_BASE + 0x18;

#[cfg(target_arch = "aarch64")]
const UART_CR: usize = UART0_BASE + 0x30;

/// Enable PL011 TX/RX (QEMU rejects writes to DR when UARTEN is clear).
#[cfg(target_arch = "aarch64")]
pub fn init() {
    unsafe {
        core::ptr::write_volatile(UART_CR as *mut u32, 0x301);
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub fn init() {}

#[inline(always)]
pub fn putc(byte: u8) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        while core::ptr::read_volatile(UART_FR as *const u32) & (1 << 5) != 0 {}
        core::ptr::write_volatile(UART_DR as *mut u32, byte as u32);
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = byte;
}

#[inline(always)]
pub fn write_str(s: &str) {
    for &b in s.as_bytes() {
        putc(b);
    }
}

/// Decimal print for `u16` — zero heap (PL011 metrics).
#[inline(always)]
pub fn write_u16(mut n: u16) {
    if n == 0 {
        putc(b'0');
        return;
    }
    let mut buf = [0u8; 5];
    let mut i = 0usize;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        putc(buf[i]);
    }
}

/// One-shot metronome egress trace (PL011).
#[inline(always)]
pub fn log_tx_notify_slot31() {
    write_str("TX Notify Slot 31\n");
}
