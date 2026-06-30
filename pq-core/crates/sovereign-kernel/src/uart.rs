//! Serial debug output — PL011 (aarch64 virt) / COM1 8250 (x86_64 microvm).

#[cfg(target_arch = "aarch64")]
const UART0_BASE: usize = 0x0900_0000;

#[cfg(target_arch = "aarch64")]
const UART_DR: usize = UART0_BASE;

#[cfg(target_arch = "aarch64")]
const UART_FR: usize = UART0_BASE + 0x18;

#[cfg(target_arch = "aarch64")]
const UART_CR: usize = UART0_BASE + 0x30;

#[cfg(target_arch = "x86_64")]
const COM1_DATA: u16 = 0x3f8;

#[cfg(target_arch = "x86_64")]
const COM1_LSR: u16 = 0x3fd;

/// Enable UART TX (architecture-specific).
pub fn init() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::ptr::write_volatile(UART_CR as *mut u32, 0x301);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // COM1 TX works without full 8250 programming on QEMU microvm.
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn x86_outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn x86_inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack, preserves_flags));
    val
}

#[inline(always)]
pub fn putc(byte: u8) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        while core::ptr::read_volatile(UART_FR as *const u32) & (1 << 5) != 0 {}
        core::ptr::write_volatile(UART_DR as *mut u32, byte as u32);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        while x86_inb(COM1_LSR) & 0x20 == 0 {}
        x86_outb(COM1_DATA, byte);
    }
}

#[inline(always)]
pub fn write_str(s: &str) {
    for &b in s.as_bytes() {
        putc(b);
    }
}

/// Two-digit hex nybble print for MAC / debug bytes.
#[inline(always)]
pub fn write_u8_hex(b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    putc(HEX[(b >> 4) as usize]);
    putc(HEX[(b & 0x0f) as usize]);
}

/// Decimal print for `u16` — zero heap.
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

/// One-shot metronome egress trace.
#[inline(always)]
pub fn log_tx_notify_slot31() {
    write_str("TX Notify Slot 31\n");
}

/// RX activity trace — length only to keep UART output bounded.
#[inline(always)]
pub fn log_rx_frame(len: usize) {
    write_str("RX frame len=");
    write_u16(len.min(u16::MAX as usize) as u16);
    putc(b'\n');
}
