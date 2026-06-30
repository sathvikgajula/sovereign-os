//! Bare-metal bin root: `_start` at `.text._start` + panic handler.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use sovereign_kernel::entry;

/// Rust handoff from naked `_start` (resolves `kernel_main` from the lib crate).
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn start_rust() -> ! {
    entry::kernel_main()
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[unsafe(naked)]
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "ldr x0, =__stack_top",
        "mov sp, x0",
        "bl start_rust",
        "1:",
        "b 1b",
    );
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    entry::bare_start()
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "aarch64")]
    sovereign_kernel::uart::write_str("panic\n");
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    eprintln!(
        "sovereign-kernel: bare-metal ELF — build with:\n\
         \x20 cargo build -p sovereign-kernel --target aarch64-unknown-none --release\n\
         \x20 cargo build -p sovereign-kernel --target x86_64-unknown-none --release"
    );
}
