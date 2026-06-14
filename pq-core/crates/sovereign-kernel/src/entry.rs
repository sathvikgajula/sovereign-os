//! Bare-metal entry point for QEMU / UEFI handoff.

use sovereign_alloc::enter_metronome_thread;
#[cfg(not(target_os = "none"))]
use sovereign_alloc::init;
use sovereign_frame::{Egress, FRAME_LEN, MetronomeTimer};
use sovereign_hal::arch::cpu_pause;

use crate::timer::TscTimer;
#[cfg(target_arch = "aarch64")]
use crate::uart;
use crate::virtio::{VirtioEgress, VirtioNet};

/// x86_64 stack setup — called from bin `_start`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn bare_start() -> ! {
    unsafe {
        extern "C" {
            static __stack_top: u8;
        }
        core::arch::asm!(
            "mov rsp, {stack}",
            stack = in(reg) core::ptr::addr_of!(__stack_top) as usize,
        );
    }
    kernel_main()
}

/// Zero `.bss` before Rust statics / allocator touch (no CRT on `target_os = "none"`).
#[cfg(target_os = "none")]
fn clear_bss() {
    unsafe extern "C" {
        static __bss_start: u8;
        static __bss_end: u8;
    }
    let start = core::ptr::addr_of!(__bss_start) as usize;
    let end = core::ptr::addr_of!(__bss_end) as usize;
    if end > start {
        unsafe {
            core::ptr::write_bytes(start as *mut u8, 0, end - start);
        }
    }
}

/// Static heartbeat payload — avoids large stack frames in the metronome loop.
#[cfg(target_os = "none")]
static mut HEARTBEAT_FRAME: [u8; FRAME_LEN] = [0u8; FRAME_LEN];

/// Core boot sequence — called from bin `start_rust` / x86 `bare_start`.
#[cfg(target_os = "none")]
pub extern "C" fn kernel_main() -> ! {
    #[cfg(target_arch = "aarch64")]
    uart::init();

    clear_bss();

    static mut NET: Option<VirtioNet> = None;
    unsafe {
        NET = Some(VirtioNet::empty());
        if VirtioNet::probe_into(NET.as_mut().unwrap()).is_err() {
            #[cfg(target_arch = "aarch64")]
            uart::write_str("VirtIO probe failed\n");
            loop {
                cpu_pause();
            }
        }
    }

    let timer = TscTimer::calibrate();
    let net = unsafe { NET.as_ref().unwrap() };
    let egress = VirtioEgress(net);

    enter_metronome_thread();

    let mut epoch: u64 = 0;
    loop {
        unsafe {
            HEARTBEAT_FRAME[..8].copy_from_slice(&epoch.to_le_bytes());
            match egress.transmit(unsafe { &*core::ptr::addr_of!(HEARTBEAT_FRAME) }) {
                Ok(()) => {}
                Err(_) => {}
            }
        }
        epoch = epoch.wrapping_add(1);
        let deadline = timer.monotonic_ns().wrapping_add(200_000_000);
        timer.sleep_until(deadline);
    }
}
