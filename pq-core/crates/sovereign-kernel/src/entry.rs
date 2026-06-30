//! Bare-metal entry point for QEMU / UEFI handoff.

use core::sync::atomic::{AtomicU64, Ordering};

use sovereign_alloc::enter_metronome_thread;
#[cfg(not(target_os = "none"))]
use sovereign_alloc::init;
use sovereign_frame::{Egress, FRAME_LEN, MetronomeTimer};
use sovereign_hal::arch::cpu_pause;

use crate::timer::TscTimer;
use crate::uart;
use crate::virtio::{VirtioEgress, VirtioIngress, VirtioNet};

/// Total RX frames delivered by the metronome loop (observable from tests).
#[cfg(target_os = "none")]
static RX_FRAME_COUNT: AtomicU64 = AtomicU64::new(0);

static mut NET: Option<VirtioNet> = None;

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

#[cfg(target_os = "none")]
unsafe fn init_mmu_and_dma() {
    #[cfg(target_arch = "aarch64")]
    {
        crate::mmu::aarch64::build_tables();
        crate::mmu::aarch64::enable_mmu();
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::mmu::x86_64::boot_mmu();
    }
    uart::write_str("mmu-on\n");
    #[cfg(target_arch = "aarch64")]
    crate::dma::init_virtio_queues();
    #[cfg(target_arch = "aarch64")]
    uart::write_str("MMU+DMA arena NC @0x4800\n");
    #[cfg(target_arch = "x86_64")]
    uart::write_str("MMU+DMA arena @low\n");
}

/// Static heartbeat payload — avoids large stack frames in the metronome loop.
#[cfg(target_os = "none")]
static mut HEARTBEAT_FRAME: [u8; FRAME_LEN] = [0u8; FRAME_LEN];

/// Post-virtio boot: smoltcp, metronome, RX lab (x86 tail-call from queue setup).
#[cfg(target_os = "none")]
pub(crate) unsafe fn run_after_virtio() -> ! {
    let net: &'static VirtioNet = NET.as_ref().unwrap();
    let timer = TscTimer::calibrate();

    #[cfg(all(feature = "rx-lab", target_arch = "x86_64"))]
    {
        net.inject_selftest_rx();
        let ingress = VirtioIngress(net);
        let _ = ingress.poll(|_data, len| {
            RX_FRAME_COUNT.fetch_add(1, Ordering::Relaxed);
            uart::log_rx_frame(len);
        });
        let mut last_rx_used = net.rx_used_idx();
        loop {
            let _ = ingress.poll(|_data, len| {
                RX_FRAME_COUNT.fetch_add(1, Ordering::Relaxed);
                uart::log_rx_frame(len);
            });
            let used = net.rx_used_idx();
            if used != last_rx_used {
                uart::write_str("RX used idx=");
                uart::write_u16(used);
                uart::putc(b'\n');
                last_rx_used = used;
            }
            let deadline = timer.monotonic_ns().wrapping_add(50_000_000);
            timer.sleep_until(deadline);
        }
    }

    crate::net::init_stack(net);

    #[cfg(feature = "rx-lab")]
    {
        crate::net::inject_udp_selftest();
        for _ in 0..8 {
            crate::net::poll_stack(&timer);
        }
    }

    let egress = VirtioEgress(net);
    let ingress = VirtioIngress(net);

    enter_metronome_thread();

    #[cfg(feature = "rx-lab")]
    {
        let _ = ingress.poll(|_data, len| {
            RX_FRAME_COUNT.fetch_add(1, Ordering::Relaxed);
            uart::log_rx_frame(len);
        });
    }

    let mut epoch: u64 = 0;
    let mut last_rx_used: u16 = 0;
    loop {
        crate::net::poll_stack(&timer);

        #[cfg(feature = "rx-lab")]
        {
            let _ = ingress.poll(|_data, len| {
                RX_FRAME_COUNT.fetch_add(1, Ordering::Relaxed);
                uart::log_rx_frame(len);
            });
            let used = net.rx_used_idx();
            if used != last_rx_used {
                uart::write_str("RX used idx=");
                uart::write_u16(used);
                uart::putc(b'\n');
                last_rx_used = used;
            }
        }

        HEARTBEAT_FRAME[..8].copy_from_slice(&epoch.to_le_bytes());
        let _ = egress.transmit(&*core::ptr::addr_of!(HEARTBEAT_FRAME));
        epoch = epoch.wrapping_add(1);
        let deadline = timer.monotonic_ns().wrapping_add(200_000_000);
        timer.sleep_until(deadline);
    }
}

/// Core boot sequence — called from bin `start_rust` / x86 `bare_start`.
#[cfg(target_os = "none")]
pub extern "C" fn kernel_main() -> ! {
    uart::init();
    #[cfg(target_arch = "aarch64")]
    clear_bss();

    unsafe {
        init_mmu_and_dma();
    }

    unsafe {
        NET = Some(VirtioNet::empty());
        if VirtioNet::probe_into(NET.as_mut().unwrap()).is_err() {
            uart::write_str("VirtIO probe failed\n");
            loop {
                cpu_pause();
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            VirtioNet::finish_x86_queues(NET.as_mut().unwrap());
        }
        #[cfg(target_arch = "aarch64")]
        {
            #[cfg(feature = "rx-lab")]
            NET.as_ref().unwrap().inject_selftest_rx();
            run_after_virtio();
        }
    }
}
