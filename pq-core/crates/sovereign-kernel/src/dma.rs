//! Fixed non-cacheable DMA arena for virtio virtqueues (MMU-backed).

use core::cell::UnsafeCell;

use crate::virtio::queue::{RxVirtqueue, TxVirtqueue};

/// Physical base of the virtio DMA arena (must match linker script).
#[cfg(target_arch = "aarch64")]
pub const DMA_ARENA_BASE: usize = 0x4800_0000;

#[inline(always)]
pub fn dma_arena_base() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        DMA_ARENA_BASE
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe extern "C" {
            static __dma_arena_start: u8;
        }
        core::ptr::addr_of!(__dma_arena_start) as usize
    }
}
/// Arena size — one 2 MiB NC mapping covers this region.
pub const DMA_ARENA_SIZE: usize = 1 << 20;

const QUEUE_DEPTH: usize = 8;

/// Virtio TX/RX rings and frame buffers — lives only in `.dma_arena`.
#[repr(C, align(4096))]
pub struct VirtioDmaLayout {
    pub rx: UnsafeCell<RxVirtqueue<QUEUE_DEPTH>>,
    pub tx: UnsafeCell<TxVirtqueue<QUEUE_DEPTH>>,
}

impl VirtioDmaLayout {
    pub const fn new() -> Self {
        Self {
            rx: UnsafeCell::new(RxVirtqueue::new()),
            tx: UnsafeCell::new(TxVirtqueue::new()),
        }
    }
}

#[link_section = ".dma_arena"]
#[used]
static mut VIRTIO_DMA: VirtioDmaLayout = VirtioDmaLayout::new();

/// True when `addr..addr+len` lies entirely inside the DMA arena.
#[inline(always)]
pub fn range_in_arena(start: usize, end: usize) -> bool {
    let base = dma_arena_base();
    end > start
        && start >= base
        && end <= base + DMA_ARENA_SIZE
}

/// RX virtqueue in the DMA arena (identity-mapped PA == VA after MMU init).
#[inline(always)]
pub fn rx_queue() -> &'static UnsafeCell<RxVirtqueue<QUEUE_DEPTH>> {
    unsafe { &VIRTIO_DMA.rx }
}

/// TX virtqueue in the DMA arena.
#[inline(always)]
pub fn tx_queue() -> &'static UnsafeCell<TxVirtqueue<QUEUE_DEPTH>> {
    unsafe { &VIRTIO_DMA.tx }
}

/// Zero virtio queue state before probe (arena is NOLOAD).
pub unsafe fn init_virtio_queues() {
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(VIRTIO_DMA) as *mut u8,
        0,
        core::mem::size_of::<VirtioDmaLayout>(),
    );
}
