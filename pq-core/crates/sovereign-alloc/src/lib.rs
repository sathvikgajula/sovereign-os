//! Deterministic buddy/slab allocator with Core 0 heap lockout.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod buddy;
mod pool;

pub use buddy::{BuddyAllocator, MIN_BLOCK, POOL_BYTES};
pub use pool::StaticPool;

use buddy::layout_to_buddy;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

/// Set while the metronome thread (Core 0) is active — heap alloc forbidden.
static METRONOME_THREAD_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Mark entry into the real-time metronome thread.
pub fn enter_metronome_thread() {
    METRONOME_THREAD_ACTIVE.store(true, Ordering::Release);
}

/// Mark exit from the metronome thread.
pub fn leave_metronome_thread() {
    METRONOME_THREAD_ACTIVE.store(false, Ordering::Release);
}

/// Abort if heap allocation is attempted on Core 0 metronome thread.
#[inline]
pub fn assert_heap_allowed() {
    if METRONOME_THREAD_ACTIVE.load(Ordering::Acquire) {
        panic!("heap allocation forbidden on Core 0 metronome thread");
    }
}

/// Initialize the static 32 MiB buddy pool. Call once from `_start` before heap use.
///
/// # Safety
/// Must be invoked exactly once during bare-metal boot.
pub unsafe fn init() {
    pool::init_static_pool();
}

/// Global deterministic allocator facade.
pub struct SovereignAllocator;

impl SovereignAllocator {
    pub const fn new() -> Self {
        Self
    }
}

unsafe impl GlobalAlloc for SovereignAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        assert_heap_allowed();
        let layout = layout_to_buddy(layout);
        match pool::buddy_mut() {
            Some(buddy) => buddy.alloc(layout),
            None => null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        assert_heap_allowed();
        let layout = layout_to_buddy(layout);
        if let Some(buddy) = pool::buddy_mut() {
            buddy.dealloc(ptr, layout);
        }
    }
}

/// Recommended global allocator instance for bare-metal binaries.
#[cfg(target_os = "none")]
#[global_allocator]
static GLOBAL: SovereignAllocator = SovereignAllocator::new();

/// Static RT frame pool — 64 × 512 B slots, never heap-backed.
pub struct RtFramePool<const N: usize> {
    pub slots: [[u8; 512]; N],
    head: usize,
}

impl<const N: usize> RtFramePool<N> {
    pub const fn new() -> Self {
        Self {
            slots: [[0u8; 512]; N],
            head: 0,
        }
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    /// Borrow next slot (round-robin) for in-place frame assembly — zero alloc.
    pub fn next_slot(&mut self) -> &mut [u8; 512] {
        let idx = self.head % N;
        self.head = self.head.wrapping_add(1);
        &mut self.slots[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metronome_guard_blocks_while_active() {
        enter_metronome_thread();
        assert!(METRONOME_THREAD_ACTIVE.load(Ordering::Acquire));
        leave_metronome_thread();
        assert!(!METRONOME_THREAD_ACTIVE.load(Ordering::Acquire));
    }

    #[test]
    fn buddy_alloc_dealloc() {
        let mut mem = vec![0u8; 4096];
        unsafe {
            let mut buddy = BuddyAllocator::new(&mut mem);
            let layout = Layout::from_size_align(512, 512).unwrap();
            let p = buddy.alloc(layout);
            assert!(!p.is_null());
            buddy.dealloc(p, layout);
        }
    }
}
