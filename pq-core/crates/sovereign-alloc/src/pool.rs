//! Static 32 MiB physical memory pool in `.bss`.

use crate::buddy::{BuddyAllocator, POOL_BYTES};

/// Raw pre-mapped arena — linker places this in `.bss`.
#[repr(align(4096))]
pub struct StaticPool {
    pub bytes: [u8; POOL_BYTES],
}

impl StaticPool {
    pub const fn new() -> Self {
        Self {
            bytes: [0u8; POOL_BYTES],
        }
    }
}

/// 32 MiB arena — `.uninit_pool` is excluded from `clear_bss()` (boot must not zero it).
#[cfg_attr(target_os = "none", link_section = ".uninit_pool")]
static mut STATIC_POOL: StaticPool = StaticPool::new();
static mut BUDDY: Option<BuddyAllocator> = None;
static mut INITIALIZED: bool = false;

/// One-time initialization of the buddy allocator over the static pool.
///
/// # Safety
/// Must be called exactly once before any heap allocation.
pub unsafe fn init_static_pool() {
    #[cfg(target_os = "none")]
    {
        // Bare-metal: no Rust BSS zero-fill — always (re)build the buddy over the static pool.
        let pool = &mut STATIC_POOL.bytes;
        BUDDY = Some(BuddyAllocator::new(pool));
        INITIALIZED = true;
        return;
    }
    #[cfg(not(target_os = "none"))]
    if INITIALIZED {
        return;
    }
    let pool = &mut STATIC_POOL.bytes;
    BUDDY = Some(BuddyAllocator::new(pool));
    INITIALIZED = true;
}

pub(crate) unsafe fn buddy_mut() -> Option<&'static mut BuddyAllocator> {
    BUDDY.as_mut()
}
