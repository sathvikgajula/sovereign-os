//! Power-of-two buddy allocator over a pre-mapped static pool.

use core::alloc::Layout;
use core::ptr;

/// Minimum allocatable block (512 B — matches metronome frame size).
pub const MIN_BLOCK: usize = 512;
/// Total static pool size (32 MiB desktop; 4 KiB bare-metal kernel stub).
#[cfg(not(feature = "kernel-minimal"))]
pub const POOL_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "kernel-minimal")]
pub const POOL_BYTES: usize = 4096;

const MAX_ORDER: usize = 16; // 512 * 2^15 = 16 MiB max single block

#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
}

/// Buddy allocator backed by caller-supplied memory slice.
pub struct BuddyAllocator {
    base: *mut u8,
    total: usize,
    max_order: usize,
    free: [*mut FreeNode; MAX_ORDER + 1],
}

impl BuddyAllocator {
    /// Initialize buddy system over `pool`. `pool.len()` must be a power of two >= MIN_BLOCK.
    pub unsafe fn new(pool: &mut [u8]) -> Self {
        let total = pool.len();
        assert!(total.is_power_of_two() && total >= MIN_BLOCK, "pool must be power-of-two");
        let max_order = (total / MIN_BLOCK).ilog2() as usize;

        let base = pool.as_mut_ptr();
        let mut alloc = Self {
            base,
            total,
            max_order,
            free: [ptr::null_mut(); MAX_ORDER + 1],
        };

        alloc.push_free(max_order, base);
        alloc
    }

    fn order_for_layout(layout: Layout) -> Option<usize> {
        let need = layout.size().max(layout.align()).max(MIN_BLOCK);
        if !need.is_power_of_two() {
            return None;
        }
        let order = (need / MIN_BLOCK).trailing_zeros() as usize;
        if MIN_BLOCK << order < need {
            return None;
        }
        Some(order)
    }

    fn push_free(&mut self, order: usize, ptr: *mut u8) {
        let node = ptr as *mut FreeNode;
        unsafe {
            (*node).next = self.free[order];
            self.free[order] = node;
        }
    }

    fn pop_free(&mut self, order: usize) -> Option<*mut u8> {
        let head = self.free[order];
        if head.is_null() {
            return None;
        }
        unsafe {
            self.free[order] = (*head).next;
        }
        Some(head as *mut u8)
    }

    pub unsafe fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let target = match Self::order_for_layout(layout) {
            Some(o) => o,
            None => return ptr::null_mut(),
        };

        let mut found_order = None;
        for order in target..=self.max_order {
            if !self.free[order].is_null() {
                found_order = Some(order);
                break;
            }
        }
        let found_order = match found_order {
            Some(o) => o,
            None => return ptr::null_mut(),
        };

        let mut ptr = self.pop_free(found_order).unwrap();
        let mut order = found_order;
        while order > target {
            order -= 1;
            let half = unsafe { ptr.add(MIN_BLOCK << order) };
            self.push_free(order, half);
        }
        ptr
    }

    pub unsafe fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let order = match Self::order_for_layout(layout) {
            Some(o) => o,
            None => return,
        };

        let mut current_order = order;
        let mut current = ptr;

        while current_order < self.max_order {
            let buddy = Self::buddy_ptr(self.base, current, current_order);
            if !self.take_buddy(current_order, buddy) {
                break;
            }
            current = if current < buddy { current } else { buddy };
            current_order += 1;
        }

        self.push_free(current_order, current);
    }

    fn buddy_ptr(base: *mut u8, ptr: *mut u8, order: usize) -> *mut u8 {
        let offset = unsafe { ptr.offset_from(base) } as usize;
        let block = MIN_BLOCK << order;
        let buddy_offset = offset ^ block;
        unsafe { base.add(buddy_offset) }
    }

    fn take_buddy(&mut self, order: usize, buddy: *mut u8) -> bool {
        let mut prev: *mut FreeNode = ptr::null_mut();
        let mut cur = self.free[order];
        while !cur.is_null() {
            if cur as *mut u8 == buddy {
                unsafe {
                    let next = (*cur).next;
                    if prev.is_null() {
                        self.free[order] = next;
                    } else {
                        (*prev).next = next;
                    }
                }
                return true;
            }
            unsafe {
                prev = cur;
                cur = (*cur).next;
            }
        }
        false
    }
}

/// Round layout up to buddy-supported power-of-two block.
pub fn layout_to_buddy(layout: Layout) -> Layout {
    let mut size = layout.size().max(layout.align()).max(MIN_BLOCK);
    if !size.is_power_of_two() {
        size = size.next_power_of_two().max(MIN_BLOCK);
    }
    Layout::from_size_align(size, MIN_BLOCK).unwrap_or(layout)
}
