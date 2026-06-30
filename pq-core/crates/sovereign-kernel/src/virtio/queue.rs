//! Static Virtqueue rings — zero heap.

/// Virtio-net RX slot size (standard Ethernet frame + virtio header headroom).
pub const RX_BUF_LEN: usize = 1526;

/// Virtqueue descriptor (virtio 1.0).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// Minimal avail ring header + ring array.
#[repr(C)]
pub struct VirtqAvail<const N: usize> {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; N],
}

/// Minimal used ring header + elements.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
pub struct VirtqUsed<const N: usize> {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; N],
}

/// Pre-allocated transmit virtqueue (power-of-two depth).
/// Descriptor table requires 16-byte alignment (virtio 1.0 §2.6).
#[repr(C, align(16))]
pub struct TxVirtqueue<const N: usize> {
    pub desc: [VirtqDesc; N],
    pub avail: VirtqAvail<N>,
    pub used: VirtqUsed<N>,
    pub buffers: [[u8; 512]; N],
    pub slot: usize,
    /// Driver-side used-ring cursor (RX recycle).
    pub last_used: u16,
}

impl<const N: usize> TxVirtqueue<N> {
    pub const fn new() -> Self {
        Self {
            desc: [VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; N],
            avail: VirtqAvail {
                flags: 0,
                idx: 0,
                ring: [0u16; N],
            },
            used: VirtqUsed {
                flags: 0,
                idx: 0,
                ring: [VirtqUsedElem { id: 0, len: 0 }; N],
            },
            buffers: [[0u8; 512]; N],
            slot: 0,
            last_used: 0,
        }
    }

    pub fn desc_phys(&self) -> u64 {
        self.desc.as_ptr() as u64
    }

    pub fn avail_phys(&self) -> u64 {
        &self.avail as *const _ as u64
    }

    pub fn used_phys(&self) -> u64 {
        &self.used as *const _ as u64
    }
}

/// Pre-allocated receive virtqueue (power-of-two depth).
#[repr(C, align(16))]
pub struct RxVirtqueue<const N: usize> {
    pub desc: [VirtqDesc; N],
    pub avail: VirtqAvail<N>,
    pub used: VirtqUsed<N>,
    pub buffers: [[u8; RX_BUF_LEN]; N],
    pub last_used: u16,
}

impl<const N: usize> RxVirtqueue<N> {
    pub const fn new() -> Self {
        Self {
            desc: [VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; N],
            avail: VirtqAvail {
                flags: 0,
                idx: 0,
                ring: [0u16; N],
            },
            used: VirtqUsed {
                flags: 0,
                idx: 0,
                ring: [VirtqUsedElem { id: 0, len: 0 }; N],
            },
            buffers: [[0u8; RX_BUF_LEN]; N],
            last_used: 0,
        }
    }

    pub fn desc_phys(&self) -> u64 {
        self.desc.as_ptr() as u64
    }

    pub fn avail_phys(&self) -> u64 {
        &self.avail as *const _ as u64
    }

    pub fn used_phys(&self) -> u64 {
        &self.used as *const _ as u64
    }
}
