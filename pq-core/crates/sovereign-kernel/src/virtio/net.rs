//! VirtIO-net MMIO transmit path conforming to `NetTx`.

use super::mmio::VirtioMmio;

#[cfg(target_arch = "aarch64")]
use super::mmio::{QEMU_VIRTIO_MMIO_BASE, QEMU_VIRTIO_MMIO_SLOTS, QEMU_VIRTIO_MMIO_STRIDE, QEMU_VIRTIO_NET_SLOT};
#[cfg(target_arch = "x86_64")]
use super::mmio::{QEMU_VIRTIO_MMIO_BASE, QEMU_VIRTIO_MMIO_FALLBACKS};
use super::queue::{RxVirtqueue, TxVirtqueue, RX_BUF_LEN};
use crate::dma;
use crate::driver::{DriverError, NetRx, NetTx};
#[cfg(target_arch = "aarch64")]
use crate::uart;
use sovereign_frame::FRAME_LEN;
use sovereign_hal::arch::cpu_pause;

/// VirtIO 1.0 network frame prefix (12 bytes, `VIRTIO_F_VERSION_1`).
#[repr(C, packed)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl VirtioNetHeader {
    pub const LEN: usize = 12;

    /// No GSO/checksum offload; `num_buffers = 1` for `VIRTIO_F_VERSION_1` TX.
    pub const fn zeroed() -> Self {
        Self {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 1,
        }
    }

    /// Sequential write into the TX buffer prefix (avoids packed-field references).
    pub fn write_to(self, out: &mut [u8; Self::LEN]) {
        out[0] = self.flags;
        out[1] = self.gso_type;
        out[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        out[4..6].copy_from_slice(&self.csum_start.to_le_bytes());
        out[6..8].copy_from_slice(&self.csum_offset.to_le_bytes());
        out[8..10].copy_from_slice(&self.num_buffers.to_le_bytes());
    }
}

const RX_QUEUE_INDEX: u32 = 0;
const TX_QUEUE_INDEX: u32 = 1;
const QUEUE_DEPTH: usize = 8;
const ETH_HDR_LEN: usize = 14;
const FRAME_PAYLOAD_LEN: usize = FRAME_LEN - VirtioNetHeader::LEN - ETH_HDR_LEN; // 486
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Mock Ethernet II coordinates (bytes 12–25 of the 512-byte TX block).
const ETH_DST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const ETH_TYPE_IPV4: [u8; 2] = [0x08, 0x00];

/// Assemble the strict 512-byte virtio-net TX block: 12B hdr + 14B eth + 486B payload.
#[inline(always)]
fn assemble_tx_block(buf: &mut [u8; FRAME_LEN], eth_src: &[u8; 6], metronome: &[u8; FRAME_LEN]) {
    let mut vhdr = [0u8; VirtioNetHeader::LEN];
    VirtioNetHeader::zeroed().write_to(&mut vhdr);
    buf[..VirtioNetHeader::LEN].copy_from_slice(&vhdr);

    let eth_off = VirtioNetHeader::LEN;
    buf[eth_off..eth_off + 6].copy_from_slice(&ETH_DST);
    buf[eth_off + 6..eth_off + 12].copy_from_slice(eth_src);
    buf[eth_off + 12..eth_off + 14].copy_from_slice(&ETH_TYPE_IPV4);

    // Minimal IPv4/UDP envelope so QEMU slirp forwards guest egress to the netdev tap.
    let ip_off = eth_off + ETH_HDR_LEN;
    let udp_off = ip_off + 20;
    let pay_off = udp_off + 8;
    let pay_len = FRAME_LEN - pay_off;

    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    let ip_total = (udp_off + 8 + pay_len - ip_off) as u16;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&ip_total.to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = 17; // UDP
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&[10, 0, 2, 15]); // guest
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&[10, 0, 2, 255]); // broadcast

    buf[udp_off..udp_off + 2].copy_from_slice(&9u16.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&9u16.to_be_bytes());
    buf[udp_off + 4..udp_off + 6].copy_from_slice(&((8 + pay_len) as u16).to_be_bytes());

    buf[pay_off..FRAME_LEN].copy_from_slice(&metronome[..pay_len.min(FRAME_PAYLOAD_LEN)]);
}

/// Non-allocating virtio-net adapter for QEMU `virt` MMIO transport.
pub struct VirtioNet {
    mmio: VirtioMmio,
    rx: &'static core::cell::UnsafeCell<RxVirtqueue<QUEUE_DEPTH>>,
    tx: &'static core::cell::UnsafeCell<TxVirtqueue<QUEUE_DEPTH>>,
    eth_src: [u8; 6],
    rx_depth: usize,
    rx_ring_mask: usize,
    tx_depth: usize,
    /// Cached `(tx_depth - 1)` for power-of-two ring indexing.
    tx_ring_mask: usize,
    ready: bool,
}

unsafe impl Sync for VirtioNet {}

impl VirtioNet {
    /// Placeholder before in-place probe (virtqueues live in the NC DMA arena).
    pub fn empty() -> Self {
        Self {
            mmio: VirtioMmio::new(0),
            rx: dma::rx_queue(),
            tx: dma::tx_queue(),
            eth_src: [0; 6],
            rx_depth: 0,
            rx_ring_mask: 0,
            tx_depth: 0,
            tx_ring_mask: 0,
            ready: false,
        }
    }

    /// Probe virtio-net and initialize `out` in place (virtqueues must live in `.bss`).
    pub unsafe fn probe_into(out: &mut Self) -> Result<(), DriverError> {
        #[cfg(target_arch = "aarch64")]
        {
            // QEMU 11+ hot-plugs virtio-net at slot 31; try it before scanning all slots.
            let slot31 = QEMU_VIRTIO_NET_SLOT;
            let base31 = QEMU_VIRTIO_MMIO_BASE + slot31 * QEMU_VIRTIO_MMIO_STRIDE;
            if Self::probe_modern(base31, out).is_ok() {
                return Ok(());
            }
            for slot in 0..QEMU_VIRTIO_MMIO_SLOTS {
                if slot == slot31 {
                    continue;
                }
                let base = QEMU_VIRTIO_MMIO_BASE + slot * QEMU_VIRTIO_MMIO_STRIDE;
                if Self::probe_modern(base, out).is_ok() {
                    return Ok(());
                }
            }
            Err(DriverError::DeviceNotReady)
        }
        #[cfg(target_arch = "x86_64")]
        {
            for &base in QEMU_VIRTIO_MMIO_FALLBACKS {
                if Self::probe_legacy(base, out).is_ok() {
                    return Ok(());
                }
            }
            Err(DriverError::DeviceNotReady)
        }
    }

    /// VirtIO 1.0 modern handshake at `base`.
    #[cfg(target_arch = "aarch64")]
    unsafe fn probe_modern(base: usize, out: &mut Self) -> Result<(), DriverError> {
        let mmio = VirtioMmio::new(base);
        if !mmio.is_net_device() {
            return Err(DriverError::DeviceNotReady);
        }

        mmio.modern_handshake()
            .map_err(|_| DriverError::DeviceNotReady)?;
        mmio.prepare_queue_config()
            .map_err(|_| DriverError::DeviceNotReady)?;

        out.mmio = mmio;
        out.eth_src = out.mmio.read_net_mac();
        out.rx_depth = 0;
        out.rx_ring_mask = 0;
        out.tx_depth = 0;
        out.tx_ring_mask = 0;
        out.ready = false;

        out.setup_rx_queue()?;
        out.setup_tx_queue()?;

        out.mmio
            .driver_ok()
            .map_err(|_| DriverError::DeviceNotReady)?;

        out.mmio.notify(RX_QUEUE_INDEX);
        post_notify_fence();

        out.ready = true;
        #[cfg(target_arch = "aarch64")]
        {
            uart::write_str("VirtIO NET DRIVER_OK mac=");
            for b in out.eth_src {
                uart::write_u8_hex(b);
            }
            uart::write_str(" dma=");
            uart::write_u16((dma::DMA_ARENA_BASE >> 16) as u16);
            uart::putc(b'\n');
        }
        Ok(())
    }

    /// Legacy probe path (x86_64 microvm and fallback).
    #[cfg(target_arch = "x86_64")]
    unsafe fn probe_legacy(base: usize, out: &mut Self) -> Result<(), DriverError> {
        let mmio = VirtioMmio::new(base);
        mmio.begin_legacy()
            .map_err(|_| DriverError::DeviceNotReady)?;

        out.mmio = mmio;
        out.eth_src = out.mmio.read_net_mac();
        out.rx_depth = 0;
        out.rx_ring_mask = 0;
        out.tx_depth = 0;
        out.tx_ring_mask = 0;
        out.ready = false;

        out.setup_rx_queue()?;
        out.setup_tx_queue()?;
        out.mmio
            .driver_ok()
            .map_err(|_| DriverError::DeviceNotReady)?;
        out.ready = true;
        Ok(())
    }

    unsafe fn setup_rx_queue(&mut self) -> Result<(), DriverError> {
        let rx = &mut *self.rx.get();
        rx.avail.flags = 0;
        rx.avail.idx = 0;

        let depth = self
            .mmio
            .configure_virtqueue_dual(
                RX_QUEUE_INDEX,
                QUEUE_DEPTH as u32,
                rx.desc_phys(),
                rx.avail_phys(),
                rx.used_phys(),
                true,
            )
            .map_err(|_| DriverError::DeviceNotReady)? as usize;

        self.rx_depth = depth;
        self.rx_ring_mask = depth - 1;
        rx.last_used = 0;

        for i in 0..depth {
            let addr = rx.buffers[i].as_ptr() as u64;
            rx.desc[i] = super::queue::VirtqDesc {
                addr,
                len: RX_BUF_LEN as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };
            rx.avail.ring[i] = i as u16;
        }
        let desc_start = rx.desc.as_ptr() as usize;
        let desc_end = desc_start + core::mem::size_of::<super::queue::VirtqDesc>() * depth;
        dma_write_sync(desc_start, desc_end);
        let avail_start = core::ptr::addr_of!(rx.avail) as usize;
        let avail_end = avail_start + core::mem::size_of_val(&rx.avail);
        dma_write_sync(avail_start, avail_end);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        rx.avail.idx = depth as u16;
        pre_notify_fence();
        Ok(())
    }

    unsafe fn setup_tx_queue(&mut self) -> Result<(), DriverError> {
        let tx = &mut *self.tx.get();
        tx.avail.flags = 0;
        tx.avail.idx = 0;
        tx.slot = 0;

        // TX Queue 1: modern 64-bit split-ring pointers + legacy QueuePFN @ 0x028 bridge.
        let desc_phys = tx.desc_phys();
        let depth = self
            .mmio
            .configure_virtqueue_dual(
                TX_QUEUE_INDEX,
                QUEUE_DEPTH as u32,
                desc_phys,
                tx.avail_phys(),
                tx.used_phys(),
                true,
            )
            .map_err(|_| DriverError::DeviceNotReady)? as usize;

        self.tx_depth = depth;
        self.tx_ring_mask = depth - 1;
        Ok(())
    }

    /// Current RX used-ring index (device write cursor).
    pub fn rx_used_idx(&self) -> u16 {
        if !self.ready || self.rx_depth == 0 {
            return 0;
        }
        let rx = unsafe { &*self.rx.get() };
        read_used_idx(&rx.used)
    }

    /// VirtIO-probed MAC address (Ethernet source for TX).
    pub fn eth_mac(&self) -> [u8; 6] {
        self.eth_src
    }

    /// Transmit a raw Ethernet II frame (smoltcp path). Prepends virtio-net header.
    pub fn send_eth_frame(&self, eth: &[u8]) -> Result<(), DriverError> {
        if !self.ready || self.tx_depth == 0 || eth.is_empty() || eth.len() > 1514 {
            return Err(if eth.len() > 1514 {
                DriverError::TransmitBusy
            } else {
                DriverError::DeviceNotReady
            });
        }

        let total = VirtioNetHeader::LEN + eth.len();
        let depth = self.tx_depth;
        let ring_mask = self.tx_ring_mask;
        let tx = unsafe { &mut *self.tx.get() };
        wait_tx_ring_slot(tx, depth);

        let idx = tx.slot & ring_mask;
        tx.slot = (tx.slot + 1) & ring_mask;

        let buf = &mut tx.buffers[idx];
        let mut vhdr = [0u8; VirtioNetHeader::LEN];
        VirtioNetHeader::zeroed().write_to(&mut vhdr);
        buf[..VirtioNetHeader::LEN].copy_from_slice(&vhdr);
        buf[VirtioNetHeader::LEN..VirtioNetHeader::LEN + eth.len()].copy_from_slice(eth);

        let buf_addr = buf.as_ptr() as u64;
        tx.desc[idx] = super::queue::VirtqDesc {
            addr: buf_addr,
            len: total as u32,
            flags: 0,
            next: 0,
        };
        dma_write_sync(buf_addr as usize, buf_addr as usize + total);

        tx.avail.flags = 0;
        let head = tx.avail.idx;
        let ring_pos = (head as usize) & ring_mask;
        tx.avail.ring[ring_pos] = idx as u16;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        tx.avail.idx = head.wrapping_add(1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        let desc_start = core::ptr::addr_of!(tx.desc[idx]) as usize;
        let desc_end = desc_start + core::mem::size_of::<super::queue::VirtqDesc>();
        dma_write_sync(desc_start, desc_end);
        let avail_start = core::ptr::addr_of!(tx.avail) as usize;
        let avail_end = avail_start + core::mem::size_of_val(&tx.avail);
        dma_write_sync(avail_start, avail_end);

        pre_notify_fence();
        unsafe {
            self.mmio.notify(TX_QUEUE_INDEX);
            self.mmio.ack_interrupt();
        }
        post_notify_fence();
        Ok(())
    }

    /// Inject a synthetic used-ring entry to validate `poll_rx` without external traffic.
    pub unsafe fn inject_selftest_rx(&self) {
        if !self.ready || self.rx_depth == 0 {
            return;
        }
        let rx = &mut *self.rx.get();
        const MSG: &[u8] = b"RX_SELFTEST";
        rx.buffers[0][..MSG.len()].copy_from_slice(MSG);
        core::ptr::write_volatile(&mut rx.used.ring[0].id as *mut u32 as *mut u32, 0);
        core::ptr::write_volatile(
            &mut rx.used.ring[0].len as *mut u32 as *mut u32,
            MSG.len() as u32,
        );
        core::ptr::write_volatile(&mut rx.used.idx as *mut u16 as *mut u16, 1);
        rx.last_used = 0;
    }
}

#[inline(always)]
fn post_notify_fence() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

#[inline(always)]
fn dma_arena_nc_active() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        return crate::mmu::aarch64::is_live();
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        false
    }
}

/// Sync driver writes visible to virtio DMA (skip D-cache clean inside NC arena).
#[inline(always)]
fn dma_write_sync(start: usize, end: usize) {
    if dma::range_in_arena(start, end) && dma_arena_nc_active() {
        pre_notify_fence();
        return;
    }
    clean_dcache_range(start, end);
}

/// Sync device writes visible to the CPU (skip D-cache invalidate inside NC arena).
#[inline(always)]
fn dma_read_sync(start: usize, end: usize) {
    if dma::range_in_arena(start, end) && dma_arena_nc_active() {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        return;
    }
    invalidate_dcache_range(start, end);
}

/// Clean guest memory range to PoC so virtio DMA sees driver writes (cached RAM only).
#[inline(always)]
fn clean_dcache_range(start: usize, end: usize) {
    #[cfg(target_arch = "aarch64")]
    if end > start {
        unsafe {
            let mut ctr: usize;
            core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr);
            let line = 4 << ((ctr >> 16) & 0xf);
            let mut addr = start & !(line - 1);
            while addr < end {
                core::arch::asm!("dc cvac, {}", in(reg) addr);
                addr += line;
            }
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
    }
}

/// Clean guest TX buffer to PoC so virtio DMA sees descriptor writes (Apple Silicon / QEMU).
#[inline(always)]
fn clean_tx_buffer(buf: &[u8; FRAME_LEN]) {
    let start = buf.as_ptr() as usize;
    dma_write_sync(start, start + FRAME_LEN);
}

#[inline(always)]
fn pre_notify_fence() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dmb st", options(nostack, preserves_flags));
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Invalidate D-cache lines covering a guest memory range (device → driver).
#[inline(always)]
fn invalidate_dcache_range(start: usize, end: usize) {
    #[cfg(target_arch = "aarch64")]
    if end > start {
        unsafe {
            let mut ctr: usize;
            core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr);
            let line = 4 << ((ctr >> 16) & 0xf);
            let mut addr = start & !(line - 1);
            while addr < end {
                core::arch::asm!("dc ivac, {}", in(reg) addr);
                addr += line;
            }
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
    }
}

#[inline(always)]
fn read_used_idx<const N: usize>(used: &super::queue::VirtqUsed<N>) -> u16 {
    let used_start = core::ptr::addr_of!(used.idx) as usize;
    let used_end = used_start + core::mem::size_of_val(used);
    dma_read_sync(used_start, used_end);
    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    unsafe { core::ptr::read_volatile(&used.idx as *const u16) }
}

#[inline(always)]
fn drain_rx_queue<F>(rx: &mut RxVirtqueue<QUEUE_DEPTH>, ring_mask: usize, handler: &mut F) -> usize
where
    F: FnMut(&[u8], usize),
{
    let mut delivered = 0usize;
    loop {
        let used_idx = read_used_idx(&rx.used);
        if rx.last_used == used_idx {
            break;
        }
        let pos = (rx.last_used as usize) & ring_mask;
        let desc_id = unsafe { core::ptr::read_volatile(&rx.used.ring[pos].id as *const u32) } as usize;
        let frame_len = unsafe { core::ptr::read_volatile(&rx.used.ring[pos].len as *const u32) } as usize;

        if desc_id < QUEUE_DEPTH {
            let buf = &rx.buffers[desc_id];
            let len = frame_len.min(RX_BUF_LEN);
            if len > 0 {
                let start = buf.as_ptr() as usize;
                dma_read_sync(start, start + len);
                let slice = unsafe { core::slice::from_raw_parts(buf.as_ptr(), len) };
                handler(slice, len);
                delivered += 1;
            }
        }

        let head = rx.avail.idx;
        let avail_pos = (head as usize) & ring_mask;
        rx.avail.ring[avail_pos] = desc_id as u16;
        rx.avail.idx = head.wrapping_add(1);
        rx.last_used = rx.last_used.wrapping_add(1);
    }

    if delivered > 0 {
        let avail_start = core::ptr::addr_of!(rx.avail) as usize;
        let avail_end = avail_start + core::mem::size_of_val(&rx.avail);
        dma_write_sync(avail_start, avail_end);
    }

    delivered
}

/// Poll RX virtqueue, deliver frames, and re-post buffers to the device.
#[inline(always)]
fn poll_rx_inner<F>(net: &VirtioNet, handler: &mut F) -> Result<usize, DriverError>
where
    F: FnMut(&[u8], usize),
{
    if !net.ready || net.rx_depth == 0 {
        return Err(DriverError::DeviceNotReady);
    }

    unsafe {
        net.mmio.ack_interrupt();
    }

    let rx = unsafe { &mut *net.rx.get() };
    let delivered = drain_rx_queue(rx, net.rx_ring_mask, handler);

    if delivered > 0 {
        pre_notify_fence();
        unsafe {
            net.mmio.notify(RX_QUEUE_INDEX);
            net.mmio.ack_interrupt();
        }
        post_notify_fence();
    }

    Ok(delivered)
}

#[inline(always)]
fn wait_tx_ring_slot(tx: &TxVirtqueue<QUEUE_DEPTH>, depth: usize) {
    let mut spins = 0u32;
    loop {
        let used_idx = read_used_idx(&tx.used);
        let inflight = tx.avail.idx.wrapping_sub(used_idx);
        if inflight < depth as u16 {
            return;
        }
        spins = spins.wrapping_add(1);
        if spins > 4096 {
            return;
        }
        cpu_pause();
    }
}

impl NetTx for VirtioNet {
    fn send_frame(&self, frame: &[u8; FRAME_LEN]) -> Result<(), DriverError> {
        if !self.ready || self.tx_depth == 0 {
            return Err(DriverError::DeviceNotReady);
        }

        let depth = self.tx_depth;
        let ring_mask = self.tx_ring_mask;

        let tx = unsafe { &mut *self.tx.get() };
        wait_tx_ring_slot(tx, depth);

        let idx = tx.slot & ring_mask;
        tx.slot = (tx.slot + 1) & ring_mask;

        assemble_tx_block(&mut tx.buffers[idx], &self.eth_src, frame);

        let buf_addr = tx.buffers[idx].as_ptr() as u64;
        tx.desc[idx] = super::queue::VirtqDesc {
            addr: buf_addr,
            len: FRAME_LEN as u32,
            flags: 0,
            next: 0,
        };
        clean_tx_buffer(&tx.buffers[idx]);

        tx.avail.flags = 0;
        let head = tx.avail.idx;
        let ring_pos = (head as usize) & ring_mask;
        tx.avail.ring[ring_pos] = idx as u16;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        tx.avail.idx = head.wrapping_add(1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        let desc_start = core::ptr::addr_of!(tx.desc[idx]) as usize;
        let desc_end = desc_start + core::mem::size_of::<super::queue::VirtqDesc>();
        dma_write_sync(desc_start, desc_end);
        let avail_start = core::ptr::addr_of!(tx.avail) as usize;
        let avail_end = avail_start + core::mem::size_of_val(&tx.avail);
        dma_write_sync(avail_start, avail_end);
        let queue_start = tx as *const TxVirtqueue<QUEUE_DEPTH> as usize;
        let queue_end = queue_start + core::mem::size_of_val(&*tx);
        dma_write_sync(queue_start, queue_end);

        static mut TX_LOGGED: bool = false;
        unsafe {
            if !TX_LOGGED {
                #[cfg(target_arch = "aarch64")]
                uart::log_tx_notify_slot31();
                TX_LOGGED = true;
            }
        }

        pre_notify_fence();
        unsafe {
            self.mmio.notify(TX_QUEUE_INDEX);
        }
        post_notify_fence();
        unsafe {
            self.mmio.ack_interrupt();
        }
        let used_idx = read_used_idx(&tx.used);

        // Wait briefly for device to mark the descriptor used.
        let used_before = used_idx;
        for _ in 0..65536 {
            let used_now = read_used_idx(&tx.used);
            if used_now != used_before {
                break;
            }
            cpu_pause();
        }

        let used_idx = read_used_idx(&tx.used);
        #[cfg(target_arch = "aarch64")]
        if tx.slot % 10 == 0 {
            uart::write_str("TX Progress: Handed off frame. Device Used Index = ");
            uart::write_u16(used_idx);
            uart::putc(b'\n');
        }
        Ok(())
    }
}

impl NetRx for VirtioNet {
    fn poll_rx<F>(&self, handler: F) -> Result<usize, DriverError>
    where
        F: FnMut(&[u8], usize),
    {
        let mut handler = handler;
        poll_rx_inner(self, &mut handler)
    }
}

/// `sovereign_frame::Egress` adapter for the metronome loop.
pub struct VirtioEgress<'a>(pub &'a VirtioNet);

impl<'a> sovereign_frame::Egress for VirtioEgress<'a> {
    type Error = DriverError;

    fn transmit(&self, frame: &[u8; FRAME_LEN]) -> Result<(), Self::Error> {
        self.0.send_frame(frame)
    }
}

/// Thin adapter exposing [`NetRx`] on the shared [`VirtioNet`] instance.
pub struct VirtioIngress<'a>(pub &'a VirtioNet);

impl<'a> VirtioIngress<'a> {
    #[inline(always)]
    pub fn poll<F>(&self, handler: F) -> Result<usize, DriverError>
    where
        F: FnMut(&[u8], usize),
    {
        self.0.poll_rx(handler)
    }
}
