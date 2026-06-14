//! VirtIO 1.0 MMIO transport — legacy + modern (VERSION_1) register access.

/// Primary virtio-mmio base for QEMU `virt` (first slot).
#[cfg(target_arch = "aarch64")]
pub const QEMU_VIRTIO_MMIO_BASE: usize = 0x0a00_0000;

/// QEMU 11+ hot-plugged `virtio-net-device` on `virt` (slot 31).
#[cfg(target_arch = "aarch64")]
pub const QEMU_VIRTIO_NET_SLOT: usize = 31;

#[cfg(target_arch = "aarch64")]
pub const QEMU_VIRTIO_NET_MMIO_BASE: usize =
    QEMU_VIRTIO_MMIO_BASE + QEMU_VIRTIO_NET_SLOT * 0x200;

/// `virt` machine virtio-mmio slots are spaced 0x200 bytes apart.
#[cfg(target_arch = "aarch64")]
pub const QEMU_VIRTIO_MMIO_STRIDE: usize = 0x200;

#[cfg(target_arch = "aarch64")]
pub const QEMU_VIRTIO_MMIO_SLOTS: usize = 32;

/// microvm / legacy mmio virtio bases probed in order on x86_64 hosts.
#[cfg(target_arch = "x86_64")]
pub const QEMU_VIRTIO_MMIO_BASE: usize = 0xfe00_0000;

#[cfg(target_arch = "x86_64")]
pub const QEMU_VIRTIO_MMIO_FALLBACKS: &[usize] = &[0xfe00_0000, 0xd000_0000];

const MAGIC: u32 = 0x7472_6976; // "virt"
const DEVICE_NET: u32 = 1;

/// VirtIO MMIO register offsets (virtio-v1.1 §4.2.2).
#[repr(u32)]
pub enum MmioReg {
    Magic = 0x000,
    Version = 0x004,
    DeviceId = 0x008,
    VendorId = 0x00c,
    DeviceFeatures = 0x010,
    DeviceFeaturesSel = 0x014,
    DriverFeatures = 0x020,
    DriverFeaturesSel = 0x024,
    /// Legacy page-frame number for combined virtqueue (force-legacy QEMU backends).
    QueuePFN = 0x028,
    QueueSel = 0x030,
    QueueNumMax = 0x034,
    QueueNum = 0x038,
    QueueReady = 0x044,
    QueueNotify = 0x050,
    InterruptStatus = 0x060,
    InterruptACK = 0x064,
    Status = 0x070,
    QueueDescLow = 0x080,
    QueueDescHigh = 0x084,
    /// Available ring (driver area) — `QueueDriverLow` in virtio spec.
    QueueDriverLow = 0x090,
    QueueDriverHigh = 0x094,
    /// Used ring (device area) — `QueueDeviceLow` in virtio spec.
    QueueDeviceLow = 0x0a0,
    QueueDeviceHigh = 0x0a4,
}

pub const STATUS_ACK: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;
pub const STATUS_FAILED: u32 = 128;

/// `VIRTIO_F_VERSION_1` — global feature bit 32 → word 1, bit 0.
const FEATURE_VERSION_1: u32 = 1;

/// `VIRTIO_NET_F_MAC` — config-space MAC (word 0, bit 5).
const VIRTIO_NET_F_MAC: u32 = 1 << 5;

/// Offload / GSO / control bits we must not ack for raw 512-byte lab frames.
const VIRTIO_NET_OFFLOAD_MASK: u32 = (1 << 0)  // CSUM
    | (1 << 1)  // GUEST_CSUM
    | (1 << 2)  // CTRL_VQ
    | (1 << 3)  // CTRL_RX
    | (1 << 4)  // CTRL_VLAN
    | (1 << 7)  // GUEST_USO4
    | (1 << 8)  // GUEST_USO6
    | (1 << 9)  // GUEST_TSO4
    | (1 << 10) // GUEST_TSO6
    | (1 << 11) // GUEST_ECN
    | (1 << 12) // GUEST_UFO
    | (1 << 13) // HOST_TSO4
    | (1 << 14) // HOST_TSO6
    | (1 << 15) // HOST_ECN
    | (1 << 16); // HOST_UFO

pub struct VirtioMmio {
    base: usize,
}

#[inline(always)]
fn mmio_fence() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl VirtioMmio {
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    #[inline(always)]
    pub unsafe fn read32(&self, reg: MmioReg) -> u32 {
        core::ptr::read_volatile((self.base + reg as usize) as *const u32)
    }

    #[inline(always)]
    pub unsafe fn write32(&self, reg: MmioReg, val: u32) {
        core::ptr::write_volatile((self.base + reg as usize) as *mut u32, val);
    }

    /// Read `DeviceStatus` and confirm `FEATURES_OK` survived device validation.
    pub unsafe fn verify_features_ok(&self) -> Result<(), ()> {
        mmio_fence();
        let status = self.read32(MmioReg::Status);
        if (status & STATUS_FAILED) != 0 || (status & STATUS_FEATURES_OK) == 0 {
            return Err(());
        }
        Ok(())
    }

    /// Legacy reset + feature pass-through (x86_64 / fallback).
    pub unsafe fn begin_legacy(&self) -> Result<(), ()> {
        if self.read32(MmioReg::Magic) != MAGIC {
            return Err(());
        }

        self.write32(MmioReg::Status, 0);
        let mut status = STATUS_ACK | STATUS_DRIVER;
        self.write32(MmioReg::Status, status);

        self.write32(MmioReg::DeviceFeaturesSel, 0);
        let features = self.read32(MmioReg::DeviceFeatures);
        self.write32(MmioReg::DriverFeaturesSel, 0);
        self.write32(MmioReg::DriverFeatures, features);

        status |= STATUS_FEATURES_OK;
        self.write32(MmioReg::Status, status);
        self.verify_features_ok()
    }

    /// True when this MMIO slot exposes a virtio-net device.
    pub unsafe fn is_net_device(&self) -> bool {
        self.read32(MmioReg::Magic) == MAGIC && self.read32(MmioReg::DeviceId) == DEVICE_NET
    }

    /// VirtIO 1.0 modern handshake — reset → ACK → DRIVER → features → FEATURES_OK.
    pub unsafe fn modern_handshake(&self) -> Result<(), ()> {
        if !self.is_net_device() {
            return Err(());
        }

        self.write32(MmioReg::Status, 0);
        mmio_fence();
        self.write32(MmioReg::Status, STATUS_ACK);
        self.write32(MmioReg::Status, STATUS_ACK | STATUS_DRIVER);

        // Word 0: MAC only — reject offload bits that reject raw 512B frame injection.
        self.write32(MmioReg::DeviceFeaturesSel, 0);
        let features0 = self.read32(MmioReg::DeviceFeatures);
        self.write32(MmioReg::DriverFeaturesSel, 0);
        let driver0 = features0 & VIRTIO_NET_F_MAC & !VIRTIO_NET_OFFLOAD_MASK;
        self.write32(MmioReg::DriverFeatures, driver0);

        // Word 1: VERSION_1 only — split-ring driver (never ack RING_PACKED).
        self.write32(MmioReg::DeviceFeaturesSel, 1);
        let features1 = self.read32(MmioReg::DeviceFeatures);
        self.write32(MmioReg::DriverFeaturesSel, 1);
        let version = self.read32(MmioReg::Version);
        if version >= 2 && (features1 & FEATURE_VERSION_1) == 0 {
            return Err(());
        }
        self.write32(MmioReg::DriverFeatures, FEATURE_VERSION_1);

        let status = self.read32(MmioReg::Status) | STATUS_FEATURES_OK;
        self.write32(MmioReg::Status, status);
        self.verify_features_ok()
    }

    /// Read the six-byte MAC from virtio-net config space (MMIO offset 0x100).
    pub unsafe fn read_net_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        for (i, b) in mac.iter_mut().enumerate() {
            *b = core::ptr::read_volatile((self.base + 0x100 + i) as *const u8);
        }
        mac
    }

    /// Re-verify FEATURES_OK and ensure DRIVER is latched before queue programming.
    pub unsafe fn prepare_queue_config(&self) -> Result<(), ()> {
        self.verify_features_ok()?;
        let status = self.read32(MmioReg::Status);
        if (status & STATUS_DRIVER) == 0 {
            self.write32(MmioReg::Status, status | STATUS_DRIVER);
            mmio_fence();
        }
        self.verify_features_ok()
    }
    /// Set `DRIVER_OK` only after re-verifying `FEATURES_OK` is still latched.
    pub unsafe fn driver_ok(&self) -> Result<(), ()> {
        self.verify_features_ok()?;
        let status = self.read32(MmioReg::Status) | STATUS_DRIVER_OK;
        self.write32(MmioReg::Status, status);
        mmio_fence();
        Ok(())
    }

    /// VirtIO 1.0 queue setup — strict MMIO write order for modern backends.
    pub unsafe fn configure_virtqueue(
        &self,
        queue_index: u32,
        queue_depth: u32,
        desc: u64,
        avail: u64,
        used: u64,
    ) -> Result<u32, ()> {
        // 1. Select queue.
        self.write32(MmioReg::QueueSel, queue_index);
        mmio_fence();

        // 2. Probe capacity; 0 means unavailable.
        let max = self.read32(MmioReg::QueueNumMax);
        if max == 0 {
            return Err(());
        }
        let num = queue_depth.min(max);
        if num == 0 {
            return Err(());
        }

        // 3. Program queue depth.
        self.write32(MmioReg::QueueNum, num);

        // 4. Publish 64-bit guest physical addresses (desc → driver/avail → device/used).
        self.write32(MmioReg::QueueDescLow, desc as u32);
        self.write32(MmioReg::QueueDescHigh, (desc >> 32) as u32);
        self.write32(MmioReg::QueueDriverLow, avail as u32);
        self.write32(MmioReg::QueueDriverHigh, (avail >> 32) as u32);
        self.write32(MmioReg::QueueDeviceLow, used as u32);
        self.write32(MmioReg::QueueDeviceHigh, (used >> 32) as u32);
        mmio_fence();

        // QueueReady is set by configure_virtqueue_dual after optional legacy PFN.
        Ok(num)
    }

    /// Legacy `QueuePFN` @ 0x028 — queue must already be selected via `QueueSel`.
    pub unsafe fn write_legacy_queue_pfn(&self, desc: u64) {
        let desc_pfn = (desc as u32) >> 12;
        self.write32(MmioReg::QueuePFN, desc_pfn);
        mmio_fence();
    }

    /// Modern split-ring pointers + legacy PFN bridge, then activate queue.
    pub unsafe fn configure_virtqueue_dual(
        &self,
        queue_index: u32,
        queue_depth: u32,
        desc: u64,
        avail: u64,
        used: u64,
        legacy_pfn: bool,
    ) -> Result<u32, ()> {
        let num = self.configure_virtqueue(queue_index, queue_depth, desc, avail, used)?;
        if legacy_pfn {
            self.write_legacy_queue_pfn(desc);
        }
        self.write32(MmioReg::QueueReady, 1);
        mmio_fence();
        Ok(num)
    }

    pub unsafe fn notify(&self, queue_index: u32) {
        core::ptr::write_volatile((self.base + MmioReg::QueueNotify as usize) as *mut u32, queue_index);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Acknowledge virtio interrupt status so the backend can make forward progress.
    pub unsafe fn ack_interrupt(&self) {
        let status = self.read32(MmioReg::InterruptStatus);
        if status != 0 {
            self.write32(MmioReg::InterruptACK, status);
            mmio_fence();
        }
    }
}
