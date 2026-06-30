//! AArch64 EL1 identity map: normal WB RAM, NC DMA arena, device MMIO.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::dma::DMA_ARENA_BASE;

const ATTR_NORMAL_WB: u64 = 0;
const ATTR_NORMAL_NC: u64 = 1;
const ATTR_DEVICE: u64 = 2;

const PTE_VALID: u64 = 1 << 0;
const PTE_TABLE: u64 = 1 << 1;
const PTE_BLOCK: u64 = 1 << 0;
const PTE_AF: u64 = 1 << 10;
const PTE_SH_INNER: u64 = 0b11 << 8;

const RAM_START: u64 = 0x4000_0000;
const RAM_END: u64 = 0x5000_0000;
const MMIO_LO: u64 = 0x0800_0000;
const MMIO_HI: u64 = 0x0c00_0000;

const RAM_SLOTS: u32 = ((RAM_END - RAM_START) >> 21) as u32;
const MMIO_SLOTS: u32 = ((MMIO_HI - (MMIO_LO & !0x1F_FFFF)) >> 21) as u32;
const LOW_WB_SLOTS: u32 = (MMIO_LO >> 21) as u32;

#[repr(C, align(4096))]
struct PageTable {
    ents: [u64; 512],
}

static mut L1: PageTable = PageTable { ents: [0; 512] };
static mut L2_RAM: PageTable = PageTable { ents: [0; 512] };
static mut L2_MMIO: PageTable = PageTable { ents: [0; 512] };

#[repr(C, align(2048))]
struct VectorTable {
    code: [u32; 512],
}

#[used]
#[link_section = ".text.vectors"]
static EL1_VECTORS: VectorTable = VectorTable {
    code: [0x1400_0000; 512],
};

static mut MMU_LIVE: bool = false;

#[inline(always)]
pub fn is_live() -> bool {
    unsafe { MMU_LIVE }
}

#[inline(always)]
fn l2_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}

#[inline(always)]
fn l2_block(pa: u64, attr_idx: u64) -> u64 {
    (pa & 0xFFFF_FFFF_E000_0000) | PTE_BLOCK | PTE_AF | PTE_SH_INNER | (attr_idx << 2)
}

unsafe fn clean_dcache(start: usize, end: usize) {
    if end <= start {
        return;
    }
    let mut ctr: usize;
    core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr);
    let line = 4 << ((ctr >> 16) & 0xf);
    let mut addr = start & !(line - 1);
    while addr < end {
        core::arch::asm!("dc cvac, {}", in(reg) addr);
        addr += line;
    }
    core::arch::asm!("dsb ish", options(nostack, preserves_flags));
}

#[inline(never)]
pub unsafe fn build_tables() {
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(L2_RAM) as *mut u8,
        0,
        core::mem::size_of::<PageTable>(),
    );
    core::ptr::write_bytes(
        core::ptr::addr_of_mut!(L2_MMIO) as *mut u8,
        0,
        core::mem::size_of::<PageTable>(),
    );

    let ram_ents = core::ptr::addr_of_mut!(L2_RAM.ents) as *mut u64;
    core::ptr::write(ram_ents, l2_block(RAM_START, ATTR_NORMAL_WB));

    let mut slot = 1u32;
    while slot < RAM_SLOTS {
        let pa = RAM_START + ((slot as u64) << 21);
        let idx = l2_index(pa);
        let attr = if pa == (DMA_ARENA_BASE as u64 & !0x1F_FFFF) {
            ATTR_NORMAL_NC
        } else {
            ATTR_NORMAL_WB
        };
        core::ptr::write(ram_ents.add(idx), l2_block(pa, attr));
        compiler_fence(Ordering::SeqCst);
        slot += 1;
    }

    let mmio_ents = core::ptr::addr_of_mut!(L2_MMIO.ents) as *mut u64;
    slot = 0;
    while slot < LOW_WB_SLOTS {
        let pa = (slot as u64) << 21;
        core::ptr::write(mmio_ents.add(slot as usize), l2_block(pa, ATTR_NORMAL_WB));
        compiler_fence(Ordering::SeqCst);
        slot += 1;
    }
    slot = 0;
    while slot < MMIO_SLOTS {
        let pa = (MMIO_LO & !0x1F_FFFF) + ((slot as u64) << 21);
        let idx = l2_index(pa);
        core::ptr::write(mmio_ents.add(idx), l2_block(pa, ATTR_DEVICE));
        compiler_fence(Ordering::SeqCst);
        slot += 1;
    }

    let l2_ram_phys = core::ptr::addr_of!(L2_RAM) as u64;
    let l2_mmio_phys = core::ptr::addr_of!(L2_MMIO) as u64;
    let l1 = core::ptr::addr_of_mut!(L1.ents) as *mut u64;
    core::ptr::write(l1, l2_mmio_phys | PTE_TABLE | PTE_VALID);
    core::ptr::write(l1.add(1), l2_ram_phys | PTE_TABLE | PTE_VALID);
    compiler_fence(Ordering::SeqCst);

    let pt_lo = core::ptr::addr_of!(L1) as usize;
    let pt_hi = pt_lo + core::mem::size_of::<PageTable>() * 3;
    clean_dcache(pt_lo, pt_hi);
}

/// Enable EL1 MMU in one asm block: TLB invalidate, M then C|I, I-cache invalidate.
#[inline(never)]
pub unsafe fn enable_mmu() {
    let vbar = core::ptr::addr_of!(EL1_VECTORS) as u64;
    let mair = (0xFFu64 << (8 * ATTR_NORMAL_WB))
        | (0x44u64 << (8 * ATTR_NORMAL_NC))
        | (0x00u64 << (8 * ATTR_DEVICE));
    // T0SZ=25, inner/outer WB walks, TG0=4KiB, TTBR1 disabled (EPD1).
    let tcr: u64 = 25 | (0b01 << 8) | (0b01 << 10) | (1 << 23);
    let ttbr = core::ptr::addr_of!(L1) as u64;

    let mut sctlr_m: u64;
    let mut sctlr_ci: u64;
    core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr_m);
    sctlr_ci = sctlr_m;
    sctlr_m &= !0x1005;
    sctlr_m |= 0x0001;
    sctlr_ci |= 0x1004;

    // FP/SIMD at EL1 — rustc may emit NEON (e.g. smoltcp struct moves).
    let cpacr: u64 = 1 << 20;

    core::arch::asm!(
        "msr vbar_el1, {vbar}",
        "isb",
        "msr mair_el1, {mair}",
        "isb",
        "msr tcr_el1, {tcr}",
        "isb",
        "msr ttbr0_el1, {ttbr}",
        "dsb ishst",
        "isb",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        "msr cpacr_el1, {cpacr}",
        "isb",
        "msr sctlr_el1, {sctlr_m}",
        "dsb ish",
        "isb",
        "ic iallu",
        "dsb ish",
        "isb",
        "msr sctlr_el1, {sctlr_ci}",
        "dsb ish",
        "isb",
        vbar = in(reg) vbar,
        mair = in(reg) mair,
        tcr = in(reg) tcr,
        ttbr = in(reg) ttbr,
        cpacr = in(reg) cpacr,
        sctlr_m = in(reg) sctlr_m,
        sctlr_ci = in(reg) sctlr_ci,
        options(nostack, preserves_flags),
    );
    MMU_LIVE = true;
}

pub unsafe fn init() {
    build_tables();
    enable_mmu();
}
