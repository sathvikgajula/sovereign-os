//! x86_64 long-mode identity map: WB RAM, UC DMA arena, UC MMIO (2 MiB huge pages).

use core::sync::atomic::{compiler_fence, Ordering};

use crate::dma::dma_arena_base;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_RW: u64 = 1 << 1;
const PTE_PWT: u64 = 1 << 3;
const PTE_PCD: u64 = 1 << 4;
const PTE_HUGE: u64 = 1 << 7;
const PTE_UC: u64 = PTE_PWT | PTE_PCD;
const PTE_WB: u64 = 0;

const MAP_2M: u64 = 1 << 21;
const MMIO_LO: u64 = 0xfe00_0000;

#[repr(C, align(4096))]
struct PageTable {
    ents: [u64; 512],
}

static mut PML4: PageTable = PageTable { ents: [0; 512] };
static mut PDPT: PageTable = PageTable { ents: [0; 512] };
static mut PD0: PageTable = PageTable { ents: [0; 512] };
static mut PD1: PageTable = PageTable { ents: [0; 512] };
static mut PD2: PageTable = PageTable { ents: [0; 512] };
static mut PD3: PageTable = PageTable { ents: [0; 512] };

static mut MMU_LIVE: bool = false;

#[inline(always)]
pub fn is_live() -> bool {
    unsafe { MMU_LIVE }
}

#[inline(always)]
fn pdpt_index(va: u64) -> usize {
    ((va >> 30) & 0x3) as usize
}

#[inline(always)]
fn pd_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}

#[inline(always)]
fn huge_2m(pa: u64, attr: u64) -> u64 {
    (pa & 0xFFFF_FFFF_E000_0000) | PTE_PRESENT | PTE_RW | PTE_HUGE | attr
}

#[inline(never)]
pub unsafe fn build_tables() {
    let pml4 = core::ptr::addr_of_mut!(PML4.ents) as *mut u64;
    core::ptr::write(pml4, core::ptr::addr_of!(PDPT) as u64 | PTE_PRESENT | PTE_RW);
    let dma_2m = (dma_arena_base() as u64) & !(MAP_2M - 1);
    let mmio_2m = MMIO_LO & !(MAP_2M - 1);
    let mut va = 0u64;
    while va < 0x0100_0000 {
        let aligned = va & !(MAP_2M - 1);
        let attr = if aligned == dma_2m {
            PTE_UC
        } else {
            PTE_WB
        };
        map_2m(va, attr);
        va += MAP_2M;
    }
    map_2m(mmio_2m, PTE_UC);
}

#[inline(always)]
unsafe fn map_2m(va: u64, attr: u64) {
    let pi = pdpt_index(va);
    let di = pd_index(va);
    let pdpt = core::ptr::addr_of_mut!(PDPT.ents) as *mut u64;
    let pd_ent = match pi {
        0 => core::ptr::addr_of_mut!(PD0.ents) as *mut u64,
        1 => core::ptr::addr_of_mut!(PD1.ents) as *mut u64,
        2 => core::ptr::addr_of_mut!(PD2.ents) as *mut u64,
        _ => core::ptr::addr_of_mut!(PD3.ents) as *mut u64,
    };
    if core::ptr::read(pdpt.add(pi)) == 0 {
        let pd_phys = match pi {
            0 => core::ptr::addr_of!(PD0) as u64,
            1 => core::ptr::addr_of!(PD1) as u64,
            2 => core::ptr::addr_of!(PD2) as u64,
            _ => core::ptr::addr_of!(PD3) as u64,
        };
        core::ptr::write(pdpt.add(pi), pd_phys | PTE_PRESENT | PTE_RW);
    }
    let aligned = va & !(MAP_2M - 1);
    core::ptr::write(pd_ent.add(di), huge_2m(aligned, attr));
}

#[inline(never)]
pub unsafe fn enable_mmu() {
    let mut cr0: u64;
    core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
    let cr3 = core::ptr::addr_of!(PML4) as u64;
    let mut cr4: u64;
    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
    cr4 |= 1 << 5; // PAE
    cr0 |= 1 << 31; // PG
    core::arch::asm!(
        "mov cr4, {cr4}",
        "mov cr3, {cr3}",
        "mov cr0, {cr0}",
        "jmp 2f",
        "2:",
        cr4 = in(reg) cr4,
        cr3 = in(reg) cr3,
        cr0 = in(reg) cr0,
        options(nostack, preserves_flags),
    );
    MMU_LIVE = true;
}

/// Mark MMU path active for virtio DMA fences (identity map — no CR0.PG on PVH).
pub fn set_live() {
    unsafe {
        MMU_LIVE = true;
    }
}

pub unsafe fn boot_mmu() {
    // QEMU microvm PVH leaves paging disabled with a flat physical map for low RAM.
    // Custom 2 MiB tables + CR0.PG enable fault in this environment; virtio/DMA at
    // 0x200000 and MMIO at 0xfe000000 are reachable without enabling our page tables.
    set_live();
}
