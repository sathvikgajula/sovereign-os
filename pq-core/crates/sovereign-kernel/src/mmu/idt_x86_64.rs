//! Minimal x86_64 IDT — virtio IRQ without a full interrupt subsystem.

use core::mem::MaybeUninit;

#[repr(C, packed)]
struct IdtEntry {
    offset_lo: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_hi: u32,
    zero: u32,
}

static mut IDT: MaybeUninit<[IdtEntry; 256]> = MaybeUninit::uninit();

#[unsafe(naked)]
unsafe extern "C" fn virtio_irq_stub() {
    core::arch::naked_asm!("iretq");
}

static mut IRQ_READY: bool = false;

fn code_selector() -> u16 {
    let cs: u64;
    unsafe {
        core::arch::asm!("mov {0}, cs", out(reg) cs, options(nostack, preserves_flags));
    }
    cs as u16
}

unsafe fn set_gate(idt: &mut [IdtEntry; 256], vector: usize, handler: usize) {
    let cs = code_selector();
    let ent = &mut idt[vector];
    ent.offset_lo = handler as u16;
    ent.selector = cs;
    ent.ist = 0;
    ent.type_attr = 0x8E;
    ent.offset_mid = (handler >> 16) as u16;
    ent.offset_hi = (handler >> 32) as u32;
    ent.zero = 0;
}

/// Install a no-op handler for external IRQ vectors used by virtio-mmio.
pub unsafe fn init_irq() {
    if IRQ_READY {
        return;
    }
    let idt = IDT.write([const {
        IdtEntry {
            offset_lo: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_hi: 0,
            zero: 0,
        }
    }; 256]);
    let handler = virtio_irq_stub as usize;
    for vector in 32usize..48usize {
        set_gate(idt, vector, handler);
    }
    let limit = (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16;
    let base = idt.as_ptr() as u64;
    let mut idtr = [0u8; 10];
    idtr[..2].copy_from_slice(&limit.to_le_bytes());
    idtr[2..10].copy_from_slice(&base.to_le_bytes());
    core::arch::asm!("lidt [{0}]", in(reg) idtr.as_ptr(), options(readonly, nostack, preserves_flags));
    IRQ_READY = true;
}
