/* x86_64 QEMU PC-class kernel layout (q35 / microvm PVH) */
ENTRY(_start)

SECTIONS
{
    . = 0x100000;

    .text : ALIGN(4K) {
        KEEP(*(.text.boot))
        KEEP(*(.note.pvh))
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K) {
        *(.data .data.*)
    }

    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    .uninit_pool (NOLOAD) : ALIGN(4K) {
        *(.uninit_pool)
    }

    . = ALIGN(16);
    __stack_bottom = .;
    . += 0x40000;
    __stack_top = .;
}
