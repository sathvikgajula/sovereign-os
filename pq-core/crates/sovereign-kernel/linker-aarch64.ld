/* AArch64 QEMU `virt` — RAM base load address for `-kernel` handoff */
ENTRY(_start)

SECTIONS
{
    . = 0x40000000;

    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Allocator arena — not zeroed at boot (32 MiB). */
    .uninit_pool (NOLOAD) : {
        . = ALIGN(4096);
        *(.uninit_pool)
    }

    . = ALIGN(4096);
    __stack_bottom = .;
    . += 0x100000;
    __stack_top = .;
}
