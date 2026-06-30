/* x86_64 QEMU microvm PVH kernel — DMA arena then stack in low RAM. */
ENTRY(_start)

SECTIONS
{
    . = 0x100000;

    .text : ALIGN(4K) {
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    .note.pvh : {
        KEEP(*(.note.pvh))
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

    .dma_arena (NOLOAD) : ALIGN(4K) {
        __dma_arena_start = .;
        *(.dma_arena)
        . = ALIGN(4096);
        __dma_arena_end = .;
    }

    . = ALIGN(16);
    __stack_bottom = .;
    . += 0x80000;
    __stack_top = .;
}
