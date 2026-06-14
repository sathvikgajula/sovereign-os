//! Architecture-specific boot notes (PVH on x86_64 microvm).

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
core::arch::global_asm!(
    r#"
    .section .note.pvh, "a", @note
    .align 4
    .long 2f - 1f
    .long 4f - 3f
    .long 0x12
1:  .asciz "qemu"
2:  .align 4
3:  .long 0x10
    .long 0x100000
4:
    "#,
);
