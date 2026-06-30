//! Architecture-specific MMU setup.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub mod aarch64;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod x86_64;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use aarch64::init as init_aarch64;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use x86_64::boot_mmu as init_x86_64;
