//! Architecture-specific MMU setup.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub mod aarch64;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use aarch64::init as init_aarch64;
