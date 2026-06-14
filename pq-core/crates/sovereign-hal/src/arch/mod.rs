//! Architecture-specific timestamp and spin-hint primitives.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod generic;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{cpu_pause, read_timestamp};
#[cfg(target_arch = "aarch64")]
pub use aarch64::{cpu_pause, read_timestamp, read_timestamp_freq_hz};
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use generic::{cpu_pause, read_timestamp};
