//! Hardware abstraction: timestamps, CPU pause, cache-line constants, core pinning.

#![cfg_attr(not(feature = "std"), no_std)]

pub const CACHE_LINE: usize = 64;

pub mod arch;

/// HAL-level errors for platform setup routines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalError {
    NoCoresAvailable,
    PinFailed,
    Unsupported,
}

/// Pin the calling thread to `core_id` when OS affinity APIs are available.
#[cfg(feature = "std")]
pub fn pin_current_thread(core_id: usize) -> Result<(), HalError> {
    let cores = core_affinity::get_core_ids().unwrap_or_default();
    if cores.is_empty() {
        return Err(HalError::NoCoresAvailable);
    }

    let target = cores
        .iter()
        .find(|c| c.id == core_id)
        .copied()
        .or_else(|| cores.first().copied())
        .ok_or(HalError::NoCoresAvailable)?;

    if core_affinity::set_for_current(target) {
        Ok(())
    } else {
        Err(HalError::PinFailed)
    }
}

/// Bare-metal / no-std builds cannot pin threads without a platform scheduler.
#[cfg(not(feature = "std"))]
pub fn pin_current_thread(_core_id: usize) -> Result<(), HalError> {
    Err(HalError::Unsupported)
}
