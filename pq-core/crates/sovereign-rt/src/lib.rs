//! Cross-platform real-time thread initialization for the Sovereign metronome.

mod log;

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod stub;

#[cfg(target_os = "macos")]
use darwin::apply_mach_realtime as apply_platform_rt;
#[cfg(target_os = "linux")]
use linux::apply_sched_fifo as apply_platform_rt;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use stub::apply_rt_policy as apply_platform_rt;

/// Pin to Core 0 and apply the platform real-time scheduling policy.
///
/// Must be called once from the metronome thread **before** entering `run_loop`.
/// This path may allocate/log; it is never invoked from `tick()` / `drain_pending()`.
pub fn init_metronome_thread() {
    sovereign_alloc::enter_metronome_thread();

    match sovereign_hal::pin_current_thread(0) {
        Ok(()) => log::rt_log_fmt(format_args!("[ULTRA] Metronome pinned to Core 0")),
        Err(e) => log::rt_log_fmt(format_args!("[METRONOME] Core pin failed: {:?}", e)),
    }

    apply_platform_rt();

    #[cfg(all(feature = "std", target_os = "macos"))]
    {
        if let Err(e) =
            thread_priority::set_current_thread_priority(thread_priority::ThreadPriority::Max)
        {
            log::rt_log_fmt(format_args!("[METRONOME] thread_priority elevation failed: {:?}", e));
        }
    }
}
