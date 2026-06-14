//! No-op RT policy for platforms without a dedicated backend.

use crate::log::rt_log_fmt;

pub fn apply_rt_policy() {
    rt_log_fmt(format_args!(
        "[METRONOME] No platform RT policy available on this target."
    ));
}
