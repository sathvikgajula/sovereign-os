//! Linux POSIX real-time scheduling via `SCHED_FIFO` priority 99.

use crate::log::rt_log_fmt;

const RT_PRIORITY: i32 = 99;

/// Apply `SCHED_FIFO` at maximum user priority. Requires `CAP_SYS_NICE` or root.
pub fn apply_sched_fifo() {
    unsafe {
        let param = libc::sched_param {
            sched_priority: RT_PRIORITY,
        };
        let ret = libc::sched_setscheduler(0, libc::SCHED_FIFO, &param);
        if ret != 0 {
            let errno = *libc::__errno_location();
            rt_log_fmt(format_args!(
                "[METRONOME] sched_setscheduler(SCHED_FIFO, prio={}) failed: errno={} \
                 (grant CAP_SYS_NICE or run as root for RT policy)",
                RT_PRIORITY, errno
            ));
        } else {
            rt_log_fmt(format_args!(
                "[HW_LOCK] Linux SCHED_FIFO priority {} applied.",
                RT_PRIORITY
            ));
        }
    }
}
