//! macOS / Darwin Mach `THREAD_TIME_CONSTRAINT_POLICY` real-time scheduling.

use crate::log::rt_log_fmt;

const KERN_SUCCESS: i32 = 0;
const THREAD_TIME_CONSTRAINT_POLICY: u32 = 2;
const THREAD_TIME_CONSTRAINT_POLICY_COUNT: u32 = 4;

const PERIOD_NS: u64 = 200_000_000;
const COMPUTATION_NS: u64 = 500_000;
const CONSTRAINT_NS: u64 = 2_000_000;

#[repr(C)]
struct mach_timebase_info_data_t {
    numer: u32,
    denom: u32,
}

#[repr(C)]
struct thread_time_constraint_policy_data_t {
    period: u32,
    computation: u32,
    constraint: u32,
    preemptible: u32,
}

extern "C" {
    fn mach_task_self() -> u32;
    fn mach_thread_self() -> u32;
    fn mach_timebase_info(info: *mut mach_timebase_info_data_t) -> i32;
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
    fn thread_policy_set(
        thread: u32,
        flavor: u32,
        policy_info: *const i32,
        count: u32,
    ) -> i32;
}

#[inline]
fn ns_to_mach(ns: u64, numer: u32, denom: u32) -> u32 {
    let ticks = (ns as u128) * (denom as u128) / (numer as u128);
    ticks as u32
}

fn emit_mach_error(call: &str, kr: i32) {
    rt_log_fmt(format_args!("[METRONOME] {} failed: kern_return={}", call, kr));
}

/// Apply Mach thread time-constraint policy (200 ms period, 500 µs computation budget).
pub fn apply_mach_realtime() {
    let mut info = mach_timebase_info_data_t { numer: 0, denom: 0 };

    let kr = unsafe { mach_timebase_info(&mut info) };
    if kr != KERN_SUCCESS {
        emit_mach_error("mach_timebase_info", kr);
        return;
    }

    if info.numer == 0 {
        emit_mach_error("mach_timebase_info(numer==0)", -1);
        return;
    }

    let policy = thread_time_constraint_policy_data_t {
        period: ns_to_mach(PERIOD_NS, info.numer, info.denom),
        computation: ns_to_mach(COMPUTATION_NS, info.numer, info.denom),
        constraint: ns_to_mach(CONSTRAINT_NS, info.numer, info.denom),
        preemptible: 1,
    };

    let thread_port = unsafe { mach_thread_self() };

    let kr = unsafe {
        thread_policy_set(
            thread_port,
            THREAD_TIME_CONSTRAINT_POLICY,
            &policy as *const thread_time_constraint_policy_data_t as *const i32,
            THREAD_TIME_CONSTRAINT_POLICY_COUNT,
        )
    };

    unsafe {
        mach_port_deallocate(mach_task_self(), thread_port);
    }

    if kr != KERN_SUCCESS {
        emit_mach_error("thread_policy_set", kr);
    } else {
        rt_log_fmt(format_args!("[HW_LOCK] Mach RT Thread Policy applied."));
    }
}
