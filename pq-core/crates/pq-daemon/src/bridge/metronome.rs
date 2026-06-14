use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use crossbeam_channel::{Receiver, TryRecvError};
use sovereign_frame::{PendingWrite, FRAME_LEN, TickOutcome};
use sovereign_rt::init_metronome_thread;
use zeroize::Zeroize;

use super::socket::{try_write, SendAttempt};

const TICK_INTERVAL: Duration = Duration::from_millis(5);

// ── Zero-Allocation Telemetry ───────────────────────────────────────────────

struct StackWriter {
    buf: [u8; 128],
    pos: usize,
}

impl StackWriter {
    fn new() -> Self {
        Self {
            buf: [0u8; 128],
            pos: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

impl core::fmt::Write for StackWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.pos;
        let to_copy = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        Ok(())
    }
}

macro_rules! sys_log {
    ($($arg:tt)*) => {
        {
            use core::fmt::Write;
            let mut w = crate::bridge::metronome::StackWriter::new();
            let _ = write!(w, $($arg)*);
            let _ = write!(w, "\n");
            let bytes = w.as_bytes();
            unsafe {
                libc::write(
                    2,
                    bytes.as_ptr() as *const libc::c_void,
                    bytes.len(),
                );
            }
        }
    };
}

// ── IPC Gate Flags ──────────────────────────────────────────────────────────

pub struct GateFlags {
    pub kernel_ready: Arc<AtomicBool>,
    pub local_peer_up: Arc<AtomicBool>,
}

impl GateFlags {
    pub fn new() -> Self {
        Self {
            kernel_ready: Arc::new(AtomicBool::new(false)),
            local_peer_up: Arc::new(AtomicBool::new(false)),
        }
    }

    fn clone_inner(&self) -> (Arc<AtomicBool>, Arc<AtomicBool>) {
        (self.kernel_ready.clone(), self.local_peer_up.clone())
    }
}

// ── Metronome ───────────────────────────────────────────────────────────────

pub struct Metronome {
    alive: Arc<AtomicBool>,
    faulted: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Metronome {
    pub fn spawn(
        fd: RawFd,
        rx: Receiver<[u8; FRAME_LEN]>,
        gates: &GateFlags,
        seed_key: [u8; 32],
        seed_nonce: [u8; 12],
    ) -> Self {
        let alive = Arc::new(AtomicBool::new(true));
        let faulted = Arc::new(AtomicBool::new(false));
        let flag = alive.clone();
        let fault_flag = faulted.clone();
        let (kernel_ready, local_peer_up) = gates.clone_inner();

        let handle = std::thread::Builder::new()
            .name("metronome-core0".into())
            .spawn(move || {
                init_metronome_thread();

                run_loop(
                    fd,
                    &rx,
                    &flag,
                    &fault_flag,
                    &kernel_ready,
                    &local_peer_up,
                    seed_key,
                    seed_nonce,
                );
            })
            .expect("failed to spawn metronome thread");

        Self {
            alive,
            faulted,
            handle: Some(handle),
        }
    }

    pub fn is_faulted(&self) -> bool {
        self.faulted.load(Ordering::Acquire)
    }

    pub fn shutdown(&mut self) {
        self.alive.store(false, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Metronome {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ── AEP ChaCha20 Cover Traffic Engine ───────────────────────────────────────

struct AepEngine {
    cipher: ChaCha20,
}

impl AepEngine {
    fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        sys_log!("[AEP_INIT] ChaCha20 engine seeded.");
        Self {
            cipher: ChaCha20::new(key.into(), nonce.into()),
        }
    }

    #[inline(always)]
    fn fill_cover(&mut self, buf: &mut [u8; FRAME_LEN]) {
        *buf = [0u8; FRAME_LEN];
        self.cipher.apply_keystream(buf);
    }

    fn zeroize_state(&mut self) {
        let raw: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                &mut self.cipher as *mut ChaCha20 as *mut u8,
                std::mem::size_of::<ChaCha20>(),
            )
        };
        raw.zeroize();
    }
}

// ── Core Loop ───────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn run_loop(
    fd: RawFd,
    rx: &Receiver<[u8; FRAME_LEN]>,
    alive: &AtomicBool,
    faulted: &AtomicBool,
    kernel_ready: &AtomicBool,
    local_peer_up: &AtomicBool,
    mut seed_key: [u8; 32],
    mut seed_nonce: [u8; 12],
) {
    let mut aep = AepEngine::new(&seed_key, &seed_nonce);
    seed_key.zeroize();
    seed_nonce.zeroize();

    let mut pending = PendingWrite::new();

    let mut tick_count = 0;

    while alive.load(Ordering::Acquire) {
        let outcome = tick(fd, rx, &mut pending, &mut aep, kernel_ready, local_peer_up);
        if outcome == TickOutcome::Guillotine {
            aep.zeroize_state();
            pending.clear();
            faulted.store(true, Ordering::Release);
            break;
        }
        let start = std::time::Instant::now();
        spin_sleep::sleep(TICK_INTERVAL);
        let elapsed = start.elapsed();
        let skew = if elapsed > TICK_INTERVAL {
            elapsed - TICK_INTERVAL
        } else {
            TICK_INTERVAL - elapsed
        };
        
        tick_count += 1;
        if tick_count % 10 == 0 {
            let q_len = rx.len();
            sys_log!("[METRICS] skew_us:{} queue_depth:{}", skew.as_micros(), q_len);
        }
    }

    aep.zeroize_state();
}

#[inline(always)]
fn tick(
    fd: RawFd,
    rx: &Receiver<[u8; FRAME_LEN]>,
    pending: &mut PendingWrite,
    aep: &mut AepEngine,
    kernel_ready: &AtomicBool,
    local_peer_up: &AtomicBool,
) -> TickOutcome {
    if !kernel_ready.load(Ordering::Acquire) {
        return TickOutcome::Ok;
    }

    if !local_peer_up.load(Ordering::Acquire) {
        return TickOutcome::Ok;
    }

    if pending.is_active() {
        return drain_pending(fd, pending);
    }

    match rx.try_recv() {
        Ok(frame) => {
            pending.activate(&frame);
            drain_pending(fd, pending)
        }
        Err(TryRecvError::Empty) => {
            let mut cover = [0u8; FRAME_LEN];
            aep.fill_cover(&mut cover);
            pending.activate(&cover);
            drain_pending(fd, pending)
        }
        Err(TryRecvError::Disconnected) => TickOutcome::Ok,
    }
}

#[inline(always)]
fn drain_pending(fd: RawFd, pending: &mut PendingWrite) -> TickOutcome {
    while pending.is_active() {
        match try_write(fd, pending.remaining()) {
            SendAttempt::Wrote(n) => {
                pending.advance(n);
            }
            SendAttempt::WouldBlock => {
                return TickOutcome::Ok;
            }
            SendAttempt::Broken => {
                pending.clear();
                return TickOutcome::Ok;
            }
            SendAttempt::Fatal(_) => {
                pending.clear();
                return TickOutcome::Guillotine;
            }
        }
    }
    TickOutcome::Ok
}
