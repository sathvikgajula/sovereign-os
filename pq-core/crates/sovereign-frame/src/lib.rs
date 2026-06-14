//! `#![no_std]` 512-byte metronome frame state machine (allocation-free hot path).

#![no_std]

pub mod metronome;

pub const FRAME_LEN: usize = 512;

pub use metronome::{run_loop, Egress, MetronomeTimer, heartbeat_frame};

/// Outcome of a single metronome tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    Ok,
    Guillotine,
}

/// Partial-frame egress buffer for non-blocking socket writes.
pub struct PendingWrite {
    active: bool,
    offset: u16,
    buf: [u8; FRAME_LEN],
}

impl PendingWrite {
    pub const fn new() -> Self {
        Self {
            active: false,
            offset: 0,
            buf: [0u8; FRAME_LEN],
        }
    }

    #[inline(always)]
    pub fn is_active(&self) -> bool {
        self.active
    }

    #[inline(always)]
    pub fn remaining(&self) -> &[u8] {
        &self.buf[self.offset as usize..FRAME_LEN]
    }

    #[inline(always)]
    pub fn remaining_len(&self) -> usize {
        FRAME_LEN - self.offset as usize
    }

    #[inline(always)]
    pub fn activate(&mut self, src: &[u8; FRAME_LEN]) {
        self.buf.copy_from_slice(src);
        self.offset = 0;
        self.active = true;
    }

    #[inline(always)]
    pub fn advance(&mut self, n: usize) {
        let new_offset = self.offset as usize + n;
        if new_offset >= FRAME_LEN {
            self.clear();
        } else {
            self.offset = new_offset as u16;
        }
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.active = false;
        self.offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_write_roundtrip() {
        let mut p = PendingWrite::new();
        let frame = [0xABu8; FRAME_LEN];
        p.activate(&frame);
        assert!(p.is_active());
        p.advance(FRAME_LEN);
        assert!(!p.is_active());
    }
}
