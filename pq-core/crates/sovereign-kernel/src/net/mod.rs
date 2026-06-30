//! Minimal smoltcp stack over virtio-net (aarch64).

mod device;
mod stack;

pub use stack::{inject_udp_selftest, poll_stack, init_stack};
