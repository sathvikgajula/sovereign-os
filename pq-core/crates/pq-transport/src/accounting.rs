use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Cryptographically signed Bandwidth Voucher per 64KB Data Batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Voucher {
    pub relay_id: String,
    pub timestamp: u64,
    pub data_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct PeerAccounting {
    pub incoming_bytes: u64,
    pub outgoing_bytes: u64,
    pub missed_vouchers: u32,
}

impl PeerAccounting {
    fn debt_ratio(&self) -> f64 {
        if self.outgoing_bytes == 0 {
            return 0.0;
        }
        self.incoming_bytes as f64 / self.outgoing_bytes as f64
    }
}

/// Tracking mechanism for Bandwidth constraints and Vouchers.
#[derive(Clone, Default)]
pub struct BandwidthTracker {
    peers: Arc<Mutex<HashMap<String, PeerAccounting>>>,
}

impl BandwidthTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add incoming bytes (bytes we consumed from them).
    pub fn add_incoming(&self, peer_did: &str, bytes: u64) {
        let mut map = self.peers.lock().unwrap();
        let acc = map.entry(peer_did.to_string()).or_default();
        acc.incoming_bytes += bytes;
    }

    /// Add outgoing bytes (bytes they consumed from us).
    pub fn add_outgoing(&self, peer_did: &str, bytes: u64) {
        let mut map = self.peers.lock().unwrap();
        let acc = map.entry(peer_did.to_string()).or_default();
        acc.outgoing_bytes += bytes;
    }

    /// Log a missing voucher for a 64KB batch. Returns true if they exceeded the limit.
    pub fn log_missing_voucher(&self, peer_did: &str) -> bool {
        let mut map = self.peers.lock().unwrap();
        let acc = map.entry(peer_did.to_string()).or_default();
        acc.missed_vouchers += 1;
        acc.missed_vouchers >= 3
    }
    
    /// Reset the missed vouchers (on successful valid voucher receipt).
    pub fn reset_missing_voucher(&self, peer_did: &str) {
        let mut map = self.peers.lock().unwrap();
        let acc = map.entry(peer_did.to_string()).or_default();
        acc.missed_vouchers = 0;
    }

    /// Check if peer has exceeded MAX_DEBT ratio.
    /// Ratio = incoming / outgoing. If they consumed much more than they provided.
    /// MAX_DEBT ratio is e.g. 5.0 (they downloaded 5x more than they uploaded).
    pub fn is_max_debt_exceeded(&self, peer_did: &str, max_debt_ratio: f64, grace_bytes: u64) -> bool {
        let map = self.peers.lock().unwrap();
        if let Some(acc) = map.get(peer_did) {
            // Give them a grace window (e.g. 10MB) before we care about ratio
            if acc.outgoing_bytes < grace_bytes {
                return false;
            }
            return acc.debt_ratio() > max_debt_ratio;
        }
        false
    }
}
