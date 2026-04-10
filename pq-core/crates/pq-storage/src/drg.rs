use anyhow::Result;
use blake3::Hasher;
use std::time::Duration;

/// Sequential DRG Evaluator
pub struct DrgGraph {
    pub nodes: Vec<[u8; 32]>,
}

impl DrgGraph {
    /// Generate a sequential Depth Robust Graph path using BLAKE3.
    /// Traps parallel execution by forcing H_i = Hash(Data_i || H_{i-1}).
    pub fn build(data_blocks: &[&[u8]], seed: &[u8; 32]) -> Self {
        let mut nodes = Vec::with_capacity(data_blocks.len());
        let mut prev_hash = *seed;

        for block in data_blocks {
            let mut hasher = Hasher::new();
            hasher.update(block);
            hasher.update(&prev_hash);
            
            prev_hash = hasher.finalize().into();
            nodes.push(prev_hash);
        }

        Self { nodes }
    }

    pub fn root(&self) -> Option<[u8; 32]> {
        self.nodes.last().copied()
    }

    pub fn get_leaf(&self, index: usize) -> Option<[u8; 32]> {
        self.nodes.get(index).copied()
    }
}

/// Calculate the T_max constraint for the Spot Check.
/// T_max = µ_ping + 3*σ_jitter + 50ms
pub fn calculate_t_max(mu_ping: Duration, sigma_jitter: Duration) -> Duration {
    mu_ping + (sigma_jitter * 3) + Duration::from_millis(50)
}

/// A Spot Check Challenge containing random indices to prove.
pub struct SpotCheckChallenge {
    pub indices: Vec<usize>,
}

impl SpotCheckChallenge {
    pub fn new(indices: Vec<usize>) -> Self {
        Self { indices }
    }
}

/// Verifies a spot check challenge against the expected response.
/// Prover must return the 3 leaf hashes. We verify the time elapsed is <= T_max.
pub fn verify_spot_check(
    expected_leaves: &[[u8; 32]],
    provided_leaves: &[[u8; 32]],
    elapsed_time: Duration,
    t_max: Duration,
) -> bool {
    // Late math is deleted math
    if elapsed_time > t_max {
        return false;
    }

    if expected_leaves.len() != provided_leaves.len() {
        return false;
    }

    for (expected, provided) in expected_leaves.iter().zip(provided_leaves.iter()) {
        if expected != provided {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_drg_sequential_hashing() {
        let data1 = b"block1";
        let data2 = b"block2";
        let seed = [0u8; 32];
        let graph = DrgGraph::build(&[&data1[..], &data2[..]], &seed);

        assert_eq!(graph.nodes.len(), 2);
    }

    #[test]
    fn test_lazy_node_fails_verification_window() {
        // T_max parameters
        let mu_ping = Duration::from_millis(30);
        let sigma_jitter = Duration::from_millis(10);
        let t_max = calculate_t_max(mu_ping, sigma_jitter); // 30 + 30 + 50 = 110ms

        let expected_leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let provided_leaves = expected_leaves.clone();

        // Simulate lazy node 2.0s sleep
        let start = Instant::now();
        std::thread::sleep(Duration::from_secs(2)); // Lazy evaluation
        let elapsed = start.elapsed();

        let is_valid = verify_spot_check(&expected_leaves, &provided_leaves, elapsed, t_max);
        
        assert!(!is_valid, "Lazy node successfully bypassed the T_max window! This is a hard failure.");
    }
    
    #[test]
    fn test_honest_node_passes_verification_window() {
        let mu_ping = Duration::from_millis(30);
        let sigma_jitter = Duration::from_millis(10);
        let t_max = calculate_t_max(mu_ping, sigma_jitter); // 110ms

        let expected_leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let provided_leaves = expected_leaves.clone();

        let is_valid = verify_spot_check(&expected_leaves, &provided_leaves, Duration::from_millis(110), t_max);
        assert!(is_valid);
        
        let is_valid_late = verify_spot_check(&expected_leaves, &provided_leaves, Duration::from_millis(111), t_max);
        assert!(!is_valid_late);
    }
}
