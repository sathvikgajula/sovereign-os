use blake3::hash;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbltEntry {
    pub count: i32,
    pub key_sum: [u8; 32],
    pub hash_sum: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbltSketch {
    pub cells: Vec<IbltEntry>,
}

pub struct Iblt {
    size: usize,
}

impl Iblt {
    pub fn new(size: usize) -> Self {
        Self { size }
    }

    /// Generates a "Blurry" IBLT sketch for privacy-preserving re-sync.
    /// Action: 15% of cells are injected with false-positive noise.
    pub fn generate_blurry_sketch(&self, data: &[[u8; 32]]) -> IbltSketch {
        let mut cells = vec![IbltEntry { count: 0, key_sum: [0u8; 32], hash_sum: [0u8; 32] }; self.size];
        let mut rng = rand::thread_rng();

        // 1. Map data into IBLT cells
        for cid in data {
            let idx = (hash(cid).as_bytes()[0] as usize) % self.size;
            cells[idx].count += 1;
            for i in 0..32 {
                cells[idx].key_sum[i] ^= cid[i];
                cells[idx].hash_sum[i] ^= hash(cid).as_bytes()[i];
            }
        }

        // 2. Inject 15% False-Positive Blur
        let blur_count = (self.size as f64 * 0.15) as usize;
        for _ in 0..blur_count {
            let idx = rng.gen_range(0..self.size);
            // Inject entropy to "blur" the counts and sums
            cells[idx].count += 1;
            let mut noise = [0u8; 32];
            rng.fill(&mut noise);
            for i in 0..32 {
                cells[idx].key_sum[i] ^= noise[i];
            }
        }

        IbltSketch { cells }
    }
}
