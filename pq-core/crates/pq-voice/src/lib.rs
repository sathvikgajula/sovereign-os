use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tokio::sync::mpsc;
use tracing::{info, warn};

pub mod handshake;

pub const VOICE_FRAME_SIZE: usize = 1200;

/// Stream health status.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamHealth {
    Active,
    Muted { reason: String },
}

/// Splits a 1200-byte CBR audio frame into two XORed streams (Noise and Audio⊕Noise).
pub struct XorStreamSplitter {
    rng: StdRng,
}

impl XorStreamSplitter {
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
        }
    }

    /// Split a 1200-byte frame into (stream_a, stream_b).
    pub fn split_frame(&mut self, audio: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if audio.len() > VOICE_FRAME_SIZE {
            return Err(anyhow!("Audio frame too large"));
        }

        let mut a_frame = vec![0u8; VOICE_FRAME_SIZE];
        a_frame[..audio.len()].copy_from_slice(audio);

        let mut noise = vec![0u8; VOICE_FRAME_SIZE];
        self.rng.fill_bytes(&mut noise);

        let mut xor_frame = vec![0u8; VOICE_FRAME_SIZE];
        for i in 0..VOICE_FRAME_SIZE {
            xor_frame[i] = a_frame[i] ^ noise[i];
        }

        // stream1 = noise, stream2 = audio ^ noise
        Ok((noise, xor_frame))
    }
}

impl Default for XorStreamSplitter {
    fn default() -> Self {
        Self::new()
    }
}

/// Reassembles two streams back into the original audio.
/// Implements "Mute-on-loss": if either stream is missing a frame, outputs silence.
pub struct XorStreamReassembler {
    health: StreamHealth,
}

impl XorStreamReassembler {
    pub fn new() -> Self {
        Self {
            health: StreamHealth::Active,
        }
    }

    pub fn reassemble_frame(
        &mut self,
        stream1: Option<&[u8]>,
        stream2: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match (stream1, stream2) {
            (Some(s1), Some(s2)) => {
                if s1.len() != VOICE_FRAME_SIZE || s2.len() != VOICE_FRAME_SIZE {
                    self.health = StreamHealth::Muted {
                        reason: "Invalid frame size".to_string(),
                    };
                    return Ok(vec![0u8; VOICE_FRAME_SIZE]); // Mute
                }

                self.health = StreamHealth::Active;
                let mut audio = vec![0u8; VOICE_FRAME_SIZE];
                for i in 0..VOICE_FRAME_SIZE {
                    audio[i] = s1[i] ^ s2[i];
                }
                Ok(audio)
            }
            _ => {
                if self.health == StreamHealth::Active {
                    warn!("[VOICE] Stream loss detected. Enforcing Mute-on-Loss (CBR Silence).");
                    self.health = StreamHealth::Muted {
                        reason: "Relay offline/packet loss".to_string(),
                    };
                }
                Ok(vec![0u8; VOICE_FRAME_SIZE]) // Strict silence
            }
        }
    }

    pub fn health(&self) -> &StreamHealth {
        &self.health
    }
}

impl Default for XorStreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_split_reassemble() {
        let mut splitter = XorStreamSplitter::new();
        let mut reassembler = XorStreamReassembler::new();

        let audio = b"Real-time Sovereign voice packet";
        
        let (s1, s2) = splitter.split_frame(audio).unwrap();
        
        assert_eq!(s1.len(), 1200);
        assert_eq!(s2.len(), 1200);

        let recovered = reassembler.reassemble_frame(Some(&s1), Some(&s2)).unwrap();
        assert!(recovered.starts_with(audio), "Recovered audio should match original");
        assert_eq!(reassembler.health(), &StreamHealth::Active);
    }

    #[test]
    fn test_mute_on_loss() {
        let mut splitter = XorStreamSplitter::new();
        let mut reassembler = XorStreamReassembler::new();

        let audio = b"Real-time Sovereign voice packet";
        let (s1, _s2) = splitter.split_frame(audio).unwrap();

        // Missing stream 2
        let recovered = reassembler.reassemble_frame(Some(&s1), None).unwrap();
        
        // Should be complete silence (zeros)
        assert_eq!(recovered, vec![0u8; 1200]);
        assert_eq!(
            reassembler.health(),
            &StreamHealth::Muted { reason: "Relay offline/packet loss".to_string() }
        );
    }
}
