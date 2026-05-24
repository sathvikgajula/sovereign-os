use anyhow::Result;
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

pub const CHUNK_SIZE: usize = 65536; // 64KB

pub mod erasure;
pub mod receipt;

pub struct SovereignStream {
    cipher: ChaCha20Poly1305,
    stream_id: [u8; 32],
    index: u64,
}

impl SovereignStream {
    pub fn new(key: &[u8; 32], stream_id: &[u8; 32]) -> Self {
        let cipher_key = Key::from_slice(key);
        Self {
            cipher: ChaCha20Poly1305::new(cipher_key),
            stream_id: *stream_id,
            index: 0,
        }
    }

    /// Derives the 96-bit nonce from the 64-bit index
    fn derive_nonce(&self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.index.to_be_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Derives the AAD from Stream ID and Index
    fn derive_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(40);
        aad.extend_from_slice(&self.stream_id);
        aad.extend_from_slice(&self.index.to_be_bytes());
        aad
    }

    /// Encrypt a single chunk of up to 64KB
    pub fn encrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > CHUNK_SIZE {
            anyhow::bail!("Chunk exceeds 64KB");
        }

        let nonce = self.derive_nonce();
        let aad = self.derive_aad();

        let payload = Payload {
            msg: data,
            aad: &aad,
        };

        // Ciphertext_i = ChaCha20-Poly1305(Key, Nonce_i, Chunk_i, AAD_i)
        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        self.index += 1;
        Ok(ciphertext)
    }

    /// Decrypt a single chunk. Fails on tampering or reordering.
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.derive_nonce();
        let aad = self.derive_aad();

        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        let plaintext = self
            .cipher
            .decrypt(&nonce, payload)
            .map_err(|_| anyhow::anyhow!("Decryption failed or data tampered"))?;

        self.index += 1;
        Ok(plaintext)
    }

    /// Reset stream index (e.g. for replaying or verifying identically)
    pub fn reset_index(&mut self) {
        self.index = 0;
    }

    /// Shatters data into 64KB chunks and encrypts each.
    pub fn shatter_and_encrypt(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut results = Vec::new();
        for chunk in data.chunks(CHUNK_SIZE) {
            results.push(self.encrypt_chunk(chunk)?);
        }
        Ok(results)
    }
}

/// Helper that generates a sequential Merkle Root from raw data chunks using BLAKE3
pub fn generate_merkle_cid(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_encryption_decryption() {
        let key = [0x42; 32];
        let stream_id = [0x77; 32];
        
        let mut enc_stream = SovereignStream::new(&key, &stream_id);
        let mut dec_stream = SovereignStream::new(&key, &stream_id);

        let chunk1_data = b"Hello, Sovereign Stream!";
        let chunk2_data = b"Second chunk, ensuring nonce increment works.";

        let ct1 = enc_stream.encrypt_chunk(chunk1_data).unwrap();
        let ct2 = enc_stream.encrypt_chunk(chunk2_data).unwrap();

        assert_ne!(ct1, chunk1_data);
        assert_ne!(ct2, chunk2_data);

        let pt1 = dec_stream.decrypt_chunk(&ct1).unwrap();
        let pt2 = dec_stream.decrypt_chunk(&ct2).unwrap();

        assert_eq!(pt1, chunk1_data);
        assert_eq!(pt2, chunk2_data);
    }

    #[test]
    fn test_reorder_attack_fails() {
        let key = [0x42; 32];
        let stream_id = [0x77; 32];
        
        let mut enc_stream = SovereignStream::new(&key, &stream_id);
        let mut dec_stream = SovereignStream::new(&key, &stream_id);

        let ct1 = enc_stream.encrypt_chunk(b"First").unwrap();
        let ct2 = enc_stream.encrypt_chunk(b"Second").unwrap();

        // Feed ct2 first
        let res = dec_stream.decrypt_chunk(&ct2);
        assert!(res.is_err(), "Decryption should fail because index doesn't match AAD/Nonce");
    }
}
