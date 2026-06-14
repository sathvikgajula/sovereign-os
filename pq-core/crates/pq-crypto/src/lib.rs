#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

pub use pqcrypto_kyber::kyber768;
pub use pqcrypto_dilithium::dilithium3;

// ── Error taxonomy (no_std + std) ───────────────────────────────────────────

/// Explicit cryptographic error mapping (replaces `anyhow` in the PQ core).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidPublicKey,
    InvalidSignature,
    VerifyFailed,
    InvalidCiphertext,
}

pub type CryptoResult<T> = Result<T, CryptoError>;

#[cfg(feature = "std")]
impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidPublicKey => write!(f, "invalid post-quantum public key"),
            CryptoError::InvalidSignature => write!(f, "invalid post-quantum signature"),
            CryptoError::VerifyFailed => write!(f, "post-quantum signature verification failed"),
            CryptoError::InvalidCiphertext => write!(f, "invalid post-quantum ciphertext"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

// ── ML-DSA-65 (Dilithium3) Digital Signatures ──────────────────────────────

use pqcrypto_traits::sign::{DetachedSignature, PublicKey as SignPublicKeyTrait};

/// A post-quantum signing keypair using ML-DSA-65 (Dilithium3).
pub struct SigningKeypair {
    pub public_key: dilithium3::PublicKey,
    secret_key: dilithium3::SecretKey,
}

impl SigningKeypair {
    /// Generate a fresh ML-DSA-65 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Sign a message and return the detached signature bytes.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = dilithium3::detached_sign(message, &self.secret_key);
        sig.as_bytes().to_vec()
    }

    /// Return the raw public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }
}

/// Verify a detached ML-DSA-65 signature against a public key.
pub fn verify_signature(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> CryptoResult<()> {
    let pk = dilithium3::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = dilithium3::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    dilithium3::verify_detached_signature(&sig, message, &pk).map_err(|_| CryptoError::VerifyFailed)
}

// ── ML-KEM-768 (Kyber768) Key Encapsulation ────────────────────────────────

use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
    SharedSecret as KemSharedSecretTrait,
};

/// A post-quantum KEM keypair using ML-KEM-768 (Kyber768).
pub struct KemKeypair {
    pub public_key: kyber768::PublicKey,
    secret_key: kyber768::SecretKey,
}

/// The result of an ML-KEM-768 encapsulation.
pub struct Encapsulated {
    /// The shared secret derived during encapsulation.
    pub shared_secret: Vec<u8>,
    /// The ciphertext to send to the keypair holder.
    pub ciphertext: Vec<u8>,
}

impl KemKeypair {
    /// Generate a fresh ML-KEM-768 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = kyber768::keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Encapsulate against this keypair's public key.
    pub fn encapsulate(&self) -> Encapsulated {
        let (ss, ct) = kyber768::encapsulate(&self.public_key);
        Encapsulated {
            shared_secret: ss.as_bytes().to_vec(),
            ciphertext: ct.as_bytes().to_vec(),
        }
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> CryptoResult<Vec<u8>> {
        let ct = kyber768::Ciphertext::from_bytes(ciphertext_bytes)
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let ss = kyber768::decapsulate(&ct, &self.secret_key);
        Ok(ss.as_bytes().to_vec())
    }

    /// Return the raw public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = SigningKeypair::generate();
        let msg = b"post-quantum identity test";
        let sig = kp.sign(msg);
        assert!(verify_signature(msg, &sig, &kp.public_key_bytes()).is_ok());
    }

    #[test]
    fn test_sign_verify_bad_message() {
        let kp = SigningKeypair::generate();
        let sig = kp.sign(b"correct message");
        assert!(verify_signature(b"wrong message", &sig, &kp.public_key_bytes()).is_err());
    }

    #[test]
    fn test_kem_roundtrip() {
        let kp = KemKeypair::generate();
        let enc = kp.encapsulate();
        let recovered = kp.decapsulate(&enc.ciphertext).unwrap();
        assert_eq!(enc.shared_secret, recovered);
    }
}

#[cfg(test)]
mod v1_root_gen {
    use super::*;
    #[test]
    fn gen_v1_root() {
        let kp = SigningKeypair::generate();
        println!("ROOT_PK_BYTES: {:?}", kp.public_key_bytes());
    }
}
