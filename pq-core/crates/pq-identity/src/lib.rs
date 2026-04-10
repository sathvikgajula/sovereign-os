//! # pq-identity
//!
//! Post-quantum decentralized identity (DID) layer.
//! Generates `did:pqc:` identifiers from ML-DSA-65 public keys
//! and exports DID Documents in JSON-LD format.

use pq_crypto::SigningKeypair;
use serde::{Deserialize, Serialize};

/// A post-quantum DID identity built from an ML-DSA-65 keypair.
pub struct PqDid {
    /// The DID string, e.g. `did:pqc:<fingerprint>`.
    pub did: String,
    /// The signing keypair backing this identity.
    pub keypair: SigningKeypair,
    /// Hex-encoded BLAKE3 fingerprint of the public key.
    pub fingerprint: String,
}

/// JSON-LD DID Document representation.
#[derive(Debug, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
}

/// A verification method entry within a DID Document.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyHex")]
    pub public_key_hex: String,
}

impl PqDid {
    /// Create a new post-quantum DID identity.
    ///
    /// Generates a fresh ML-DSA-65 keypair, derives a BLAKE3 fingerprint
    /// of the public key, and constructs the `did:pqc:<fingerprint>` identifier.
    pub fn new() -> Self {
        let keypair = SigningKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();
        let hash = blake3::hash(&pk_bytes);
        let fingerprint = hex::encode(hash.as_bytes());
        let did = format!("did:pqc:{fingerprint}");

        Self {
            did,
            keypair,
            fingerprint,
        }
    }

    /// Export the DID Document as a JSON-LD structure.
    pub fn to_did_document(&self) -> DidDocument {
        let pk_hex = hex::encode(self.keypair.public_key_bytes());
        let vm_id = format!("{}#key-1", self.did);

        DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/dilithium-2023/v1".to_string(),
            ],
            id: self.did.clone(),
            verification_method: vec![VerificationMethod {
                id: vm_id.clone(),
                method_type: "PostQuantumVerificationKey2023".to_string(),
                controller: self.did.clone(),
                public_key_hex: pk_hex,
            }],
            authentication: vec![vm_id],
        }
    }

    /// Serialize the DID Document to a pretty-printed JSON string.
    pub fn to_json(&self) -> String {
        let doc = self.to_did_document();
        serde_json::to_string_pretty(&doc).expect("Failed to serialize DID Document")
    }

    /// Sign arbitrary data with this identity's keypair.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.keypair.sign(data)
    }

    /// Return a BLAKE3 hash of the DID string, hex-encoded.
    /// Used as a Nostr event tag for peer discovery.
    pub fn did_hash(&self) -> String {
        let hash = blake3::hash(self.did.as_bytes());
        hex::encode(hash.as_bytes())
    }

    /// Return the raw ML-DSA-65 public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public_key_bytes()
    }
}

impl Default for PqDid {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_format() {
        let identity = PqDid::new();
        assert!(identity.did.starts_with("did:pqc:"));
        // BLAKE3 produces a 32-byte (64-hex-char) hash
        assert_eq!(identity.fingerprint.len(), 64);
    }

    #[test]
    fn test_did_document_structure() {
        let identity = PqDid::new();
        let doc = identity.to_did_document();
        assert_eq!(doc.id, identity.did);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].method_type,
            "PostQuantumVerificationKey2023"
        );
        assert_eq!(doc.authentication.len(), 1);
    }

    #[test]
    fn test_json_export() {
        let identity = PqDid::new();
        let json = identity.to_json();
        assert!(json.contains("did:pqc:"));
        assert!(json.contains("PostQuantumVerificationKey2023"));
        assert!(json.contains("@context"));
    }
}
