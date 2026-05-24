use crate::PqDid;
use pq_crypto::SigningKeypair;
use std::collections::HashMap;

/// Manages pairwise relationship isolation.
/// Each peer gets a unique DID, preventing cross-relationship correlation.
pub struct PairwiseManager {
    /// Maps a human-readable alias (or global identifier) to a specific pairwise DID.
    /// In a production system, this would be backed by local SQLite.
    relationships: HashMap<String, PqDid>,
}

impl PairwiseManager {
    pub fn new() -> Self {
        Self {
            relationships: HashMap::new(),
        }
    }

    /// Retrieve or generate a pairwise DID for a given contact alias.
    pub fn get_or_create_did(&mut self, alias: &str) -> &PqDid {
        self.relationships
            .entry(alias.to_string())
            .or_insert_with(PqDid::new)
    }

    /// Retrieve the DID for a given contact alias without creating one if it doesn't exist.
    pub fn get_did(&self, alias: &str) -> Option<&PqDid> {
        self.relationships.get(alias)
    }
}

impl Default for PairwiseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairwise_isolation() {
        let mut manager = PairwiseManager::new();

        let did_alice = manager.get_or_create_did("Alice").did.clone();
        let did_bob = manager.get_or_create_did("Bob").did.clone();

        // Ensure zero mathematical link (they are completely different keypairs)
        assert_ne!(did_alice, did_bob);

        // Fetching again returns the same DID
        let did_alice_2 = manager.get_or_create_did("Alice").did.clone();
        assert_eq!(did_alice, did_alice_2);
    }
}
