use crate::pairwise::PairwiseManager;
use crate::PqDid;
use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// A single-use routing token issued by a mutually trusted Manager 
/// to facilitate a blind introduction between two strangers.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingToken {
    pub token: [u8; 32],
}

impl RoutingToken {
    pub fn generate() -> Self {
        let mut rng = StdRng::from_entropy();
        let mut token = [0u8; 32];
        rng.fill_bytes(&mut token);
        Self { token }
    }
}

/// The Ephemeral Bridge coordinates introductions without mathematically
/// linking the final Pairwise DIDs back to the coordinating Manager.
pub struct EphemeralBridge {
    active_tokens: Vec<RoutingToken>,
}

impl EphemeralBridge {
    pub fn new() -> Self {
        Self {
            active_tokens: Vec::new(),
        }
    }

    /// Issue a temporary routing token to coordinate an intro.
    pub fn issue_token(&mut self) -> RoutingToken {
        let token = RoutingToken::generate();
        self.active_tokens.push(token.clone());
        token
    }

    /// Validates the token, burns it (single use), and facilitates the
    /// creation of an isolated Pairwise DID for the new stranger.
    pub fn consume_token_and_pair(
        &mut self,
        token: &RoutingToken,
        pairwise_manager: &mut PairwiseManager,
        stranger_alias: &str,
    ) -> Result<String> {
        if let Some(pos) = self.active_tokens.iter().position(|t| t == token) {
            // BURN the token (Single Use)
            self.active_tokens.remove(pos);

            // Establish the permanent isolated identifier
            let new_did = pairwise_manager.get_or_create_did(stranger_alias);
            Ok(new_did.did.clone())
        } else {
            Err(anyhow!("Invalid or expired routing token"))
        }
    }
}

impl Default for EphemeralBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ephemeral_bridge_flow() {
        let mut bridge = EphemeralBridge::new();
        let mut manager = PairwiseManager::new();

        // 1. Manager issues token to Alice & Bob
        let token = bridge.issue_token();

        // 2. Bob uses token to pair with Alice
        let alice_pairwise_did = bridge.consume_token_and_pair(&token, &mut manager, "Alice_Stranger").unwrap();

        // 3. Token is burned; trying again fails
        assert!(bridge.consume_token_and_pair(&token, &mut manager, "Alice_Stranger").is_err());

        // 4. The relationship is now established mathematically isolated in the PairwiseManager
        let fetched = manager.get_did("Alice_Stranger").unwrap();
        assert_eq!(fetched.did, alice_pairwise_did);
    }
}
