use serde::{Deserialize, Serialize};

/// Represents a candidate Sanctuary Relay with an ephemeral auth token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SanctuaryCandidate {
    pub ip_address: String, // e.g., "198.51.100.14:9000"
    pub auth_token: String, // Ephemeral token for Hydra tunnel attachment
}

/// The CallRequest payload initiated by the caller (Alice).
/// Contains 10 Sanctuary options proposed by Alice.
/// Encapsulated inside a Mix-Net asynchronous Sphinx packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRequest {
    pub caller_did: String,
    pub candidates: Vec<SanctuaryCandidate>, // Must contain exactly 10 candidates
}

/// The CallAccept payload returned by the receiver (Bob).
/// Emits back the index positions (0-9) of the 2 mutually accepted relays 
/// (based on Bob's local Web of Trust calculations).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallAccept {
    pub responder_did: String,
    pub selected_indices: [u8; 2],
}

impl CallRequest {
    pub fn new(caller_did: &str, candidates: Vec<SanctuaryCandidate>) -> anyhow::Result<Self> {
        if candidates.len() != 10 {
            return Err(anyhow::anyhow!("CallRequest must container exactly 10 Sanctuary candidates"));
        }
        Ok(Self {
            caller_did: caller_did.to_string(),
            candidates,
        })
    }
}

impl CallAccept {
    pub fn new(responder_did: &str, selected_indices: [u8; 2]) -> anyhow::Result<Self> {
        if selected_indices[0] >= 10 || selected_indices[1] >= 10 || selected_indices[0] == selected_indices[1] {
            return Err(anyhow::anyhow!("CallAccept must select 2 valid distinct indices between 0 and 9"));
        }
        Ok(Self {
            responder_did: responder_did.to_string(),
            selected_indices,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_handshake() {
        let mut candidates = Vec::new();
        for i in 0..10 {
            candidates.push(SanctuaryCandidate {
                ip_address: format!("192.168.1.{}", i),
                auth_token: format!("token_{}", i),
            });
        }

        let request = CallRequest::new("did:pqc:alice", candidates).unwrap();
        assert_eq!(request.candidates.len(), 10);

        let accept = CallAccept::new("did:pqc:bob", [2, 5]).unwrap();
        assert_eq!(accept.selected_indices, [2, 5]);
    }

    #[test]
    fn test_invalid_request() {
        let candidates = vec![SanctuaryCandidate {
            ip_address: "".to_string(),
            auth_token: "".to_string(),
        }]; // Only 1 candidate
        assert!(CallRequest::new("did:pqc:alice", candidates).is_err());
    }

    #[test]
    fn test_invalid_accept() {
        assert!(CallAccept::new("did:pqc:bob", [10, 1]).is_err());
        assert!(CallAccept::new("did:pqc:bob", [3, 3]).is_err());
    }
}
