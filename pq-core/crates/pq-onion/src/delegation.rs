use crate::MixSphinxPacket;
use anyhow::{anyhow, Result};
use tracing::{info, warn};

/// Task containing an encrypted MixSphinxPacket to be forwarded.
#[derive(Debug, Clone)]
pub struct RelayTask {
    pub payload: MixSphinxPacket,
}

/// A handler that delegates relay tasks to a Home Sanctuary when the mobile node
/// is experiencing high-speed mobility (which would stutter the 200ms Metronome).
pub struct MobilityHandler;

impl MobilityHandler {
    /// Determines whether to forward a packet locally or push it to a Home Sanctuary.
    ///
    /// The trigger: if $\sigma_{\Delta t} > 3.0$s (from a component like pq-reputation),
    /// we delegate.
    pub fn process_relay_task(
        task: RelayTask,
        mobility_sigma: f64,
        home_sanctuary_id: &str,
    ) -> Result<DelegationAction> {
        if mobility_sigma > 3.0 {
            warn!(
                "[DELEGATION] High-speed mobility detected (sigma: {:.2}s). Volumetric ghosting to {}.",
                mobility_sigma, home_sanctuary_id
            );
            Ok(DelegationAction::DelegateToHome {
                target_sanctuary: home_sanctuary_id.to_string(),
                task,
            })
        } else {
            info!(
                "[DELEGATION] Mobility stable (sigma: {:.2}s). Permitting local metronome output.",
                mobility_sigma
            );
            Ok(DelegationAction::ForwardLocally(task))
        }
    }
}

pub enum DelegationAction {
    ForwardLocally(RelayTask),
    DelegateToHome {
        target_sanctuary: String,
        task: RelayTask,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobility_trigger() {
        let task = RelayTask {
            payload: MixSphinxPacket { data: [0u8; 512] },
        };

        // Low mobility: Keep locally
        let action = MobilityHandler::process_relay_task(task.clone(), 1.5, "did:pqc:sanctuary1").unwrap();
        match action {
            DelegationAction::ForwardLocally(_) => {}
            _ => panic!("Expected ForwardLocally"),
        }

        // High mobility: Delegate
        let action = MobilityHandler::process_relay_task(task, 3.5, "did:pqc:sanctuary1").unwrap();
        match action {
            DelegationAction::DelegateToHome { target_sanctuary, .. } => {
                assert_eq!(target_sanctuary, "did:pqc:sanctuary1");
            }
            _ => panic!("Expected DelegateToHome"),
        }
    }
}
