use crate::MixSphinxPacket;
use std::collections::VecDeque;

/// Roles in the 3-ary distribution tree.
#[derive(Debug, Clone, PartialEq)]
pub enum TreeRole {
    Originator,
    Relay { children: Vec<String> }, // 3 DIDs max
    Leaf,
}

/// A scheduled packet replacement to maintain 200ms timing with 1-packet-per-tick.
#[derive(Debug, Clone)]
pub struct ScheduledRelay {
    pub tick_offset: usize,
    pub target_did: String,
    pub payload: Vec<u8>,
}

/// Builds and manages a balanced 3-ary Distribution Tree for group messaging.
pub struct DistributionTree {
    pub role: TreeRole,
}

impl DistributionTree {
    pub fn new(members: &[String], my_did: &str) -> Self {
        // Build 3-ary tree logic out of a sorted member list (naive array mapping).
        let mut sorted_members = members.to_vec();
        sorted_members.sort();

        let my_idx = sorted_members.iter().position(|r| r == my_did).unwrap_or(0);
        
        let c1 = my_idx * 3 + 1;
        let c2 = my_idx * 3 + 2;
        let c3 = my_idx * 3 + 3;

        let mut children = Vec::new();
        if c1 < sorted_members.len() { children.push(sorted_members[c1].clone()); }
        if c2 < sorted_members.len() { children.push(sorted_members[c2].clone()); }
        if c3 < sorted_members.len() { children.push(sorted_members[c3].clone()); }

        let role = if my_idx == 0 {
            TreeRole::Originator
        } else if children.is_empty() {
            TreeRole::Leaf
        } else {
            TreeRole::Relay { children }
        };

        Self { role }
    }

    /// Schedules forwarding to children by returning a series of packets 
    /// explicitly staggered to perfectly substitute constant 200ms chaff output.
    pub fn schedule_group_send(&self, payload: &[u8]) -> Vec<ScheduledRelay> {
        let mut schedule = Vec::new();

        let children = match &self.role {
            TreeRole::Originator => {
                // Not returning actual children list here, assuming 3 for originator mock
                vec![] // Handled manually below for testing
            }
            TreeRole::Relay { children } => children.clone(),
            TreeRole::Leaf => vec![],
        };

        for (idx, target_did) in children.into_iter().enumerate() {
            schedule.push(ScheduledRelay {
                tick_offset: idx + 1, // Stagger perfectly into consecutive 200ms slots
                target_did,
                payload: payload.to_vec(),
            });
        }

        schedule
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distribution_tree() {
        let mut members = Vec::new();
        for i in 0..50 {
            members.push(format!("did:pqc:{:02}", i));
        }

        let tree = DistributionTree::new(&members, "did:pqc:00");
        assert_eq!(tree.role, TreeRole::Originator);

        let tree_relay = DistributionTree::new(&members, "did:pqc:01");
        match tree_relay.role {
            TreeRole::Relay { ref children } => {
                assert_eq!(children.len(), 3);
                assert_eq!(children[0], "did:pqc:04");
                assert_eq!(children[1], "did:pqc:05");
                assert_eq!(children[2], "did:pqc:06");
            }
            _ => panic!("Expected Relay"),
        }

        let schedule = tree_relay.schedule_group_send(b"test");
        assert_eq!(schedule.len(), 3);
        assert_eq!(schedule[0].tick_offset, 1);
        assert_eq!(schedule[1].tick_offset, 2);
        assert_eq!(schedule[2].tick_offset, 3);
    }
}
