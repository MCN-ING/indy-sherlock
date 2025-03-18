use std::collections::HashMap;

use crate::parser::{ParsedTransaction, TransactionData, Role};
use super::{AnomalyFinding, AnomalyType, AnomalySeverity};

/// Specialized detector focusing on analyzing role changes
pub struct RoleChangeDetector {
    // DIDs with special privileges (trustees, stewards)
    privileged_dids: HashMap<String, Role>,
    // DIDs that are authorized to change roles
    authorized_dids: HashMap<String, Role>,
}

impl RoleChangeDetector {
    pub fn new() -> Self {
        Self {
            privileged_dids: HashMap::new(),
            authorized_dids: HashMap::new(),
        }
    }
    
    /// Initialize with known trusted DIDs
    pub fn with_trusted_dids(trusted_dids: HashMap<String, Role>) -> Self {
        let mut detector = Self::new();
        
        // Add these DIDs to both maps - they're both privileged and authorized to make changes
        for (did, role) in trusted_dids {
            detector.privileged_dids.insert(did.clone(), role.clone());
            detector.authorized_dids.insert(did, role);
        }
        
        detector
    }
    
    /// Scan a transaction batch to update the internal state of role assignments
    pub fn scan_transactions(&mut self, transactions: &[ParsedTransaction]) {
        for txn in transactions {
            // We only care about NYM transactions that assign roles
            if let TransactionData::Nym(nym_data) = &txn.specific_data {
                if let Some(role_str) = &nym_data.role {
                    // Parse the role
                    let role = match role_str.as_str() {
                        "0" => Role::Trustee,
                        "2" => Role::Steward,
                        "101" => Role::EndorserTrustAnchor,
                        "201" => Role::Network,
                        "" => Role::User,  // Empty string means USER role
                        _ => Role::Unknown(role_str.clone()),
                    };
                    
                    // Update our role tracking
                    if matches!(role, Role::Trustee | Role::Steward) {
                        // This is a privileged DID
                        self.privileged_dids.insert(nym_data.dest.clone(), role.clone());
                        // Privileged DIDs are also authorized to make changes
                        self.authorized_dids.insert(nym_data.dest.clone(), role);
                    } else if matches!(role, Role::EndorserTrustAnchor | Role::Network) {
                        // Not a privileged DID, but still want to track it
                        self.authorized_dids.insert(nym_data.dest.clone(), role);
                    }
                }
            }
        }
    }
    
    /// Detect suspicious role changes
    pub fn detect_suspicious_role_changes(&self, transactions: &[ParsedTransaction]) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();
        
        for txn in transactions {
            // We only care about NYM transactions that assign roles
            if let TransactionData::Nym(nym_data) = &txn.specific_data {
                if let Some(role_str) = &nym_data.role {
                    // Parse the role being assigned
                    let new_role = match role_str.as_str() {
                        "0" => Role::Trustee,
                        "2" => Role::Steward,
                        "101" => Role::EndorserTrustAnchor,
                        "201" => Role::Network,
                        "" => Role::User,  // Empty string means USER role
                        _ => Role::Unknown(role_str.clone()),
                    };
                    
                    // Check if the transaction author is authorized to assign this role
                    let author_authorized = self.authorized_dids.get(&txn.identifier)
                        .map(|role| match (role, &new_role) {
                            // Trustees can assign any role
                            (Role::Trustee, _) => true,
                            // Stewards can assign Endorser or Network Monitor roles
                            (Role::Steward, Role::EndorserTrustAnchor) => true,
                            (Role::Steward, Role::Network) => true,
                            (Role::Steward, Role::User) => true,
                            // Other combinations are not authorized
                            _ => false,
                        })
                        .unwrap_or(false);
                    
                    // Check if this is assigning a privileged role
                    let is_privileged_role = matches!(new_role, Role::Trustee | Role::Steward);
                    
                    // Check if the target DID already has a role
                    let target_did = &nym_data.dest;
                    let target_has_existing_role = self.privileged_dids.contains_key(target_did) || 
                                                  self.authorized_dids.contains_key(target_did);
                    
                    // Now check for suspicious patterns
                    
                    // 1. Unauthorized role assignment
                    if !author_authorized {
                        findings.push(AnomalyFinding::new(
                            AnomalyType::UnauthorizedAction,
                            AnomalySeverity::Critical,
                            &format!(
                                "Unauthorized role assignment: DID {} attempted to assign role {:?} to DID {}",
                                txn.identifier, new_role, target_did
                            ),
                            vec![txn.seq_no],
                            vec![txn.identifier.clone(), target_did.clone()],
                        ));
                    }
                    
                    // 2. Role elevation
                    if is_privileged_role && target_has_existing_role {
                        let previous_role = self.privileged_dids.get(target_did)
                            .cloned()
                            .or_else(|| self.authorized_dids.get(target_did).cloned())
                            .unwrap_or(Role::User);
                        
                        // Check if this is an elevation
                        let is_elevation = match (&previous_role, &new_role) {
                            (Role::User, _) => true, // Any role is higher than user
                            (Role::EndorserTrustAnchor, Role::Steward) => true,
                            (Role::EndorserTrustAnchor, Role::Trustee) => true,
                            (Role::Network, Role::Steward) => true,
                            (Role::Network, Role::Trustee) => true,
                            (Role::Steward, Role::Trustee) => true,
                            _ => false,
                        };
                        
                        if is_elevation {
                            findings.push(AnomalyFinding::new(
                                AnomalyType::RoleElevation,
                                AnomalySeverity::High,
                                &format!(
                                    "Role elevation detected: DID {} elevated from {:?} to {:?} by DID {}",
                                    target_did, previous_role, new_role, txn.identifier
                                ),
                                vec![txn.seq_no],
                                vec![txn.identifier.clone(), target_did.clone()],
                            ));
                        }
                    }
                    
                    // 3. Too many privileged DIDs
                    if is_privileged_role {
                        // Count existing privileged DIDs of this type
                        let existing_count = self.privileged_dids
                            .values()
                            .filter(|r| **r == new_role)
                            .count();
                        
                        // Flag if there are already many of this type
                        // Arbitrary thresholds based on common governance models
                        let threshold = match new_role {
                            Role::Trustee => 5,   // Most networks have fewer than 5 trustees
                            Role::Steward => 25,  // Stewards could be more numerous
                            _ => 100,             // Not applicable for other roles
                        };
                        
                        if existing_count >= threshold {
                            findings.push(AnomalyFinding::new(
                                AnomalyType::UnexpectedTransactionSequence,  // Changed to UnexpectedTransactionSequence
                                AnomalySeverity::Medium,
                                &format!(
                                    "Unusual number of privileged DIDs: Adding another {:?} (total: {})",
                                    new_role, existing_count + 1
                                ),
                                vec![txn.seq_no],
                                vec![txn.identifier.clone(), target_did.clone()],
                            ));
                        }
                    }
                }
            }
        }
        
        findings
    }
    
    /// Get a current snapshot of privileged DIDs
    pub fn get_privileged_dids(&self) -> &HashMap<String, Role> {
        &self.privileged_dids
    }
    
    /// Get a current snapshot of authorized DIDs
    pub fn get_authorized_dids(&self) -> &HashMap<String, Role> {
        &self.authorized_dids
    }
}