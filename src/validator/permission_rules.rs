use std::collections::HashMap;
use crate::parser::{ParsedTransaction, TransactionData, TransactionType, Role};
use crate::validator::{ValidationRule, ValidationFinding, ValidationSeverity};
use crate::error::Result;

/// Rule for validating if a DID has appropriate permissions for its actions
pub struct PermissionValidationRule {
    // Map of DIDs to their roles for permission checking
    did_roles: HashMap<String, Role>,
    strict_mode: bool,  // If true, reject transactions without a known DID role
}

impl PermissionValidationRule {
    pub fn new() -> Self {
        Self {
            did_roles: HashMap::new(),
            strict_mode: false,
        }
    }
    
    /// Create with a pre-populated map of DID roles
    pub fn with_roles(did_roles: HashMap<String, Role>, strict_mode: bool) -> Self {
        Self {
            did_roles,
            strict_mode,
        }
    }
    
    /// Add or update a DID's role
    pub fn add_did_role(&mut self, did: &str, role: Role) {
        self.did_roles.insert(did.to_string(), role);
    }
    
    /// Get a DID's current role
    pub fn get_did_role(&self, did: &str) -> Option<&Role> {
        self.did_roles.get(did)
    }
    
    /// Check if a DID is authorized for a specific transaction type
    fn is_authorized_for_transaction(&self, did: &str, txn_type: &TransactionType) -> bool {
        let role = match self.did_roles.get(did) {
            Some(r) => r,
            None => return !self.strict_mode, // Unknown DIDs allowed in non-strict mode
        };
        
        match role {
            // Trustee can do anything
            Role::Trustee => true,
            
            // Steward permissions
            Role::Steward => match txn_type {
                TransactionType::NYM => true,
                TransactionType::ATTRIB => true,
                TransactionType::SCHEMA => true,
                TransactionType::ClaimDef => true,
                TransactionType::NODE => true,
                TransactionType::RevocRegDef => true,
                TransactionType::RevocRegEntry => true,
                // Config transactions usually need Trustee
                TransactionType::PoolUpgrade => false,
                TransactionType::PoolConfig => false,
                TransactionType::AuthRule => false,
                TransactionType::AuthRules => false,
                TransactionType::PoolRestart => false,
                TransactionType::ValidatorInfo => true,
                TransactionType::SetFees => false,
                TransactionType::TxnsAuthrAgrmt => false,
                TransactionType::TxnsAuthrAgrmtAml => false,
                TransactionType::GetTxnsAuthrAgrmt => true, // Read operations allowed
                TransactionType::DisableAuthrAgrmt => false,
                TransactionType::UNKNOWN(_) => false,
            },
            
            // Endorser permissions
            Role::EndorserTrustAnchor => match txn_type {
                TransactionType::NYM => true, // Limited capabilities checked separately
                TransactionType::ATTRIB => true,
                TransactionType::SCHEMA => true,
                TransactionType::ClaimDef => true,
                TransactionType::RevocRegDef => true,
                TransactionType::RevocRegEntry => true,
                TransactionType::NODE => false,
                TransactionType::ValidatorInfo => false,
                // Endorsers can't do config transactions
                TransactionType::PoolUpgrade => false,
                TransactionType::PoolConfig => false,
                TransactionType::AuthRule => false,
                TransactionType::AuthRules => false,
                TransactionType::PoolRestart => false,
                TransactionType::SetFees => false,
                TransactionType::TxnsAuthrAgrmt => false,
                TransactionType::TxnsAuthrAgrmtAml => false, 
                TransactionType::GetTxnsAuthrAgrmt => true, // Read operations allowed
                TransactionType::DisableAuthrAgrmt => false,
                TransactionType::UNKNOWN(_) => false,
            },
            
            // Network Monitor permissions
            Role::Network => match txn_type {
                TransactionType::ValidatorInfo => true,
                _ => false, // Can't do much else
            },
            
            // User permissions
            Role::User => match txn_type {
                TransactionType::NYM => false, // Can't create DIDs
                TransactionType::ATTRIB => true, // Only for their own DID
                TransactionType::GetTxnsAuthrAgrmt => true, // Read operations allowed
                _ => false,
            },
            
            // Unknown roles get minimal permissions
            Role::Unknown(_) => !self.strict_mode,
        }
    }
    
    /// Check if a DID can assign a specific role to another DID
    fn can_assign_role(&self, author_did: &str, role_to_assign: &Role) -> bool {
        let author_role = match self.did_roles.get(author_did) {
            Some(r) => r,
            None => return false, // Unknown DID can't assign roles
        };
        
        match (author_role, role_to_assign) {
            // Trustee can assign any role
            (Role::Trustee, _) => true,
            
            // Steward can assign endorser and user roles
            (Role::Steward, Role::EndorserTrustAnchor) => true,
            (Role::Steward, Role::User) => true,
            (Role::Steward, Role::Network) => true,
            
            // Endorser can only create users
            (Role::EndorserTrustAnchor, Role::User) => true,
            
            // Others can't assign roles
            _ => false,
        }
    }
}

impl ValidationRule for PermissionValidationRule {
    fn name(&self) -> &'static str {
        "Permission Validation Rule"
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    
    fn validate(&self, transaction: &ParsedTransaction) -> Result<Vec<ValidationFinding>> {
        let mut findings = Vec::new();
        
        // 1. Basic transaction type permission check
        if !self.is_authorized_for_transaction(&transaction.identifier, &transaction.txn_type) {
            findings.push(ValidationFinding::new(
                ValidationSeverity::Error,
                &format!(
                    "DID {} is not authorized to create a {:?} transaction",
                    transaction.identifier, transaction.txn_type
                ),
            ));
        }
        
        // 2. Special checks for specific transaction types
        match &transaction.specific_data {
            TransactionData::Nym(nym_data) => {
                // Check for role assignment permissions
                if let Some(role_str) = &nym_data.role {
                    let role = match role_str.as_str() {
                        "0" => Role::Trustee,
                        "2" => Role::Steward,
                        "101" => Role::EndorserTrustAnchor,
                        "201" => Role::Network,
                        "" => Role::User,
                        _ => Role::Unknown(role_str.clone()),
                    };
                    
                    if !self.can_assign_role(&transaction.identifier, &role) {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Error,
                            &format!(
                                "DID {} is not authorized to assign role {:?} to DID {}",
                                transaction.identifier, role, nym_data.dest
                            ),
                        ));
                    }
                }
            },
            TransactionData::Attrib(attrib_data) => {
                // Check if DID is writing on its own attribute
                if let Some(author_role) = self.did_roles.get(&transaction.identifier) {
                    if *author_role == Role::User && transaction.identifier != attrib_data.dest {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Error,
                            &format!(
                                "DID {} (role: {:?}) is attempting to modify attributes for DID {}",
                                transaction.identifier, author_role, attrib_data.dest
                            ),
                        ));
                    }
                }
            },
            TransactionData::Node(_) => {
                // Check role is Steward or Trustee for node transactions
                if let Some(role) = self.did_roles.get(&transaction.identifier) {
                    if !matches!(role, Role::Steward | Role::Trustee) {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Error,
                            &format!(
                                "DID {} with role {:?} is not authorized to create NODE transactions",
                                transaction.identifier, role
                            ),
                        ));
                    }
                } else if self.strict_mode {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        &format!(
                            "Unknown DID {} is attempting to create a NODE transaction",
                            transaction.identifier
                        ),
                    ));
                }
            },
            // Add checks for other transaction types as needed
            _ => {}
        }
        
        Ok(findings)
    }
}