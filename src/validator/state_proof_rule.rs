use crate::parser::ParsedTransaction;
use crate::validator::{ValidationRule, ValidationFinding, ValidationSeverity};
use crate::validator::state_proof::StateProofVerifier;
use crate::error::Result;
use tracing::debug;

/// Rule for validating transaction state proofs
pub struct StateProofValidationRule {
    verifier: StateProofVerifier,
}

impl StateProofValidationRule {
    pub fn new() -> Self {
        Self {
            verifier: StateProofVerifier::new(),
        }
    }
}

impl ValidationRule for StateProofValidationRule {
    fn name(&self) -> &'static str {
        "State Proof Validation Rule"
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    
    fn validate(&self, transaction: &ParsedTransaction) -> Result<Vec<ValidationFinding>> {
        let mut findings = Vec::new();
        
        // Check if this transaction has the necessary state proof components
        if transaction.raw_data["auditPath"].is_null() || transaction.raw_data["rootHash"].is_null() {
            // If the transaction has no state proof components, we'll skip detailed verification
            debug!("Transaction #{} is missing state proof components - skipping verification", 
                transaction.seq_no);
            
            findings.push(ValidationFinding::new(
                ValidationSeverity::Warning,
                &format!("Transaction #{} is missing state proof components (auditPath or rootHash)", 
                    transaction.seq_no)
            ));
            
            return Ok(findings);
        }
        
        // Validate ledger size vs audit path length
        let ledger_size = transaction.raw_data["ledgerSize"].as_u64().unwrap_or(0);

        // We need to handle the empty array case differently to avoid the temporary value issue
        let audit_path_len = match transaction.raw_data["auditPath"].as_array() {
            Some(path) => path.len(),
            None => 0
        };
        
        if ledger_size > 0 && audit_path_len > 0 {
            let expected_max_path_length = (ledger_size as f64).log2().ceil() as usize;
            if audit_path_len > expected_max_path_length {
                findings.push(ValidationFinding::new(
                    ValidationSeverity::Error,
                    &format!(
                        "Invalid audit path length: got {}, max expected {} for ledger size {}",
                        audit_path_len, expected_max_path_length, ledger_size
                    )
                ));
                
                // Return early as this is a critical error
                return Ok(findings);
            }
        }
        
        // Use tokio's task::block_in_place to safely call async code from a sync context
        match tokio::task::block_in_place(|| {
            // Use the current runtime's handle to avoid creating a new runtime
            let handle = tokio::runtime::Handle::current();
            handle.block_on(self.verifier.verify_transaction(transaction))
        }) {
            Ok(result) => {
                if !result.verified {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        &format!("State proof verification failed: {}", result.details),
                    ));
                    
                    // Add warnings as separate findings
                    for warning in result.warnings {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            &warning,
                        ));
                    }
                } else {
                    debug!("State proof verified for transaction #{}", transaction.seq_no);
                }
            },
            Err(e) => {
                findings.push(ValidationFinding::with_context(
                    ValidationSeverity::Error,
                    "Failed to execute state proof verification",
                    &e.to_string(),
                ));
            }
        }
        
        Ok(findings)
    }
}