use crate::parser::ParsedTransaction;
use crate::error::Result;
use tracing::{debug, info, warn};

pub struct StateProofVerificationResult {
    pub verified: bool,
    pub details: String,
    pub warnings: Vec<String>,
}

pub struct StateProofVerifier {
}

impl StateProofVerifier {
    pub fn new() -> Self {
        Self {}
    }
    
    /// Main verification method for state proofs
    pub async fn verify_transaction(&self, transaction: &ParsedTransaction) -> Result<StateProofVerificationResult> {
        let mut result = StateProofVerificationResult {
            verified: false,
            details: String::new(),
            warnings: Vec::new(),
        };
        
        debug!("Verifying state proof for transaction #{} of type {:?}", transaction.seq_no, transaction.txn_type);
        
        // In Hyperledger Indy, state proof components are at the root level
        // We need to check for auditPath and rootHash which are the key components
        let audit_path = &transaction.raw_data["auditPath"];
        let root_hash = &transaction.raw_data["rootHash"];
        
        // Check if we have the necessary state proof components
        if audit_path.is_null() || root_hash.is_null() {
            result.details = "Transaction is missing state proof components".to_string();
            result.warnings.push("Missing audit path or root hash".to_string());
            // For backwards compatibility, don't fail verification just because state proof is missing
            result.verified = true;
            return Ok(result);
        }
        
        // Verify the state proof
        match self.verify_state_proof(transaction) {
            Ok(verification_details) => {
                result.verified = true;
                result.details = verification_details;
                info!("State proof structure validated for transaction #{}", transaction.seq_no);
            },
            Err(e) => {
                result.verified = false;
                result.details = format!("State proof verification failed: {}", e);
                result.warnings.push("Invalid state proof".to_string());
            }
        }
        
        debug!("State proof verification result: verified={}, warnings={:?}", 
            result.verified, result.warnings);
        
        Ok(result)
    }
    
    /// Provides a detailed explanation of the state proof in a transaction
    pub fn explain_state_proof(&self, transaction: &ParsedTransaction) -> String {
        // Initialize the explanation string
        let mut explanation = String::new();
        explanation.push_str("\nState Proof Structure Explanation:\n");
        
        // Check for required components
        let audit_path = transaction.raw_data["auditPath"].as_array();
        let root_hash = transaction.raw_data["rootHash"].as_str();
        let ledger_size = transaction.raw_data["ledgerSize"].as_u64();
        
        // Basic component check
        if audit_path.is_none() || root_hash.is_none() {
            explanation.push_str("❌ Transaction is missing required state proof components.\n");
            return explanation;
        }
        
        let audit_path = audit_path.unwrap();
        let root_hash = root_hash.unwrap();
        
        // Explain the components
        explanation.push_str(&format!("✅ Root Hash: {} (base58 encoded)\n", root_hash));
        explanation.push_str(&format!("✅ Merkle Path Length: {} levels\n", audit_path.len()));
        
        if let Some(size) = ledger_size {
            let expected_path_length = (size as f64).log2().ceil() as usize;
            explanation.push_str(&format!("✅ Ledger Size: {}\n", size));
            
            if audit_path.len() <= expected_path_length {
                explanation.push_str(&format!("✅ Merkle Path Length is valid (max expected: {})\n", expected_path_length));
            } else {
                explanation.push_str(&format!("❌ Merkle Path Length is invalid! Got {}, max expected: {}\n", 
                    audit_path.len(), expected_path_length));
            }
        } else {
            explanation.push_str("⚠️ Cannot validate Merkle Path length: ledger size unknown\n");
        }
        
        // Explain the audit path (show first few and last few entries if it's long)
        explanation.push_str("\nMerkle Path Entries:\n");
        
        if audit_path.len() <= 8 {
            // Show all entries for short paths
            for (i, entry) in audit_path.iter().enumerate() {
                if let Some(e) = entry.as_str() {
                    explanation.push_str(&format!("  {}: {}\n", i, e));
                }
            }
        } else {
            // Show first 4 and last 4 for long paths
            for i in 0..4 {
                if let Some(e) = audit_path[i].as_str() {
                    explanation.push_str(&format!("  {}: {}\n", i, e));
                }
            }
            
            explanation.push_str("  ...\n");
            
            for i in audit_path.len() - 4..audit_path.len() {
                if let Some(e) = audit_path[i].as_str() {
                    explanation.push_str(&format!("  {}: {}\n", i, e));
                }
            }
        }
        
        // Explain what state proofs are used for
        explanation.push_str("\nState Proof Purpose:\n");
        explanation.push_str("State proofs allow verification that a transaction is genuinely part of the ledger.\n");
        explanation.push_str("A complete verification would include:\n");
        explanation.push_str("1. Calculating a hash of the transaction data\n");
        explanation.push_str("2. Verifying the Merkle path from the transaction to the root hash\n");
        explanation.push_str("3. Confirming the root hash matches the one signed by validator nodes\n\n");
        explanation.push_str("Note: This tool validates the structure of state proofs but does not perform\n");
        explanation.push_str("      cryptographic verification of the Merkle path.\n");
        
        explanation
    }

    /// Verify state proof for a transaction
    fn verify_state_proof(&self, transaction: &ParsedTransaction) -> Result<String> {
        // Extract the audit path
        let audit_path = match transaction.raw_data["auditPath"].as_array() {
            Some(path) => path,
            None => {
                warn!("Missing audit path in transaction");
                return Err(anyhow::anyhow!("Missing audit path in transaction"));
            }
        };
        
        // Extract the root hash
        let root_hash = match transaction.raw_data["rootHash"].as_str() {
            Some(hash) => hash,
            None => {
                warn!("Missing root hash in transaction");
                return Err(anyhow::anyhow!("Missing root hash in transaction"));
            }
        };
        
        // Check for signature information - in Indy this is in reqSignature
        let req_signature = &transaction.raw_data["reqSignature"];
        if req_signature.is_null() {
            warn!("Missing reqSignature in transaction");
            // We'll continue even without this as we can still verify the structure
        }
        
        // Structural validation:
        // Check that the audit path has a reasonable length (Merkle trees should have log2(n) height)
        let ledger_size = transaction.raw_data["ledgerSize"].as_u64().unwrap_or(0);
        let expected_max_path_length = if ledger_size > 0 {
            // Calculate log2 and round up
            (ledger_size as f64).log2().ceil() as usize
        } else {
            32 // Default maximum path length if ledger size unknown
        };
        
        if audit_path.len() > expected_max_path_length {
            warn!("Audit path length ({}) exceeds expected maximum ({}) for ledger size {}", 
                 audit_path.len(), expected_max_path_length, ledger_size);
            return Err(anyhow::anyhow!("Audit path too long for ledger size"));
        }
        
        // Note: We are not performing cryptographic verification of the Merkle path
        // This would require detailed knowledge of Indy's specific hash calculation methods
        
        info!("State proof structure validated for transaction #{}", transaction.seq_no);
        
        Ok(format!("State proof structure verified for transaction #{} (root hash: {})", 
                  transaction.seq_no, root_hash))
    }
    
    /// Validate transaction sequence number
    pub fn validate_sequence_number(&self, seq_no: u64, previous_seq_no: Option<u64>) -> Result<()> {
        // Check if the sequence number forms a continuous chain with the previous transaction
        if let Some(prev_seq_no) = previous_seq_no {
            if seq_no != prev_seq_no + 1 {
                return Err(anyhow::anyhow!("Sequence number gap detected: expected {}, found {}", 
                    prev_seq_no + 1, seq_no));
            }
        }
        
        Ok(())
    }
    
    /// Validate that transaction timestamps are in chronological order
    pub fn validate_timestamp(&self, timestamp: u64, previous_timestamp: Option<u64>) -> Result<()> {
        if let Some(prev_timestamp) = previous_timestamp {
            if timestamp < prev_timestamp {
                return Err(anyhow::anyhow!("Transaction timestamp out of order: current {} is before previous {}", 
                    timestamp, prev_timestamp));
            }
        }
        
        Ok(())
    }
}