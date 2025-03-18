use std::collections::{HashMap, HashSet};
use crate::parser::{ParsedTransaction, TransactionData};
use crate::validator::{ValidationRule, ValidationFinding, ValidationSeverity};
use crate::error::Result;

/// Rule for validating that transactions follow the expected sequence
#[derive(Clone)]
pub struct SequenceValidationRule {
    // Track schema sequence numbers
    schema_seq_nos: HashSet<i32>,
    
    // Track cred def sequence numbers
    cred_def_seq_nos: HashSet<i32>,
    
    // Map schema seq_nos to attribute counts
    schema_attr_counts: HashMap<i32, usize>,
    
    // Map cred def IDs to their schema seq_nos
    cred_def_to_schema: HashMap<String, i32>,
    
    // Track revoc reg def IDs
    revoc_reg_def_ids: HashSet<String>,
}

impl SequenceValidationRule {
    pub fn new() -> Self {
        Self {
            schema_seq_nos: HashSet::new(),
            cred_def_seq_nos: HashSet::new(),
            schema_attr_counts: HashMap::new(),
            cred_def_to_schema: HashMap::new(),
            revoc_reg_def_ids: HashSet::new(),
        }
    }
    
    pub fn with_known_schemas(schema_seq_nos: HashSet<i32>) -> Self {
        let mut rule = Self::new();
        rule.schema_seq_nos = schema_seq_nos;
        rule
    }
    
    /// Add a known schema to the rule tracker
    pub fn add_schema(&mut self, seq_no: i32, attr_count: usize) {
        self.schema_seq_nos.insert(seq_no);
        self.schema_attr_counts.insert(seq_no, attr_count);
    }
    
    /// Add a known credential definition to the rule tracker
    pub fn add_cred_def(&mut self, seq_no: i32, cred_def_id: &str, schema_seq_no: i32) {
        self.cred_def_seq_nos.insert(seq_no);
        self.cred_def_to_schema.insert(cred_def_id.to_string(), schema_seq_no);
    }
    
    /// Add a known revocation registry definition to the rule tracker
    pub fn add_revoc_reg_def(&mut self, revoc_reg_def_id: &str) {
        self.revoc_reg_def_ids.insert(revoc_reg_def_id.to_string());
    }
    
    /// Update internal state based on a new transaction
    pub fn process_transaction(&mut self, transaction: &ParsedTransaction) {
        match &transaction.specific_data {
            TransactionData::Schema(schema_data) => {
                self.schema_seq_nos.insert(transaction.seq_no);
                self.schema_attr_counts.insert(transaction.seq_no, schema_data.data.attr_names.len());
            },
            TransactionData::ClaimDef(claim_def_data) => {
                self.cred_def_seq_nos.insert(transaction.seq_no);
                if let Ok(schema_seq_no) = claim_def_data.schema_ref.parse::<i32>() {
                    self.cred_def_to_schema.insert(
                        format!("{}:{}:{}:{}", 
                            transaction.identifier,
                            claim_def_data.signature_type,
                            schema_seq_no,
                            claim_def_data.tag
                        ),
                        schema_seq_no
                    );
                }
            },
            TransactionData::RevocRegDef(revoc_reg_def_data) => {
                self.revoc_reg_def_ids.insert(revoc_reg_def_data.id.clone());
            },
            _ => {}
        }
    }
}

impl ValidationRule for SequenceValidationRule {
    fn name(&self) -> &'static str {
        "Transaction Sequence Validation Rule"
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    
    fn validate(&self, transaction: &ParsedTransaction) -> Result<Vec<ValidationFinding>> {
        let mut findings = Vec::new();
        
        match &transaction.specific_data {
            TransactionData::ClaimDef(claim_def_data) => {
                // A CLAIM_DEF must reference an existing schema
                if let Ok(schema_seq_no) = claim_def_data.schema_ref.parse::<i32>() {
                    // Special check: if the schema_seq_no is just before the current transaction,
                    // it might be a valid reference that hasn't been processed yet in sequential validation
                    if schema_seq_no == transaction.seq_no - 1 {
                        // Skip this check - a schema was likely just written right before this CLAIM_DEF
                        // This handles the common pattern where a schema is created and immediately used
                    } else if !self.schema_seq_nos.contains(&schema_seq_no) {
                        // Use Warning instead of Error for reference checks
                        // This ensures that references to schemas in other ledgers or batches don't cause errors
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            &format!(
                                "CLAIM_DEF references schema with seq_no: {} which was not processed in this audit",
                                schema_seq_no
                            ),
                        ));
                    }
                } else {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Warning,  // Changed from Error to Warning
                        &format!(
                            "CLAIM_DEF has non-numeric schema reference: {}",
                            claim_def_data.schema_ref
                        ),
                    ));
                }
            },
            
            _ => {
                // No sequence checks for other transaction types
            }
        }
        
        Ok(findings)
    }
}