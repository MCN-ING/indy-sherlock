pub mod signature;
pub mod permission_rules;
pub mod format_rules;
pub mod sequence_rules;
pub mod state_proof;
pub mod state_proof_rule;
use crate::parser::ParsedTransaction;
use crate::error::Result;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for ValidationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationSeverity::Info => write!(f, "INFO"),
            ValidationSeverity::Warning => write!(f, "WARNING"),
            ValidationSeverity::Error => write!(f, "ERROR"),
            ValidationSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationFinding {
    pub severity: ValidationSeverity,
    pub message: String,
    pub context: Option<String>,
}

impl ValidationFinding {
    pub fn new(severity: ValidationSeverity, message: &str) -> Self {
        Self {
            severity,
            message: message.to_string(),
            context: None,
        }
    }
    
    pub fn with_context(severity: ValidationSeverity, message: &str, context: &str) -> Self {
        Self {
            severity,
            message: message.to_string(),
            context: Some(context.to_string()),
        }
    }
}

pub struct ValidationResult {
    pub transaction_id: i32,
    pub findings: Vec<ValidationFinding>,
    pub is_valid: bool,
}

pub trait ValidationRule: Send + Sync + std::any::Any {
    fn name(&self) -> &'static str;
    fn validate(&self, transaction: &ParsedTransaction) -> Result<Vec<ValidationFinding>>;
    
    // Provide default implementations that delegate to Any trait's downcast methods
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

pub struct ValidationEngine {
    pub rules: Vec<Box<dyn ValidationRule>>,
}

impl ValidationEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
        }
    }
    
    pub fn add_rule<R: ValidationRule + 'static>(&mut self, rule: R) {
        self.rules.push(Box::new(rule));
    }
    
    // Update sequence rule with pre-processed data
    pub fn update_sequence_rule(&mut self, new_rule: crate::validator::sequence_rules::SequenceValidationRule) {
        // Remove the old sequence rule
        self.rules.retain(|rule| rule.name() != "Transaction Sequence Validation Rule");
        
        // Add the new sequence rule
        self.add_rule(new_rule);
    }
    
    pub async fn validate_transaction(&self, transaction: &ParsedTransaction) -> Result<ValidationResult> {
        let mut findings = Vec::new();
        
        for rule in &self.rules {
            match rule.validate(transaction) {
                Ok(rule_findings) => {
                    findings.extend(rule_findings);
                }
                Err(e) => {
                    findings.push(ValidationFinding::with_context(
                        ValidationSeverity::Error,
                        &format!("Rule '{}' failed to execute", rule.name()),
                        &e.to_string(),
                    ));
                }
            }
        }
        
        // A transaction is valid if there are no ERROR or CRITICAL findings
        let is_valid = !findings.iter().any(|f| {
            matches!(f.severity, ValidationSeverity::Error | ValidationSeverity::Critical)
        });
        
        Ok(ValidationResult {
            transaction_id: transaction.seq_no,
            findings,
            is_valid,
        })
    }
}