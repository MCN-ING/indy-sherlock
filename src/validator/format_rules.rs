use std::collections::HashSet;
use crate::parser::{ParsedTransaction, TransactionData};
use crate::validator::{ValidationRule, ValidationFinding, ValidationSeverity};
use crate::error::Result;

/// Rule for validating that transaction data follows expected formats
pub struct FormatValidationRule {
    schema_pattern_check: bool,      // Validates schema formats
    attrib_pattern_check: bool,      // Validates attribute formats
    credential_def_check: bool,      // Validates credential definition formats
    revocation_format_check: bool,   // Validates revocation registry formats
}

impl FormatValidationRule {
    pub fn new() -> Self {
        Self {
            schema_pattern_check: true,
            attrib_pattern_check: true,
            credential_def_check: true,
            revocation_format_check: true,
        }
    }
    
    pub fn with_options(
        schema_check: bool,
        attrib_check: bool,
        cred_def_check: bool,
        revoc_check: bool,
    ) -> Self {
        Self {
            schema_pattern_check: schema_check,
            attrib_pattern_check: attrib_check,
            credential_def_check: cred_def_check,
            revocation_format_check: revoc_check,
        }
    }
    
    // Validate schema version format (SemVer-ish)
    fn validate_schema_version(&self, version: &str) -> bool {
        let version_parts: Vec<&str> = version.split('.').collect();
        
        // Check if we have at least major.minor parts
        if version_parts.len() < 2 {
            return false;
        }
        
        // Check if all parts are numeric
        version_parts.iter().all(|part| {
            part.parse::<u32>().is_ok()
        })
    }
    
    // Validate attribute name format
    fn validate_attribute_name(&self, name: &str) -> bool {
        // Simple validation - attributes shouldn't be too long or have special chars
        !name.is_empty() && name.len() <= 256 && !name.contains(|c: char| c == '<' || c == '>' || c == '&')
    }
}

impl ValidationRule for FormatValidationRule {
    fn name(&self) -> &'static str {
        "Transaction Format Validation Rule"
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
            TransactionData::Schema(schema_data) if self.schema_pattern_check => {
                // Check schema name format
                if schema_data.data.name.trim().is_empty() {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "Schema name cannot be empty",
                    ));
                }
                
                // Check schema version format
                if !self.validate_schema_version(&schema_data.data.version) {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        &format!(
                            "Invalid schema version format: {}. Expected format: major.minor[.patch]",
                            schema_data.data.version
                        ),
                    ));
                }
                
                // Check attribute names
                if schema_data.data.attr_names.is_empty() {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "Schema must contain at least one attribute",
                    ));
                }
                
                // Check for duplicate attribute names
                let mut unique_attrs = HashSet::new();
                for attr in &schema_data.data.attr_names {
                    if !unique_attrs.insert(attr) {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            &format!("Duplicate attribute name in schema: {}", attr),
                        ));
                    }
                    
                    // Check attribute name format
                    if self.attrib_pattern_check && !self.validate_attribute_name(attr) {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            &format!("Attribute name '{}' has invalid format", attr),
                        ));
                    }
                }
            },
            TransactionData::Attrib(attrib_data) if self.attrib_pattern_check => {
                // An ATTRIB transaction should have exactly one of raw, hash, or enc
                let has_raw = attrib_data.raw.is_some();
                let has_hash = attrib_data.hash.is_some();
                let has_enc = attrib_data.enc.is_some();
                
                let attribute_count = has_raw as usize + has_hash as usize + has_enc as usize;
                
                if attribute_count == 0 {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "ATTRIB transaction must contain one of: raw, hash, or enc",
                    ));
                } else if attribute_count > 1 {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "ATTRIB transaction must contain exactly one of: raw, hash, or enc",
                    ));
                }
                
                // Check raw format if present
                if let Some(raw) = &attrib_data.raw {
                    // Raw should be a valid JSON string
                    if raw.trim().is_empty() {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            "ATTRIB raw value is empty",
                        ));
                    } else if let Err(_) = serde_json::from_str::<serde_json::Value>(raw) {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Error,
                            "ATTRIB raw value is not a valid JSON string",
                        ));
                    }
                }
            },
            TransactionData::ClaimDef(claim_def_data) if self.credential_def_check => {
                // Verify signature type is recognized
                match claim_def_data.signature_type.as_str() {
                    "CL" => {}, // Known type
                    _ => {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            &format!(
                                "Unknown signature type in CLAIM_DEF: {}",
                                claim_def_data.signature_type
                            ),
                        ));
                    }
                }
                
                // Check that tag is provided
                if claim_def_data.tag.trim().is_empty() {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Warning,
                        "CLAIM_DEF tag is empty",
                    ));
                }
                
                // Check data structure has required fields for a CL signature
                let has_primary = claim_def_data.data.get("primary").is_some();
                
                if !has_primary {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "CLAIM_DEF missing required 'primary' field in data",
                    ));
                }
                
                // Check schema_ref format
                if claim_def_data.schema_ref.trim().is_empty() {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "CLAIM_DEF schema_ref is empty",
                    ));
                } else if let Err(_) = claim_def_data.schema_ref.parse::<u64>() {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Warning,
                        &format!(
                            "CLAIM_DEF schema_ref '{}' is not a valid sequence number",
                            claim_def_data.schema_ref
                        ),
                    ));
                }
            },
            TransactionData::RevocRegDef(revoc_data) if self.revocation_format_check => {
                // Validate revocation registry defintions
                
                // Check revoc_def_type is valid
                match revoc_data.revoc_def_type.as_str() {
                    "CL_ACCUM" => {}, // This is the standard type
                    _ => {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            &format!(
                                "Unknown revocation definition type: {}",
                                revoc_data.revoc_def_type
                            ),
                        ));
                    }
                }
                
                // Validate credential definition ID format
                if !revoc_data.cred_def_id.contains(':') {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Warning,
                        &format!(
                            "Invalid credential definition ID format: {}",
                            revoc_data.cred_def_id
                        ),
                    ));
                }
                
                // Check required fields in the value
                let has_issuance_type = revoc_data.value.get("issuanceType").is_some();
                let has_max_cred_num = revoc_data.value.get("maxCredNum").is_some();
                let has_tails_hash = revoc_data.value.get("tailsHash").is_some();
                let has_tails_location = revoc_data.value.get("tailsLocation").is_some();
                
                if !has_issuance_type {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "RevocRegDef missing required 'issuanceType' field",
                    ));
                }
                
                if !has_max_cred_num {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "RevocRegDef missing required 'maxCredNum' field",
                    ));
                }
                
                if !has_tails_hash {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "RevocRegDef missing required 'tailsHash' field",
                    ));
                }
                
                if !has_tails_location {
                    findings.push(ValidationFinding::new(
                        ValidationSeverity::Error,
                        "RevocRegDef missing required 'tailsLocation' field",
                    ));
                }
            },
            TransactionData::Node(node_data) => {
                // Validate required node fields when adding a node
                if transaction.seq_no < 1000 { // Assume early transactions are node additions
                    if node_data.node_ip.is_none() {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            "NODE transaction missing node_ip field",
                        ));
                    }
                    
                    if node_data.node_port.is_none() {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            "NODE transaction missing node_port field",
                        ));
                    }
                    
                    if node_data.client_ip.is_none() {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            "NODE transaction missing client_ip field",
                        ));
                    }
                    
                    if node_data.client_port.is_none() {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Warning,
                            "NODE transaction missing client_port field",
                        ));
                    }
                    
                    if node_data.alias.trim().is_empty() {
                        findings.push(ValidationFinding::new(
                            ValidationSeverity::Error,
                            "NODE transaction has empty alias field",
                        ));
                    }
                }
            },
            _ => {
                // No specific format checks for other transaction types
            }
        }
        
        Ok(findings)
    }
}