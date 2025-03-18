use std::collections::{HashMap, HashSet};

use crate::parser::{ParsedTransaction, TransactionData, TransactionType};
use super::{AnomalyFinding, AnomalyType, AnomalySeverity};

/// Specialized detector for tracking and analyzing schema changes
pub struct SchemaModificationDetector {
    // Track schemas by name -> version -> attributes
    schemas: HashMap<String, HashMap<String, Vec<String>>>,
    // Track who has published schemas
    schema_publishers: HashMap<String, HashSet<String>>,
    // Track timestamps of schema publications
    schema_timestamps: HashMap<String, Vec<u64>>,
    // Suspicious attribute patterns
    sensitive_attribute_patterns: HashSet<String>,
}

impl SchemaModificationDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            schemas: HashMap::new(),
            schema_publishers: HashMap::new(),
            schema_timestamps: HashMap::new(),
            sensitive_attribute_patterns: HashSet::new(),
        };
        
        // Initialize common sensitive attribute patterns
        detector.sensitive_attribute_patterns.insert("ssn".to_lowercase());
        detector.sensitive_attribute_patterns.insert("social_security".to_lowercase());
        detector.sensitive_attribute_patterns.insert("tax_id".to_lowercase());
        detector.sensitive_attribute_patterns.insert("passport".to_lowercase());
        detector.sensitive_attribute_patterns.insert("credit_card".to_lowercase());
        detector.sensitive_attribute_patterns.insert("bank_account".to_lowercase());
        detector.sensitive_attribute_patterns.insert("password".to_lowercase());
        detector.sensitive_attribute_patterns.insert("secret".to_lowercase());
        detector.sensitive_attribute_patterns.insert("private_key".to_lowercase());
        detector.sensitive_attribute_patterns.insert("key".to_lowercase());
        
        detector
    }
    
    /// Update internal state with transaction data
    pub fn scan_transactions(&mut self, transactions: &[ParsedTransaction]) {
        for txn in transactions {
            if let TransactionData::Schema(schema_data) = &txn.specific_data {
                let schema_name = &schema_data.data.name;
                let schema_version = &schema_data.data.version;
                let attributes = &schema_data.data.attr_names;
                
                // Track the schema
                self.schemas
                    .entry(schema_name.clone())
                    .or_default()
                    .insert(schema_version.clone(), attributes.clone());
                
                // Track the publisher
                self.schema_publishers
                    .entry(schema_name.clone())
                    .or_default()
                    .insert(txn.identifier.clone());
                
                // Track the timestamp
                self.schema_timestamps
                    .entry(schema_name.clone())
                    .or_default()
                    .push(txn.txn_time);
            }
        }
    }
    
    /// Detect suspicious schema modifications
    pub fn detect_suspicious_modifications(&self, transactions: &[ParsedTransaction]) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();
        
        // Process only schema transactions
        let schema_txns: Vec<&ParsedTransaction> = transactions.iter()
            .filter(|txn| matches!(txn.txn_type, TransactionType::SCHEMA))
            .collect();
            
        if schema_txns.is_empty() {
            return findings;
        }
        
        // Detect sensitive attributes
        self.detect_sensitive_attributes(&schema_txns, &mut findings);
        
        // Detect attribute removals in schema versions
        self.detect_attribute_removals(&schema_txns, &mut findings);
        
        // Detect unusual schema naming patterns (typosquatting)
        self.detect_unusual_naming(&schema_txns, &mut findings);
        
        // Detect excessive versioning
        self.detect_excessive_versions(&schema_txns, &mut findings);
        
        // Detect schema publisher changes
        self.detect_publisher_changes(&schema_txns, &mut findings);
        
        findings
    }
    
    fn detect_sensitive_attributes(&self, transactions: &[&ParsedTransaction], findings: &mut Vec<AnomalyFinding>) {
        for txn in transactions {
            if let TransactionData::Schema(schema_data) = &txn.specific_data {
                let schema_name = &schema_data.data.name;
                let schema_version = &schema_data.data.version;
                let attributes = &schema_data.data.attr_names;
                
                let sensitive_attrs: Vec<&String> = attributes.iter()
                    .filter(|attr| {
                        let attr_lower = attr.to_lowercase();
                        self.sensitive_attribute_patterns.iter().any(|pattern| attr_lower.contains(pattern))
                    })
                    .collect();
                
                if !sensitive_attrs.is_empty() {
                    findings.push(AnomalyFinding::new(
                        AnomalyType::SchemaModification,
                        AnomalySeverity::Medium,
                        &format!(
                            "Schema '{} v{}' contains potentially sensitive attributes: {}",
                            schema_name,
                            schema_version,
                            sensitive_attrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
                        ),
                        vec![txn.seq_no],
                        vec![txn.identifier.clone()],
                    ));
                }
                
                // Check for unusually large number of attributes
                if attributes.len() > 20 {
                    findings.push(AnomalyFinding::new(
                        AnomalyType::SchemaModification,
                        AnomalySeverity::Low,
                        &format!(
                            "Schema '{} v{}' has an unusually large number of attributes: {}",
                            schema_name,
                            schema_version,
                            attributes.len()
                        ),
                        vec![txn.seq_no],
                        vec![txn.identifier.clone()],
                    ));
                }
            }
        }
    }
    
    fn detect_attribute_removals(&self, transactions: &[&ParsedTransaction], findings: &mut Vec<AnomalyFinding>) {
        for txn in transactions {
            if let TransactionData::Schema(schema_data) = &txn.specific_data {
                let schema_name = &schema_data.data.name;
                let schema_version = &schema_data.data.version;
                let current_attrs = &schema_data.data.attr_names;
                
                // Check if we have previous versions
                if let Some(schema_versions) = self.schemas.get(schema_name) {
                    // Skip if this is the first version we've seen
                    if schema_versions.len() <= 1 || !schema_versions.contains_key(schema_version) {
                        continue;
                    }
                    
                    // Look at each previous version to detect removals
                    for (prev_version, prev_attrs) in schema_versions.iter() {
                        // Skip comparing to self
                        if prev_version == schema_version {
                            continue;
                        }
                        
                        // Compare version strings as semantic versions to ensure proper ordering
                        if is_newer_version(schema_version, prev_version) {
                            // Find removed attributes
                            let removed_attrs: Vec<&String> = prev_attrs.iter()
                                .filter(|attr| !current_attrs.contains(attr))
                                .collect();
                                
                            if !removed_attrs.is_empty() {
                                findings.push(AnomalyFinding::new(
                                    AnomalyType::SchemaModification,
                                    AnomalySeverity::Medium,
                                    &format!(
                                        "Schema '{}' removed attributes in version {} that were present in version {}: {}",
                                        schema_name,
                                        schema_version,
                                        prev_version,
                                        removed_attrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
                                    ),
                                    vec![txn.seq_no],
                                    vec![txn.identifier.clone()],
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    
    fn detect_unusual_naming(&self, transactions: &[&ParsedTransaction], findings: &mut Vec<AnomalyFinding>) {
        let all_schema_names: HashSet<String> = self.schemas.keys().cloned().collect();
        
        for txn in transactions {
            if let TransactionData::Schema(schema_data) = &txn.specific_data {
                let schema_name = &schema_data.data.name;
                
                // Check for typosquatting (similar names with small differences)
                for existing_name in &all_schema_names {
                    if schema_name != existing_name && 
                       string_similarity(schema_name, existing_name) > 0.8 && 
                       string_similarity(schema_name, existing_name) < 1.0 {
                        
                        findings.push(AnomalyFinding::new(
                            AnomalyType::SchemaModification,
                            AnomalySeverity::High,
                            &format!(
                                "Schema name '{}' is suspiciously similar to existing schema '{}'",
                                schema_name,
                                existing_name
                            ),
                            vec![txn.seq_no],
                            vec![txn.identifier.clone()],
                        ));
                    }
                }
                
                // Check for unusual characters in schema name
                if !schema_name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ' ') {
                    findings.push(AnomalyFinding::new(
                        AnomalyType::SchemaModification,
                        AnomalySeverity::Low,
                        &format!(
                            "Schema name '{}' contains unusual characters",
                            schema_name
                        ),
                        vec![txn.seq_no],
                        vec![txn.identifier.clone()],
                    ));
                }
            }
        }
    }
    
    fn detect_excessive_versions(&self, transactions: &[&ParsedTransaction], findings: &mut Vec<AnomalyFinding>) {
        for txn in transactions {
            if let TransactionData::Schema(schema_data) = &txn.specific_data {
                let schema_name = &schema_data.data.name;
                
                // Check for excessive versions
                if let Some(schema_versions) = self.schemas.get(schema_name) {
                    if schema_versions.len() > 5 {
                        findings.push(AnomalyFinding::new(
                            AnomalyType::SchemaModification,
                            AnomalySeverity::Low,
                            &format!(
                                "Schema '{}' has an unusually high number of versions: {}",
                                schema_name,
                                schema_versions.len()
                            ),
                            vec![txn.seq_no],
                            vec![txn.identifier.clone()],
                        ));
                    }
                }
                
                // Check for rapid versioning
                if let Some(timestamps) = self.schema_timestamps.get(schema_name) {
                    if timestamps.len() > 2 {
                        let mut sorted_timestamps = timestamps.clone();
                        sorted_timestamps.sort();
                        
                        // Check if multiple versions were created within a short time
                        for i in 1..sorted_timestamps.len() {
                            let time_diff = sorted_timestamps[i] - sorted_timestamps[i-1];
                            
                            // If less than 1 hour between versions
                            if time_diff < 3600 {
                                findings.push(AnomalyFinding::new(
                                    AnomalyType::SchemaModification,
                                    AnomalySeverity::Medium,
                                    &format!(
                                        "Rapid schema versioning detected for '{}': multiple versions created within {} seconds",
                                        schema_name,
                                        time_diff
                                    ),
                                    vec![txn.seq_no],
                                    vec![txn.identifier.clone()],
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    
    fn detect_publisher_changes(&self, transactions: &[&ParsedTransaction], findings: &mut Vec<AnomalyFinding>) {
        for txn in transactions {
            if let TransactionData::Schema(schema_data) = &txn.specific_data {
                let schema_name = &schema_data.data.name;
                
                // Check if schema was previously published by a different DID
                if let Some(publishers) = self.schema_publishers.get(schema_name) {
                    // Skip if this is the first publisher or if this DID has published this schema before
                    if publishers.len() > 1 && !publishers.contains(&txn.identifier) {
                        findings.push(AnomalyFinding::new(
                            AnomalyType::SchemaModification,
                            AnomalySeverity::High,
                            &format!(
                                "Schema '{}' was published by a new DID {}. Previous publishers: {}",
                                schema_name,
                                txn.identifier,
                                publishers.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                            ),
                            vec![txn.seq_no],
                            vec![txn.identifier.clone()],
                        ));
                    }
                }
            }
        }
    }
}

// Helper function to check if version A is newer than version B
// Very basic semver comparison
fn is_newer_version(version_a: &str, version_b: &str) -> bool {
    let parse_version = |v: &str| -> Vec<u32> {
        v.split('.')
         .filter_map(|part| part.parse::<u32>().ok())
         .collect()
    };
    
    let parts_a = parse_version(version_a);
    let parts_b = parse_version(version_b);
    
    for i in 0..std::cmp::min(parts_a.len(), parts_b.len()) {
        if parts_a[i] > parts_b[i] {
            return true;
        } else if parts_a[i] < parts_b[i] {
            return false;
        }
    }
    
    // If we get here, the common parts are equal, so the longer one is newer
    parts_a.len() > parts_b.len()
}

// Simple string similarity function using Levenshtein distance
fn string_similarity(s1: &str, s2: &str) -> f64 {
    let s1_len = s1.chars().count();
    let s2_len = s2.chars().count();
    
    if s1_len == 0 || s2_len == 0 {
        if s1_len == s2_len {
            return 1.0;
        } else {
            return 0.0;
        }
    }
    
    let distance = levenshtein_distance(s1, s2);
    let max_len = std::cmp::max(s1_len, s2_len) as f64;
    
    1.0 - (distance as f64 / max_len)
}

// Levenshtein distance implementation
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    
    let m = s1_chars.len();
    let n = s2_chars.len();
    
    let mut dp = vec![vec![0; n + 1]; m + 1];
    
    for i in 0..=m {
        dp[i][0] = i;
    }
    
    for j in 0..=n {
        dp[0][j] = j;
    }
    
    for i in 1..=m {
        for j in 1..=n {
            let cost = if s1_chars[i - 1] == s2_chars[j - 1] { 0 } else { 1 };
            
            dp[i][j] = std::cmp::min(
                dp[i - 1][j] + 1,                 // deletion
                std::cmp::min(
                    dp[i][j - 1] + 1,             // insertion
                    dp[i - 1][j - 1] + cost       // substitution
                )
            );
        }
    }
    
    dp[m][n]
}