use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};

use crate::parser::{ParsedTransaction, TransactionData, Role};

pub mod role_changes;
pub mod schema_modifications;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyType {
    HighTransactionFrequency,
    RoleElevation,
    NodeConfigurationChange,
    UnexpectedTransactionSequence,
    UnauthorizedAction,
    SchemaModification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyFinding {
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
    pub related_transactions: Vec<i32>, // Sequence numbers of related transactions
    pub related_dids: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub context: Option<String>,
}

impl AnomalyFinding {
    pub fn new(
        anomaly_type: AnomalyType,
        severity: AnomalySeverity,
        description: &str,
        related_transactions: Vec<i32>,
        related_dids: Vec<String>,
    ) -> Self {
        Self {
            anomaly_type,
            severity,
            description: description.to_string(),
            related_transactions,
            related_dids,
            timestamp: Utc::now(),
            context: None,
        }
    }

    pub fn with_context(
        anomaly_type: AnomalyType,
        severity: AnomalySeverity,
        description: &str,
        related_transactions: Vec<i32>,
        related_dids: Vec<String>,
        context: &str,
    ) -> Self {
        let mut finding = Self::new(
            anomaly_type,
            severity,
            description,
            related_transactions, 
            related_dids,
        );
        finding.context = Some(context.to_string());
        finding
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransactionBaseline {
    // Average transactions per day for each DID
    pub did_transaction_rates: HashMap<String, f64>,
    // Tracked DIDs with their roles
    pub did_roles: HashMap<String, Role>,
    // Normal hours of operation (hour of day, 0-23)
    pub normal_hours: (u8, u8),
    // Known node configurations
    pub node_configurations: HashMap<String, NodeConfiguration>,
    // Last observed schema sequence numbers for credential def validation
    pub schema_sequence_numbers: HashSet<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfiguration {
    pub alias: String,
    pub node_ip: Option<String>,
    pub node_port: Option<u32>,
    pub client_ip: Option<String>,
    pub client_port: Option<u32>,
    pub services: Option<Vec<String>>,
    pub last_updated: DateTime<Utc>,
}

pub struct AnomalyDetector {
    pub baseline: Option<TransactionBaseline>,
    // Configurable thresholds
    pub frequency_threshold: usize,   // Transactions per day from a single DID
    pub time_window: Duration,        // For frequency checks
    pub schema_detector: schema_modifications::SchemaModificationDetector,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            baseline: None,
            frequency_threshold: 100,  // Default: flag if > 100 txns per day from one DID
            time_window: Duration::days(1),
            schema_detector: schema_modifications::SchemaModificationDetector::new(),
        }
    }

    pub fn with_thresholds(
        frequency_threshold: usize,
    
    ) -> Self {
        Self {
            baseline: None,
            frequency_threshold,
            time_window: Duration::days(1),
            schema_detector: schema_modifications::SchemaModificationDetector::new(),
        }
    }

    pub fn build_baseline(&mut self, transactions: &[ParsedTransaction]) {
        let mut baseline = TransactionBaseline::default();


        // Group transactions by DID
        let mut did_transactions: HashMap<String, Vec<&ParsedTransaction>> = HashMap::new();
        
        // Update schema detector with baseline data
        self.schema_detector.scan_transactions(transactions);
        
        for txn in transactions {
            did_transactions
                .entry(txn.identifier.clone())
                .or_default()
                .push(txn);
            
            // Track DID roles
            if let TransactionData::Nym(nym_data) = &txn.specific_data {
                if let Some(role_str) = &nym_data.role {
                    // Target DID
                    let role = match role_str.as_str() {
                        "0" => Role::Trustee,
                        "2" => Role::Steward,
                        "101" => Role::EndorserTrustAnchor,
                        "201" => Role::Network,
                        _ => Role::Unknown(role_str.clone()),
                    };
                    baseline.did_roles.insert(nym_data.dest.clone(), role);
                }
            }
            
            // Track node configurations
            if let TransactionData::Node(node_data) = &txn.specific_data {
                baseline.node_configurations.insert(
                    node_data.alias.clone(),
                    NodeConfiguration {
                        alias: node_data.alias.clone(),
                        node_ip: node_data.node_ip.clone(),
                        node_port: node_data.node_port,
                        client_ip: node_data.client_ip.clone(),
                        client_port: node_data.client_port,
                        services: node_data.services.clone(),
                        last_updated: DateTime::from_timestamp(txn.txn_time as i64, 0).unwrap_or_else(|| Utc::now()
                        ),
                    },
                );
            }
            
            // Track schema sequence numbers
            if let TransactionData::Schema(_) = &txn.specific_data {
                baseline.schema_sequence_numbers.insert(txn.seq_no);
            }
        }
        
        // Calculate average transaction rates per DID
        for (did, txns) in did_transactions {
            if !txns.is_empty() {
                // Calculate transactions per day
                let days = if txns.len() > 1 {
                    let min_time = txns.iter().map(|t| t.txn_time).min().unwrap_or(0);
                    let max_time = txns.iter().map(|t| t.txn_time).max().unwrap_or(0);
                    let time_diff_seconds = max_time.saturating_sub(min_time);
                    let time_diff_days = (time_diff_seconds as f64) / (24.0 * 60.0 * 60.0);
                    time_diff_days.max(1.0) // At least 1 day
                } else {
                    1.0 // If only one transaction
                };
                
                let rate = txns.len() as f64 / days;
                baseline.did_transaction_rates.insert(did, rate);
            }
        }
        
        self.baseline = Some(baseline);
    }

    pub fn detect_anomalies(&self, transactions: &[ParsedTransaction]) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();
        
        // We need at least a baseline for meaningful anomaly detection
        let baseline = match &self.baseline {
            Some(b) => b,
            None => return findings,
        };
        
        // Track transactions per DID for frequency analysis
        let mut did_transactions: HashMap<String, Vec<&ParsedTransaction>> = HashMap::new();
        
        // Group transactions by DID for frequency analysis
        for txn in transactions {
            did_transactions
                .entry(txn.identifier.clone())
                .or_default()
                .push(txn);
        }
        
        // Check for high frequency transactions from a single DID
        self.detect_high_frequency_transactions(&did_transactions, &mut findings);
        
        // Check each transaction for anomalies
        for txn in transactions {            
            // Check for role elevations
            self.detect_role_elevation(txn, baseline, &mut findings);
            
            // Check for node configuration changes
            self.detect_node_configuration_changes(txn, baseline, &mut findings);
            
            // Check for credential defs without schemas
            self.detect_sequence_violations(txn, baseline, &mut findings);
        }
        
        // Detect schema modifications
        let schema_findings = self.schema_detector.detect_suspicious_modifications(transactions);
        findings.extend(schema_findings);
        
        findings
    }

    fn detect_high_frequency_transactions(
        &self,
        did_transactions: &HashMap<String, Vec<&ParsedTransaction>>,
        findings: &mut Vec<AnomalyFinding>,
    ) {
        for (did, txns) in did_transactions {
            if txns.len() >= self.frequency_threshold {
                // Look at transaction timestamps to determine rate
                let timestamps: Vec<u64> = txns.iter().map(|t| t.txn_time).collect();
                
                // If timestamps span is within time_window
                if !timestamps.is_empty() {
                    let min_time = *timestamps.iter().min().unwrap();
                    let max_time = *timestamps.iter().max().unwrap();
                    let span_seconds = (max_time - min_time) as i64;
                    
                    if span_seconds <= self.time_window.num_seconds() && span_seconds > 0 {
                        let rate_per_day = (txns.len() as f64) * (86400.0 / span_seconds as f64);
                        
                        // Check if we have a baseline for this DID
                        let baseline_rate = self.baseline
                            .as_ref()
                            .and_then(|b| b.did_transaction_rates.get(did))
                            .copied()
                            .unwrap_or(0.0);
                        
                        // If current rate is significantly higher than baseline or above absolute threshold
                        if rate_per_day > baseline_rate * 3.0 || rate_per_day > self.frequency_threshold as f64 {
                            let seq_numbers: Vec<i32> = txns.iter().map(|t| t.seq_no).collect();
                            
                            findings.push(AnomalyFinding::new(
                                AnomalyType::HighTransactionFrequency,
                                AnomalySeverity::Medium,
                                &format!(
                                    "High transaction frequency detected from DID {}: {} transactions at a rate of {:.1} per day (baseline: {:.1})",
                                    did, txns.len(), rate_per_day, baseline_rate
                                ),
                                seq_numbers,
                                vec![did.clone()],
                            ));
                        }
                    }
                }
            }
        }
    }

    
    fn detect_role_elevation(
        &self,
        transaction: &ParsedTransaction,
        baseline: &TransactionBaseline,
        findings: &mut Vec<AnomalyFinding>,
    ) {
        if let TransactionData::Nym(nym_data) = &transaction.specific_data {
            if let Some(role_str) = &nym_data.role {
                // Get the new role being assigned
                let new_role = match role_str.as_str() {
                    "0" => Role::Trustee,
                    "2" => Role::Steward,
                    "101" => Role::EndorserTrustAnchor,
                    "201" => Role::Network,
                    _ => Role::Unknown(role_str.clone()),
                };
                
                // Check if we have a previous role for this DID
                if let Some(previous_role) = baseline.did_roles.get(&nym_data.dest) {
                    // Determine if this is a role elevation
                    let is_elevation = match (previous_role, &new_role) {
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
                                "Role elevation detected for DID {}: {:?} -> {:?}",
                                nym_data.dest, previous_role, new_role
                            ),
                            vec![transaction.seq_no],
                            vec![transaction.identifier.clone(), nym_data.dest.clone()],
                        ));
                    }
                }
            }
        }
    }

    fn detect_node_configuration_changes(
        &self,
        transaction: &ParsedTransaction,
        baseline: &TransactionBaseline,
        findings: &mut Vec<AnomalyFinding>,
    ) {
        if let TransactionData::Node(node_data) = &transaction.specific_data {
            // Check if we have a previous configuration for this node
            if let Some(previous_config) = baseline.node_configurations.get(&node_data.alias) {
                let mut changes = Vec::new();
                
                // Check for IP changes
                if previous_config.node_ip != node_data.node_ip {
                    changes.push(format!(
                        "Node IP changed: {:?} -> {:?}",
                        previous_config.node_ip, node_data.node_ip
                    ));
                }
                
                // Check for port changes
                if previous_config.node_port != node_data.node_port {
                    changes.push(format!(
                        "Node port changed: {:?} -> {:?}",
                        previous_config.node_port, node_data.node_port
                    ));
                }
                
                // Check for client IP changes
                if previous_config.client_ip != node_data.client_ip {
                    changes.push(format!(
                        "Client IP changed: {:?} -> {:?}",
                        previous_config.client_ip, node_data.client_ip
                    ));
                }
                
                // Check for client port changes
                if previous_config.client_port != node_data.client_port {
                    changes.push(format!(
                        "Client port changed: {:?} -> {:?}",
                        previous_config.client_port, node_data.client_port
                    ));
                }
                
                // Check for service changes
                let old_services = previous_config.services.as_ref().map(|s| s.join(", ")).unwrap_or_default();
                let new_services = node_data.services.as_ref().map(|s| s.join(", ")).unwrap_or_default();
                if old_services != new_services {
                    changes.push(format!(
                        "Services changed: {} -> {}",
                        old_services, new_services
                    ));
                }
                
                // If we detected changes
                if !changes.is_empty() {
                    findings.push(AnomalyFinding::with_context(
                        AnomalyType::NodeConfigurationChange,
                        AnomalySeverity::Medium,
                        &format!(
                            "Node configuration changed for node {}",
                            node_data.alias
                        ),
                        vec![transaction.seq_no],
                        vec![transaction.identifier.clone()],
                        &changes.join("\n"),
                    ));
                }
            }
        }
    }

    fn detect_sequence_violations(
        &self,
        transaction: &ParsedTransaction,
        baseline: &TransactionBaseline,
        findings: &mut Vec<AnomalyFinding>,
    ) {
        // Check for credential def without corresponding schema
        if let TransactionData::ClaimDef(claim_def_data) = &transaction.specific_data {
            // Extract schema reference sequence number
            let schema_ref = claim_def_data.schema_ref.parse::<i32>().unwrap_or(-1);
            
            // Check if we have this schema in our baseline
            if schema_ref > 0 && !baseline.schema_sequence_numbers.contains(&schema_ref) {
                findings.push(AnomalyFinding::new(
                    AnomalyType::UnexpectedTransactionSequence,
                    AnomalySeverity::Medium,
                    &format!(
                        "Credential definition references schema #{} which was not found on the ledger",
                        schema_ref
                    ),
                    vec![transaction.seq_no],
                    vec![transaction.identifier.clone()],
                ));
            }
        }
    }
}

// A module for quick detection of common anomalies
pub mod quick_scan {
    use super::*;
    use crate::parser::{ParsedTransaction, TransactionData, Role};
    
    // Quickly detect role elevations in a batch of transactions
    pub fn detect_role_elevations(transactions: &[ParsedTransaction]) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();
        let mut did_roles: HashMap<String, (Role, i32)> = HashMap::new();
        
        // First pass: collect all DID roles
        for txn in transactions {
            if let TransactionData::Nym(nym_data) = &txn.specific_data {
                if let Some(role_str) = &nym_data.role {
                    // Get the role being assigned
                    let role = match role_str.as_str() {
                        "0" => Role::Trustee,
                        "2" => Role::Steward,
                        "101" => Role::EndorserTrustAnchor,
                        "201" => Role::Network,
                        _ => Role::Unknown(role_str.clone()),
                    };
                    
                    // Update or insert role
                    did_roles.insert(nym_data.dest.clone(), (role, txn.seq_no));
                }
            }
        }
        
        // Second pass: find role changes
        for txn in transactions {
            if let TransactionData::Nym(nym_data) = &txn.specific_data {
                if let Some(role_str) = &nym_data.role {
                    // Only check transactions that are already in our map (role updates)
                    if let Some((prev_role, prev_seq_no)) = did_roles.get(&nym_data.dest) {
                        // Skip the first occurrence
                        if *prev_seq_no != txn.seq_no {
                            // Get the new role being assigned
                            let new_role = match role_str.as_str() {
                                "0" => Role::Trustee,
                                "2" => Role::Steward,
                                "101" => Role::EndorserTrustAnchor,
                                "201" => Role::Network,
                                _ => Role::Unknown(role_str.clone()),
                            };
                            
                            // Determine if this is a role elevation
                            let is_elevation = match (prev_role, &new_role) {
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
                                        "Role elevation detected for DID {}: {:?} -> {:?}",
                                        nym_data.dest, prev_role, new_role
                                    ),
                                    vec![txn.seq_no, *prev_seq_no],
                                    vec![txn.identifier.clone(), nym_data.dest.clone()],
                                ));
                            }
                        }
                    }
                }
            }
        }
        
        findings
    }
    
    // Quickly find high-frequency transaction patterns
    pub fn detect_high_frequency(
        transactions: &[ParsedTransaction], 
        threshold: usize, 
        time_window_seconds: u64
    ) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();
        let mut did_transactions: HashMap<String, Vec<&ParsedTransaction>> = HashMap::new();
        
        // Group transactions by DID
        for txn in transactions {
            did_transactions
                .entry(txn.identifier.clone())
                .or_default()
                .push(txn);
        }
        
        // Check each DID's transaction patterns
        for (did, txns) in did_transactions {
            if txns.len() >= threshold {
                // Sort by timestamp
                let mut txn_times: Vec<(u64, i32)> = txns.iter()
                    .map(|t| (t.txn_time, t.seq_no))
                    .collect();
                txn_times.sort_by_key(|&(time, _)| time);
                
                // Sliding window to find high-frequency periods
                let mut high_freq_periods = Vec::new();
                
                for i in 0..txn_times.len() {
                    let start_time = txn_times[i].0;
                    let mut window_txns = Vec::new();
                    window_txns.push(txn_times[i].1);  // Add starting transaction
                    
                    // Look at subsequent transactions in the time window
                    for j in i+1..txn_times.len() {
                        if txn_times[j].0 - start_time <= time_window_seconds {
                            window_txns.push(txn_times[j].1);
                        } else {
                            break;
                        }
                    }
                    
                    // If we found a sufficient number in the window
                    if window_txns.len() >= threshold {
                        high_freq_periods.push((start_time, window_txns.clone()));
                    }
                }
                
                // Report findings, but avoid duplicates
                let mut reported_periods = HashSet::new();
                
                for (start_time, seq_nos) in high_freq_periods {
                    let key = format!("{}-{}", start_time, seq_nos.len());
                    if !reported_periods.contains(&key) {
                        reported_periods.insert(key);
                        
                        let dt = DateTime::from_timestamp(start_time as i64, 0).unwrap_or_else(|| Utc::now());
                        
                        findings.push(AnomalyFinding::new(
                            AnomalyType::HighTransactionFrequency,
                            AnomalySeverity::Medium,
                            &format!(
                                "DID {} submitted {} transactions in a {:.1} minute window starting at {}",
                                did, seq_nos.len(), time_window_seconds as f64 / 60.0, dt
                            ),
                            seq_nos,
                            vec![did.clone()],
                        ));
                    }
                }
            }
        }
        
        findings
    }
    
    // Quick check for suspicious schema attributes
    pub fn detect_suspicious_schemas(transactions: &[ParsedTransaction]) -> Vec<AnomalyFinding> {
        let detector = schema_modifications::SchemaModificationDetector::new();
        detector.detect_suspicious_modifications(transactions)
    }
}