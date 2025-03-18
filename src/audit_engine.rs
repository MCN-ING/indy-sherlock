use crate::config::trust_store::TrustStoreConfig;
use crate::detector::{AnomalyDetector, AnomalyFinding};
use crate::fetcher::LedgerFetcher;
use crate::parser::{ParsedTransaction, TransactionParserRegistry};
use crate::validator::{ValidationEngine, ValidationResult, ValidationFinding, ValidationSeverity};
use crate::cache::AuditCache;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use tracing::{info, warn};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

/// Configures what components should be used during an audit
#[derive(Debug, Clone)]
pub struct AuditOptions {
   /// Whether to validate transaction state proofs
   pub validate_state_proofs: bool,
    /// Whether to validate transaction formats
    pub validate_formats: bool,
    /// Whether to validate transaction permissions
    pub validate_permissions: bool,
    /// Whether to validate transaction sequences
    pub validate_sequences: bool,
    /// Whether to detect anomalies
    pub detect_anomalies: bool,
    /// Start sequence number for audit
    pub start_seq_no: i32,
    /// Number of transactions to audit
    pub count: i32,
    /// Maximum batch size for transaction fetching
    pub batch_size: i32,
    /// Whether to use parallel processing
    pub parallel: bool,
    /// Parallelism level if parallel is true
    pub parallelism: usize,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            validate_state_proofs: true,
            validate_formats: true,
            validate_permissions: true,
            validate_sequences: true,
            detect_anomalies: true,
            start_seq_no: 1,
            count: 1000,
            batch_size: 100,
            parallel: true,
            parallelism: 10,
        }
    }
}

/// The severity level of an audit finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<ValidationSeverity> for FindingSeverity {
    fn from(severity: ValidationSeverity) -> Self {
        match severity {
            ValidationSeverity::Critical => FindingSeverity::Critical,
            ValidationSeverity::Error => FindingSeverity::High,
            ValidationSeverity::Warning => FindingSeverity::Medium,
            ValidationSeverity::Info => FindingSeverity::Info,
        }
    }
}

/// The type of an audit finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingType {
    ValidationError,
    Anomaly,
    StateProofIssue,
    FormatViolation,
    PermissionViolation,
    SequenceViolation,
    Other(String),
}

/// An individual finding from the audit process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub id: String,
    pub seq_no: i32,
    pub txn_time: u64,
    pub severity: FindingSeverity,
    pub finding_type: FindingType,
    pub description: String,
    pub details: Option<String>,
    pub related_dids: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

impl AuditFinding {
    pub fn new(
        seq_no: i32,
        txn_time: u64,
        severity: FindingSeverity,
        finding_type: FindingType,
        description: &str,
        details: Option<&str>,
        related_dids: Vec<String>,
    ) -> Self {
        Self {
            id: format!("FIND-{}-{}", seq_no, chrono::Utc::now().timestamp()),
            seq_no,
            txn_time,
            severity,
            finding_type,
            description: description.to_string(),
            details: details.map(|s| s.to_string()),
            related_dids,
            timestamp: Utc::now(),
        }
    }

    pub fn from_validation_finding(
        seq_no: i32,
        txn_time: u64,
        validation_finding: &ValidationFinding,
        related_dids: Vec<String>,
    ) -> Self {
        let finding_type = match validation_finding.message.to_lowercase() {
            msg if msg.contains("state proof") => FindingType::StateProofIssue,  
            msg if msg.contains("format") => FindingType::FormatViolation,
            msg if msg.contains("permission") || msg.contains("authorized") => FindingType::PermissionViolation,
            msg if msg.contains("sequence") || msg.contains("reference") || 
                  msg.contains("schema with seq_no") => FindingType::SequenceViolation,
            _ => FindingType::ValidationError,
        };
        
        // Adjust severity for sequence violations based on context
        let severity = if let FindingType::SequenceViolation = finding_type {
            if validation_finding.severity == ValidationSeverity::Warning {
                // Downgrade sequence warnings to Medium severity
                FindingSeverity::Medium
            } else {
                FindingSeverity::from(validation_finding.severity)
            }
        } else {
            FindingSeverity::from(validation_finding.severity)
        };

        Self {
            id: format!("FIND-{}-{}", seq_no, chrono::Utc::now().timestamp()),
            seq_no,
            txn_time,
            severity,
            finding_type,
            description: validation_finding.message.clone(),
            details: validation_finding.context.clone(),
            related_dids,
            timestamp: Utc::now(),
        }
    }

    pub fn from_anomaly_finding(
        seq_no: i32,
        txn_time: u64,
        anomaly_finding: &AnomalyFinding,
    ) -> Self {
        let severity = match anomaly_finding.severity {
            crate::detector::AnomalySeverity::Critical => FindingSeverity::Critical,
            crate::detector::AnomalySeverity::High => FindingSeverity::High,
            crate::detector::AnomalySeverity::Medium => FindingSeverity::Medium, 
            crate::detector::AnomalySeverity::Low => FindingSeverity::Low,
        };

        let finding_type = FindingType::Anomaly;

        Self {
            id: format!("ANOM-{}-{}", seq_no, chrono::Utc::now().timestamp()),
            seq_no,
            txn_time,
            severity,
            finding_type,
            description: anomaly_finding.description.clone(),
            details: anomaly_finding.context.clone(),
            related_dids: anomaly_finding.related_dids.clone(),
            timestamp: Utc::now(),
        }
    }
}

/// Aggregated statistics about the audited transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatistics {
    pub total_transactions: usize,
    pub transactions_by_type: HashMap<String, usize>,
    pub transactions_by_author: HashMap<String, usize>,
    pub earliest_timestamp: u64,
    pub latest_timestamp: u64,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub info_findings: usize,
}

impl AuditStatistics {
    pub fn new() -> Self {
        Self {
            total_transactions: 0,
            transactions_by_type: HashMap::new(),
            transactions_by_author: HashMap::new(),
            earliest_timestamp: u64::MAX,
            latest_timestamp: 0,
            critical_findings: 0,
            high_findings: 0,
            medium_findings: 0,
            low_findings: 0,
            info_findings: 0,
        }
    }

    pub fn add_transaction(&mut self, txn: &ParsedTransaction) {
        self.total_transactions += 1;
        
        // Update transaction type count
        let txn_type = format!("{:?}", txn.txn_type);
        *self.transactions_by_type.entry(txn_type).or_insert(0) += 1;
        
        // Update author count
        *self.transactions_by_author.entry(txn.identifier.clone()).or_insert(0) += 1;
        
        // Update timestamp range
        if txn.txn_time < self.earliest_timestamp {
            self.earliest_timestamp = txn.txn_time;
        }
        if txn.txn_time > self.latest_timestamp {
            self.latest_timestamp = txn.txn_time;
        }
    }

    pub fn add_finding(&mut self, finding: &AuditFinding) {
        match finding.severity {
            FindingSeverity::Critical => self.critical_findings += 1,
            FindingSeverity::High => self.high_findings += 1,
            FindingSeverity::Medium => self.medium_findings += 1,
            FindingSeverity::Low => self.low_findings += 1,
            FindingSeverity::Info => self.info_findings += 1,
        }
    }

    pub fn total_findings(&self) -> usize {
        self.critical_findings + self.high_findings + self.medium_findings + self.low_findings + self.info_findings
    }
}

/// Complete audit report containing all findings and statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub ledger_id: String,
    pub start_seq_no: i32,
    pub end_seq_no: i32,
    pub timestamp: DateTime<Utc>,
    pub duration_seconds: f64,
    pub statistics: AuditStatistics,
    pub findings: Vec<AuditFinding>,
    pub options: HashMap<String, String>,
}

impl AuditReport {
    pub fn new(ledger_id: &str, start_seq_no: i32, end_seq_no: i32, duration: Duration) -> Self {
        Self {
            ledger_id: ledger_id.to_string(),
            start_seq_no,
            end_seq_no,
            timestamp: Utc::now(),
            duration_seconds: duration.as_secs_f64(),
            statistics: AuditStatistics::new(),
            findings: Vec::new(),
            options: HashMap::new(),
        }
    }
    
    /// Print a summary of the audit report to the console
    pub fn print_summary(&self) {
        println!("\n================================");
        println!("       AUDIT REPORT SUMMARY     ");
        println!("================================");
        println!("Ledger: {}", self.ledger_id);
        println!("Transactions: #{} to #{}", self.start_seq_no, self.end_seq_no);
        println!("Execution time: {:.2} seconds", self.duration_seconds);
        println!("Transactions analyzed: {}", self.statistics.total_transactions);
        
        // Print transaction type breakdown
        println!("\nTransaction types:");
        for (txn_type, count) in &self.statistics.transactions_by_type {
            println!("  - {}: {}", txn_type, count);
        }
        
        // Print findings summary
        let total_findings = self.statistics.total_findings();
        println!("\nFindings summary:");
        println!("  - Critical: {}", self.statistics.critical_findings);
        println!("  - High: {}", self.statistics.high_findings);
        println!("  - Medium: {}", self.statistics.medium_findings);
        println!("  - Low: {}", self.statistics.low_findings);
        println!("  - Info: {}", self.statistics.info_findings);
        println!("  - Total: {}", total_findings);
        
        // Print top author DIDs
        println!("\nTop transaction authors:");
        let mut authors: Vec<(&String, &usize)> = self.statistics.transactions_by_author.iter().collect();
        authors.sort_by(|a, b| b.1.cmp(a.1));
        for (author, count) in authors.iter().take(5) {
            println!("  - {}: {} transactions", author, count);
        }
        
        // Print critical and high findings
        if self.statistics.critical_findings > 0 || self.statistics.high_findings > 0 {
            println!("\nCRITICAL and HIGH severity findings:");
            let mut count = 0;
            for finding in &self.findings {
                if finding.severity == FindingSeverity::Critical || finding.severity == FindingSeverity::High {
                    let severity_str = match finding.severity {
                        FindingSeverity::Critical => "CRITICAL",
                        FindingSeverity::High => "HIGH",
                        FindingSeverity::Medium => "MEDIUM",
                        FindingSeverity::Low => "LOW",
                        FindingSeverity::Info => "INFO",
                    };
                    println!("  - [{}] {}", severity_str, finding.description);
                    count += 1;
                    if count >= 5 {
                        println!("  - ... and {} more", 
                            self.statistics.critical_findings + self.statistics.high_findings - 5);
                        break;
                    }
                }
            }
        }
        
        println!("\nFull report available in the audit report file.");
        println!("================================\n");
    }

    pub fn add_option(&mut self, key: &str, value: &str) {
        self.options.insert(key.to_string(), value.to_string());
    }

    pub fn add_finding(&mut self, finding: AuditFinding) {
        self.statistics.add_finding(&finding);
        self.findings.push(finding);
    }

    pub fn add_transaction(&mut self, txn: &ParsedTransaction) {
        self.statistics.add_transaction(txn);
    }

    pub fn sort_findings_by_severity(&mut self) {
        self.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// The main audit engine that coordinates all the auditing components
pub struct AuditEngine {
    fetcher: LedgerFetcher,
    parser_registry: TransactionParserRegistry,
    validation_engine: ValidationEngine,
    anomaly_detector_factory: Option<fn() -> AnomalyDetector>,
    trust_store: Arc<TrustStoreConfig>,
    ledger_id: String,
}

impl AuditEngine {
    pub async fn new(
        fetcher: LedgerFetcher, 
        trust_store: Arc<TrustStoreConfig>,
        ledger_id: &str,
    ) -> Self {
        Self {
            fetcher,
            parser_registry: TransactionParserRegistry::new(),
            validation_engine: ValidationEngine::new(),
            anomaly_detector_factory: None,
            trust_store,
            ledger_id: ledger_id.to_string(),
        }
    }

    pub fn with_validation_engine(mut self, validation_engine: ValidationEngine) -> Self {
        self.validation_engine = validation_engine;
        self
    }

    pub fn with_anomaly_detector_factory(mut self, detector_factory: fn() -> AnomalyDetector) -> Self {
        self.anomaly_detector_factory = Some(detector_factory);
        self
    }

    pub async fn audit_with_cache(&mut self, mut options: AuditOptions, config_dir: &Path, force_full: bool) -> Result<AuditReport> {
        // Load cache
        let mut cache = AuditCache::load(config_dir, &self.ledger_id)?;
        
        // Try to get the current ledger size
        let maybe_ledger_size = self.fetcher.get_ledger_size().await;
        
        // Determine start sequence number
        let start_seq_no = if force_full {
            // If forcing full audit, start from the beginning
            1
        } else if options.start_seq_no > 0 {
            // If specific start is provided, use that
            options.start_seq_no
        } else {
            // Otherwise start from where we left off
            cache.get_next_seq_no()
        };
        
        // When force_full is true, make sure start_seq_no is 1
        // and also update options.start_seq_no for consistency
        if force_full {
            options.start_seq_no = 1;
        }
        
        // Special handling when the cached position is beyond the ledger size
        if let Ok(size) = &maybe_ledger_size {
            if start_seq_no > *size {
                info!("Cached sequence number ({}) is higher than ledger size ({}), no new transactions to audit", 
                      start_seq_no, size);
                
                // Update cache to match the current ledger size
                cache.update(*size);
                cache.save(config_dir)?;
                
                // Create a report indicating no new transactions
                let mut report = AuditReport::new(
                    &self.ledger_id,
                    *size,
                    *size, // Same value for start and end to indicate empty range
                    std::time::Duration::from_secs(0),
                );
                
                // Add information to the report
                report.add_option("status", "no_new_transactions");
                report.add_option("ledger_size", &size.to_string());
                report.add_option("last_transaction", &size.to_string());
                
                println!("\n================================");
                println!("       AUDIT STATUS UPDATE      ");
                println!("================================");
                println!("Ledger: {}", self.ledger_id);
                println!("Status: No new transactions to audit");
                println!("Current ledger size: {} transactions", size);
                println!("Last audited transaction: #{}", size);
                println!("================================\n");
                
                return Ok(report);
            }
        }
        
        // Standard case: Start is within ledger bounds
        let adjusted_start_seq_no = start_seq_no;
        
        // Determine count based on ledger size if not specified
        let count = if options.count <= 0 {
            if let Ok(size) = &maybe_ledger_size {
                size - adjusted_start_seq_no + 1
            } else {
                if let Err(e) = &maybe_ledger_size {
                    warn!("Failed to determine ledger size: {}", e);
                }
                options.count.max(1000) // Default to 1000 if we can't determine size
            }
        } else {
            // If user specified count, check against ledger size
            if let Ok(size) = &maybe_ledger_size {
                // Make sure we don't exceed the ledger
                std::cmp::min(options.count, *size - adjusted_start_seq_no + 1)
            } else {
                options.count
            }
        };
        
        // If no new transactions, return empty report
        if count <= 0 {
            info!("No new transactions to audit");
            
            let mut report = AuditReport::new(
                &self.ledger_id,
                adjusted_start_seq_no,
                adjusted_start_seq_no - 1, // Empty range
                std::time::Duration::from_secs(0),
            );
            
            // Add information to the report
            report.add_option("status", "no_new_transactions");
            if let Ok(size) = &maybe_ledger_size {
                report.add_option("ledger_size", &size.to_string());
                report.add_option("last_transaction", &size.to_string());
                
                println!("\n================================");
                println!("       AUDIT STATUS UPDATE      ");
                println!("================================");
                println!("Ledger: {}", self.ledger_id);
                println!("Status: No new transactions to audit");
                println!("Current ledger size: {} transactions", size);
                println!("Last audited transaction: #{}", adjusted_start_seq_no - 1);
                println!("================================\n");
            } else {
                println!("\n================================");
                println!("       AUDIT STATUS UPDATE      ");
                println!("================================");
                println!("Ledger: {}", self.ledger_id);
                println!("Status: No new transactions to audit");
                println!("Last audited transaction: #{}", adjusted_start_seq_no - 1);
                println!("================================\n");
            }
            
            return Ok(report);
        }
        
        // Run the audit with the calculated range
        info!("Auditing transactions {} to {}", adjusted_start_seq_no, adjusted_start_seq_no + count - 1);
        let report = self.audit(AuditOptions {
            start_seq_no: adjusted_start_seq_no,
            count,
            ..options
        }).await?;
        
        // Update cache with new audit information
        // Make sure we don't update the cache with a value higher than the ledger size
        if let Ok(size) = maybe_ledger_size {
            let end_seq_no = std::cmp::min(report.end_seq_no, size);
            cache.update(end_seq_no);
        } else {
            cache.update(report.end_seq_no);
        }
        
        // Save updated cache
        cache.save(config_dir)?;
        
        Ok(report)
    }

    /// Main audit method that orchestrates the entire audit process
    pub async fn audit(&mut self, options: AuditOptions) -> Result<AuditReport> {
        let start_time = Instant::now();
        println!("Starting audit on ledger {} with options: {:#?}", self.ledger_id, options);

        // Initialize report
        let mut report = AuditReport::new(
            &self.ledger_id,
            options.start_seq_no,
            options.start_seq_no + options.count - 1,
            Duration::from_secs(0), // Will update at the end
        );

        // Add audit options to report
        report.add_option("validate_state_proofs", &options.validate_state_proofs.to_string());
        report.add_option("validate_formats", &options.validate_formats.to_string());
        report.add_option("validate_permissions", &options.validate_permissions.to_string());
        report.add_option("validate_sequences", &options.validate_sequences.to_string());
        report.add_option("detect_anomalies", &options.detect_anomalies.to_string());
        report.add_option("parallel", &options.parallel.to_string());

        // Phase 1: Fetch transactions
        println!("Phase 1: Fetching transactions...");
        let raw_txns = if options.parallel {
            self.fetcher.get_transactions_in_range_parallel(
                options.start_seq_no, 
                options.count, 
                options.parallelism
            ).await?
        } else {
            self.fetcher.get_transactions_in_range_with_progress(
                options.start_seq_no, 
                options.count,
                options.batch_size
            ).await?
        };

        println!("Fetched {} transactions", raw_txns.len());
        if raw_txns.is_empty() {
            println!("No transactions found in the specified range.");
            return Ok(report);
        }

        // Phase 2: Parse transactions
        println!("Phase 2: Parsing transactions...");
        let mut parsed_txns = Vec::with_capacity(raw_txns.len());
        let mut parse_errors = 0;

        for raw_txn in &raw_txns {
            match self.parser_registry.parse_transaction(raw_txn).await {
                Ok(parsed) => {
                    // Add to statistics
                    report.add_transaction(&parsed);
                    parsed_txns.push(parsed);
                },
                Err(e) => {
                    parse_errors += 1;
                    report.add_finding(AuditFinding::new(
                        raw_txn.seq_no,
                        raw_txn.txn_time,
                        FindingSeverity::Medium,
                        FindingType::Other("ParsingError".to_string()),
                        &format!("Failed to parse transaction: {}", e),
                        None,
                        vec![],
                    ));
                }
            }
        }

        println!("Successfully parsed {} transactions ({} errors)", parsed_txns.len(), parse_errors);

        // Phase 3: Validate transactions
        if options.validate_state_proofs || options.validate_formats || 
           options.validate_permissions || options.validate_sequences {
            println!("Phase 3: Validating transactions...");
            
            // Pre-process transactions for sequencing rules if needed
            if options.validate_sequences {
                use crate::validator::sequence_rules::SequenceValidationRule;
                
                println!("Pre-processing transactions for sequence validation...");
                
                // Pre-process schemas and create a new SequenceValidationRule
                let mut seq_rule = SequenceValidationRule::new();
                
                // Process all transactions to build sequence information
                for txn in &parsed_txns {
                    seq_rule.process_transaction(txn);
                }
                
                // Update the validation engine with this pre-processed data
                self.validation_engine.update_sequence_rule(seq_rule);
            }
            
            for parsed_txn in &parsed_txns {
                match self.validation_engine.validate_transaction(parsed_txn).await {
                    Ok(validation_result) => {
                        for finding in validation_result.findings {
                            report.add_finding(AuditFinding::from_validation_finding(
                                parsed_txn.seq_no,
                                parsed_txn.txn_time,
                                &finding,
                                vec![parsed_txn.identifier.clone()],
                            ));
                        }
                    },
                    Err(e) => {
                        report.add_finding(AuditFinding::new(
                            parsed_txn.seq_no,
                            parsed_txn.txn_time,
                            FindingSeverity::Medium,
                            FindingType::Other("ValidationError".to_string()),
                            &format!("Validation engine error: {}", e),
                            None,
                            vec![parsed_txn.identifier.clone()],
                        ));
                    }
                }
            }
        }

        // Phase 4: Detect anomalies
        if options.detect_anomalies {
            if let Some(detector_factory) = self.anomaly_detector_factory {
                println!("Phase 4: Detecting anomalies...");
                
                // Create a fresh detector instance
                let mut detector = detector_factory();
                
                // Build baseline from the parsed transactions
                detector.build_baseline(&parsed_txns);
                
                // Now detect anomalies
                let anomalies = detector.detect_anomalies(&parsed_txns);
                
                for anomaly in anomalies {
                    // Find the referenced transaction for getting the timestamp
                    let txn_time = anomaly.related_transactions.first()
                        .and_then(|seq_no| parsed_txns.iter().find(|txn| txn.seq_no == *seq_no))
                        .map(|txn| txn.txn_time)
                        .unwrap_or(0);
                    
                    report.add_finding(AuditFinding::from_anomaly_finding(
                        anomaly.related_transactions.first().copied().unwrap_or(0),
                        txn_time,
                        &anomaly,
                    ));
                }
            } else {
                println!("Skipping anomaly detection: no detector configured");
            }
        }

        // Sort findings by severity
        report.sort_findings_by_severity();

        // Update report duration
        report.duration_seconds = start_time.elapsed().as_secs_f64();

        println!("Audit completed in {:.2}s with {} findings", 
            report.duration_seconds, report.statistics.total_findings());

        Ok(report)
    }

    /// Validates a single transaction and returns the validation result
    pub async fn validate_transaction(&mut self, seq_no: i32) -> Result<ValidationResult> {
        // Fetch the transaction
        let raw_txn = self.fetcher.get_transaction(seq_no).await
            .context("Failed to fetch transaction")?;
        
        // Parse the transaction
        let parsed_txn = self.parser_registry.parse_transaction(&raw_txn).await
            .context("Failed to parse transaction")?;
        
        // Validate the transaction
        self.validation_engine.validate_transaction(&parsed_txn).await
            .context("Failed to validate transaction")
    }

    /// Detect anomalies in a single transaction
    pub async fn detect_anomalies_in_transaction(&mut self, seq_no: i32) -> Result<Vec<AnomalyFinding>> {
        if let Some(detector_factory) = self.anomaly_detector_factory {
            // Fetch and parse the transaction
            let raw_txn = self.fetcher.get_transaction(seq_no).await
                .context("Failed to fetch transaction")?;
            
            let parsed_txn = self.parser_registry.parse_transaction(&raw_txn).await
                .context("Failed to parse transaction")?;
            
            // We need a baseline for comparison, so fetch some recent transactions
            let recent_txns = self.fetcher.get_transactions_in_range(
                std::cmp::max(1, seq_no - 100), 
                100
            ).await?;
            
            let mut parsed_recent_txns = Vec::new();
            for raw_recent in recent_txns {
                if let Ok(parsed) = self.parser_registry.parse_transaction(&raw_recent).await {
                    parsed_recent_txns.push(parsed);
                }
            }
            
            // Create a new detector instance
            let mut detector = detector_factory();
            detector.build_baseline(&parsed_recent_txns);
            
            // Check for anomalies
            Ok(detector.detect_anomalies(&[parsed_txn]))
        } else {
            Ok(Vec::new())
        }
    }
}