use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use std::env;
use anyhow::{Context, Result};
use std::sync::Arc;
use std::io::Write;
use tokio::sync::Mutex;

use indy_sherlock::config::Config;
use indy_sherlock::helpers::genesis::GenesisSource;

#[derive(Parser)]
#[command(name = "indy-sherlock")]
#[command(about = "Hyperledger Indy Ledger Detective Tool - investigating transactions since 2023")]
struct Cli {
    /// Path to configuration directory
    #[arg(short, long, default_value = "~/.indy-sherlock/config")]
    config_dir: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Existing commands...
    /// List configured ledgers
    ListLedgers {},
    
    /// Add a new ledger to configuration
    AddLedger {
        /// Ledger ID for reference
        #[arg(short, long)]
        id: String,
        
        /// Display name for the ledger
        #[arg(short, long)]
        name: String,
        
        /// Genesis source (URL or file path)
        #[arg(short, long)]
        genesis_source: String,
        
        /// Optional description
        #[arg(short, long)]
        description: Option<String>,
    },
    
    /// Check connection to a ledger
    CheckConnection {
        /// Ledger ID from configuration
        #[arg(short, long)]
        ledger: String,
    },
    
    /// Analyze a specific transaction
    AnalyzeTransaction {
        /// Ledger ID from configuration
        #[arg(short, long)]
        ledger: String,
        
        /// Transaction sequence number
        #[arg(short, long)]
        seq_no: i32,
    },
    
    /// Analyze a range of transactions
    AnalyzeRange {
        /// Ledger ID from configuration
        #[arg(short, long)]
        ledger: String,
        
        /// Starting transaction sequence number
        #[arg(short, long)]
        start: i32,
        
        /// Number of transactions to analyze
        #[arg(short, long)]
        count: i32,
    },
    /// Scan ledger for DIDs and update trust store
    UpdateTrustStore {
        /// Ledger ID from configuration
        #[arg(short, long)]
        ledger: String,
        
        /// Number of transactions to scan (default: 0 for all transactions)
        #[arg(short, long, default_value = "0")]
        count: i32,
    },
    /// Detect anomalies in transactions
    DetectAnomalies {
        /// Ledger ID from configuration
        #[arg(short, long)]
        ledger: String,
        
        /// Starting transaction sequence number
        #[arg(short, long, default_value = "1")]
        start: i32,
        
        /// Number of transactions to analyze (default: 0 for all transactions)
        #[arg(short, long, default_value = "0")]
        count: i32,
        
        /// Detection mode: quick or thorough (default: quick)
        #[arg(short, long, default_value = "quick")]
        mode: String,
    },
    /// Run a comprehensive audit on the ledger
    RunAudit {
        /// Ledger ID from configuration
        #[arg(short, long)]
        ledger: String,
        
        /// Starting transaction sequence number, leave empty to use cache
        #[arg(short, long)]
        start:  Option<i32>,
        
        /// Number of transactions to analyze
        #[arg(short, long, default_value = "1000")]
        count: i32,
        
        /// Output report file path
        #[arg(short, long, default_value = "audit_report.json")]
        output: String,
        
        /// Skip state proof validation
        #[arg(long)]
        no_state_proofs: bool,
        
        /// Skip format validation
        #[arg(long)]
        no_formats: bool,
        
        /// Skip permission validation
        #[arg(long)]
        no_permissions: bool,
        
        /// Skip sequence validation
        #[arg(long)]
        no_sequences: bool,
        
        /// Skip anomaly detection
        #[arg(long)]
        no_anomalies: bool,

         /// Force full audit from the beginning
         #[arg(long)]
         force_full: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Set up logging with the specified level
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set default subscriber");
    
    // Expand ~ in config_dir path if present
    let config_dir = if cli.config_dir.starts_with("~/") {
        let home = env::var("HOME").context("HOME environment variable not set")?;
        PathBuf::from(cli.config_dir.replace("~/", &format!("{}/", home)))
    } else {
        PathBuf::from(cli.config_dir)
    };
    
    // Create config directory if it doesn't exist
    if !config_dir.exists() {
        std::fs::create_dir_all(&config_dir)
            .context("Failed to create config directory")?;
    }
    
    // Load configuration
    let config = Config::load(&config_dir)?;
    
    // Process commands
    match cli.command {

        Commands::AnalyzeTransaction { ledger, seq_no } => {
            // Get the ledger configuration
            let ledger_config = config.ledgers.get_ledger(&ledger)?;
            println!("Analyzing transaction #{} on ledger: {}", seq_no, ledger_config.name);
            
            // Get genesis source
            let genesis_source = config.ledgers.get_genesis_source(&ledger)?;
            
            // Create a ledger fetcher
            use indy_sherlock::fetcher::LedgerFetcher;
            let fetcher = LedgerFetcher::new(&genesis_source).await?;
            
            // Create Arc pointer to trust store config for sharing
            let trust_store = Arc::new(config.trust_store);
            
            // Analyze the transaction with trust store for signature verification
            indy_sherlock::analyze_transaction(&fetcher, seq_no, trust_store.clone()).await?;
            
            // Fetch the raw transaction first to get related DIDs
            let raw_txn = fetcher.get_transaction(seq_no).await?;
            
            // Create a parser registry
            use indy_sherlock::parser::TransactionParserRegistry;
            let parser_registry = TransactionParserRegistry::new();
            
            // Parse the transaction to get DIDs
            match parser_registry.parse_transaction(&raw_txn).await {
                Ok(parsed_txn) => {
                    // Get related DIDs
                    let mut related_dids = vec![parsed_txn.identifier.clone()];
                    
                    // For NYM transactions, also include target DID
                    if let indy_sherlock::parser::TransactionData::Nym(nym_data) = &parsed_txn.specific_data {
                        related_dids.push(nym_data.dest.clone());
                    }
                    
                    // Show trust information for related DIDs
                    if !related_dids.is_empty() {
                        println!("\nTrust information for related DIDs:");
                        
                        for did in related_dids {
                            // Find DID in trust store
                            let trusted_did = trust_store.trusted_dids.iter().find(|td| td.did == did);
                            
                            match trusted_did {
                                Some(td) => {
                                    let trust_status = match td.trust_level {
                                        indy_sherlock::config::trust_store::TrustLevel::FullyTrusted => "✓ Fully Trusted",
                                        indy_sherlock::config::trust_store::TrustLevel::ProvisionalTrust => "? Provisional Trust",
                                        indy_sherlock::config::trust_store::TrustLevel::Untrusted => "✗ Untrusted",
                                    };
                                    
                                    let role = td.metadata.get("role").map(|r| r.as_str()).unwrap_or("Unknown");
                                    let alias = td.metadata.get("alias").map(|a| format!(" ({})", a)).unwrap_or_default();
                                    
                                    println!("  - [{}] {}{} - Role: {}", trust_status, did, alias, role);
                                    
                                    // Show verification key status
                                    if let Some(vk) = &td.verification_key {
                                        // Make sure the verification key is long enough before trying to display parts of it
                                        if vk.len() > 16 {
                                            println!("    Verification key: {}...{}", &vk[0..8], &vk[vk.len()-8..]);
                                        } else {
                                            println!("    Verification key: {}", vk);
                                        }
                                    } else {
                                        println!("    No verification key");
                                    }
                                },
                                None => {
                                    println!("  - {} - Not in trust store", did);
                                }
                            }
                        }
                    }
                },
                Err(_) => {
                    // Skip if parsing fails - trust info already shown in analysis
                }
            }
        },
    
        Commands::AnalyzeRange { ledger, start, count } => {
            // Get the ledger configuration
            let ledger_config = config.ledgers.get_ledger(&ledger)?;
            println!("Analyzing transactions #{}-{} on ledger: {}", 
                start, start + count - 1, ledger_config.name);
            
            // Get genesis source
            let genesis_source = config.ledgers.get_genesis_source(&ledger)?;
            
            // Create a ledger fetcher
            use indy_sherlock::fetcher::LedgerFetcher;
            let fetcher = LedgerFetcher::new(&genesis_source).await?;
            
            // Fetch and analyze transactions in the range
            let raw_txns = fetcher.get_transactions_in_range(start, count).await?;
            println!("Retrieved {} transactions", raw_txns.len());
            
            // Create a parser registry
            use indy_sherlock::parser::TransactionParserRegistry;
            let parser_registry = TransactionParserRegistry::new();
            
            // Analyze each transaction
            for raw_txn in raw_txns {
                match parser_registry.parse_transaction(&raw_txn).await {
                    Ok(parsed_txn) => {
                        println!("\n{}. {} (Timestamp: {})", 
                            parsed_txn.seq_no,
                            indy_sherlock::parser::helpers::get_transaction_description(&parsed_txn),
                            parsed_txn.txn_time);
                    },
                    Err(e) => {
                        println!("\n{}. Error parsing transaction: {}", raw_txn.seq_no, e);
                    }
                }
            }
        },
        
        Commands::ListLedgers {} => {
            // Display all configured ledgers
            println!("Configured Ledgers:");
            println!("===================");
            
            if config.ledgers.ledgers.is_empty() {
                println!("No ledgers configured. Use 'add-ledger' command to add one.");
                return Ok(());
            }
            
            // Sort ledgers by name for consistent display
            let mut ledger_entries: Vec<(&String, &indy_sherlock::config::ledgers::LedgerConfig)> = 
                config.ledgers.ledgers.iter().collect();
            ledger_entries.sort_by(|a, b| a.1.name.cmp(&b.1.name));
            
            for (id, ledger) in ledger_entries {
                println!("ID: {}", id);
                println!("  Name: {}", ledger.name);
                println!("  Genesis Source: {}", ledger.genesis_source);
                if let Some(desc) = &ledger.description {
                    println!("  Description: {}", desc);
                }
                println!();
            }
        },
        
        Commands::AddLedger { id, name, genesis_source, description } => {
            // Add a new ledger to the configuration
            let config_path = config.config_dir.join("ledgers.toml");
            
            // Load current config
            let mut ledgers_config = indy_sherlock::config::ledgers::LedgersConfig::load(&config_path)?;
            
            // Check if ledger ID already exists
            if ledgers_config.ledgers.contains_key(&id) {
                return Err(anyhow::anyhow!("Ledger with ID '{}' already exists", id));
            }
            
            // Validate genesis source
            let _ = GenesisSource::from_str(&genesis_source)
                .context(format!("Invalid genesis source: {}", genesis_source))?;
            
            // Add new ledger
            ledgers_config.ledgers.insert(id.clone(), indy_sherlock::config::ledgers::LedgerConfig {
                name,
                genesis_source,
                description,
            });
            
            // Save updated config
            let config_str = toml::to_string(&ledgers_config)
                .context("Failed to serialize ledgers config")?;
            
            std::fs::write(&config_path, config_str)
                .context(format!("Failed to write ledgers config to {:?}", config_path))?;
            
            println!("Ledger '{}' added successfully", id);
        },
        
        Commands::CheckConnection { ledger } => {
            // Get the ledger configuration
            let ledger_config = config.ledgers.get_ledger(&ledger)?;
            println!("Checking connection to ledger: {}", ledger_config.name);
            
            // Get genesis source
            let genesis_source = config.ledgers.get_genesis_source(&ledger)?;
            
            // Create a ledger fetcher
            use indy_sherlock::fetcher::LedgerFetcher;
            let fetcher = LedgerFetcher::new(&genesis_source).await?;
            
            // Check connection
            match fetcher.check_connection().await {
                Ok(true) => {
                    println!("✅ Successfully connected to ledger");
                    
                    // Try to fetch the first transaction
                    match fetcher.get_transaction(1).await {
                        Ok(txn) => {
                            println!("✅ Successfully fetched transaction #1");
                            println!("Transaction Type: {}", txn.txn_type);
                            println!("Transaction Time: {}", txn.txn_time);
                        },
                        Err(e) => {
                            println!("❌ Failed to fetch transaction: {}", e);
                        }
                    }
                },
                Ok(false) => {
                    println!("❌ Connection failed - could not reach ledger");
                },
                Err(e) => {
                    println!("❌ Connection error: {}", e);
                }
            }
        },
        Commands::UpdateTrustStore { ledger, count } => {
            // Get the ledger configuration
            let ledger_config = config.ledgers.get_ledger(&ledger)?;
            // Get genesis source
            let genesis_source = config.ledgers.get_genesis_source(&ledger)?;
            
            // Create a ledger fetcher
            use indy_sherlock::fetcher::LedgerFetcher;
            let start_time = std::time::Instant::now();
            println!("Connecting to ledger...");
            let fetcher = LedgerFetcher::new(&genesis_source).await?;
            
            // Create a parser registry
            use indy_sherlock::parser::TransactionParserRegistry;
            let parser_registry = TransactionParserRegistry::new();
            
            // If count is 0, get the ledger size first
            let adjusted_count = if count <= 0 {
                match fetcher.get_ledger_size().await {
                    Ok(size) => {
                        println!("Ledger size: {}. Scanning ALL transactions.", size);
                        size
                    },
                    Err(e) => {
                        println!("Failed to get ledger size: {}. Using default of 1000.", e);
                        1000
                    }
                }
            } else {
                count
            };
            
            println!("Starting trust store update for ledger '{}' with count {}", ledger_config.name, adjusted_count);
            
            // Fetch transactions using parallel fetching
            // Use a concurrency level that's reasonable for network conditions
            // You might need to adjust this based on testing
            let concurrency = 10;
            let fetch_start = std::time::Instant::now();
            let raw_txns = fetcher.get_transactions_in_range_parallel(1, adjusted_count, concurrency).await?;
            println!("Fetched {} transactions in {:.2?}", raw_txns.len(), fetch_start.elapsed());
            
            // Count transaction types
            let mut type_counts = std::collections::HashMap::new();
            for txn in &raw_txns {
                *type_counts.entry(txn.txn_type.clone()).or_insert(0) += 1;
            }
            
            println!("Transaction type breakdown:");
            for (txn_type, count) in type_counts.iter() {
                println!("  - Type {}: {} transactions", txn_type, count);
            }
            
            let nym_count = type_counts.get("1").cloned().unwrap_or(0);
            println!("Scanning {} NYM records...", nym_count);
            
            if nym_count == 0 {
                println!("No NYM transactions found in the specified range. Try increasing the count.");
                return Ok(());
            }
            
            // Process NYM transactions
            let parse_start = std::time::Instant::now();
            let mut dids = std::collections::HashMap::new();
            let mut processed = 0;
            
            // Filter for NYM transactions
            let nym_txns: Vec<_> = raw_txns.iter().filter(|txn| txn.txn_type == "1").collect();
            
            for raw_txn in nym_txns {
                processed += 1;
                print!("\rProcessing NYM {}/{}     ", processed, nym_count);
                std::io::stdout().flush().unwrap_or(());
                
                // Parse the transaction
                match parser_registry.parse_transaction(raw_txn).await {
                    Ok(parsed_txn) => {
                        // Extract DID information from NYM transactions
                        if let indy_sherlock::parser::TransactionData::Nym(nym_data) = &parsed_txn.specific_data {
                            // Store the target DID information
                            let did = nym_data.dest.clone();
                            if let Some(verkey) = &nym_data.verkey {
                                let role = nym_data.role.clone().unwrap_or_else(|| "null".to_string());
                                let alias = nym_data.alias.clone();
                                let txn_time = parsed_txn.txn_time;
                                
                                // Only add if we have a verification key
                                dids.insert(did.clone(), (verkey.clone(), role, alias, txn_time));
                            }
                        }
                    },
                    Err(_) => {
                        // Skip errors
                    }
                }
            }
            println!("\rFound {} DIDs with verification keys in {:.2?}    ", 
                dids.len(), parse_start.elapsed());
            
            // Load current trust store
            let trust_store_path = config.config_dir.join("trusted_dids.toml");
            println!("Trust store path: {:?}", trust_store_path);
            
            let trust_store_start = std::time::Instant::now();
            let mut trust_store = if trust_store_path.exists() {
                println!("Loading existing trust store...");
                let store = indy_sherlock::config::trust_store::TrustStoreConfig::load(&trust_store_path)?;
                println!("Loaded trust store with {} DIDs", store.trusted_dids.len());
                store
            } else {
                println!("Trust store doesn't exist, creating new one");
                indy_sherlock::config::trust_store::TrustStoreConfig {
                    trusted_dids: Vec::new(),
                }
            };
            
            // Add DIDs to trust store if they don't exist
            let existing_dids: std::collections::HashSet<String> = trust_store.trusted_dids
                .iter()
                .map(|td| td.did.clone())
                .collect();
            
            let mut added_count = 0;
            
            println!("Adding new DIDs to trust store...");
            for (did, (verkey, role, alias, txn_time)) in dids {
                if !existing_dids.contains(&did) {
                    // Create role name based on role code
                    let role_name = match role.as_str() {
                        "0" => "Trustee",
                        "2" => "Steward",
                        "101" => "Endorser",
                        "201" => "Network Monitor",
                        _ => "User",
                    };
                    
                    // Create a new trusted DID entry
                    let mut metadata = std::collections::HashMap::new();
                    metadata.insert("role".to_string(), role_name.to_string());
                    metadata.insert("role_code".to_string(), role);
                    if let Some(alias_val) = alias {
                        metadata.insert("alias".to_string(), alias_val);
                    }
                    
                    // Convert Unix timestamp to DateTime
                    let ledger_datetime = chrono::DateTime::from_timestamp(
                        txn_time as i64, 
                        0
                    ).unwrap_or_default();
                    
                    let trusted_did = indy_sherlock::config::trust_store::TrustedDid {
                        did: did.clone(),
                        verification_key: Some(verkey),
                        trust_level: indy_sherlock::config::trust_store::TrustLevel::Untrusted,
                        metadata,
                        added_timestamp: chrono::Utc::now(),
                        ledger_timestamp: Some(ledger_datetime),
                        last_verified: None,
                    };
                    
                    trust_store.trusted_dids.push(trusted_did);
                    added_count += 1;
                }
            }
            
            if added_count == 0 {
                println!("No new DIDs to add. Trust store already contains all found DIDs.");
            } else {
                println!("Adding {} new DIDs to trust store", added_count);
                
                // Check if parent directory exists
                if let Some(parent) = trust_store_path.parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                
                // Save the trust store
                trust_store.save(&trust_store_path)?;
                println!("✅ Trust store updated at: {:?}", trust_store_path);
                println!("Added {} new DIDs, total DIDs in store: {}", 
                    added_count, trust_store.trusted_dids.len());
                
                // Print trust store summary after updating
                trust_store.print_summary();
            }
            
            println!("Trust store processing completed in {:.2?}", trust_store_start.elapsed());
            println!("Total operation completed in {:.2?}", start_time.elapsed());
     
        },
        Commands::DetectAnomalies { ledger, start, count, mode } => {
            // Get the ledger configuration
            let ledger_config = config.ledgers.get_ledger(&ledger)?;
            
            // Get genesis source
            let genesis_source = config.ledgers.get_genesis_source(&ledger)?;
            
            // Create a ledger fetcher
            use indy_sherlock::fetcher::LedgerFetcher;
            let start_time = std::time::Instant::now();
            let fetcher = LedgerFetcher::new(&genesis_source).await?;
            
            // If count is 0, get the ledger size first
            let adjusted_count = if count <= 0 {
                match fetcher.get_ledger_size().await {
                    Ok(size) => {
                        println!("Ledger size: {}. Analyzing ALL transactions for anomalies.", size);
                        size - start + 1 // +1 because we want to include the start transaction
                    },
                    Err(e) => {
                        println!("Failed to get ledger size: {}. Using default of 1000.", e);
                        1000
                    }
                }
            } else {
                count
            };
            
            println!("Analyzing transactions #{}-{} on ledger: {} for anomalies", 
                start, start + adjusted_count - 1, ledger_config.name);
            
            // Fetch transactions using parallel fetching with a reasonable concurrency level
            let concurrency = 10; // Adjust based on network conditions
            println!("Fetching transactions in parallel...");
            let fetch_start = std::time::Instant::now();
            let raw_txns = fetcher.get_transactions_in_range_parallel(start, adjusted_count, concurrency).await?;
            println!("Fetched {} transactions in {:.2?}", raw_txns.len(), fetch_start.elapsed());
            
            // Create a parser registry
            use indy_sherlock::parser::TransactionParserRegistry;
            let parser_registry = TransactionParserRegistry::new();
            
            // Parse all transactions in parallel using Tokio
            println!("Parsing transactions...");
            let parse_start = std::time::Instant::now();
            
            // Create a shared vector to collect results
            let parsed_txns_mutex = Arc::new(Mutex::new(Vec::with_capacity(raw_txns.len())));
            let parse_errors = Arc::new(Mutex::new(0));
            
            // Create a task for each transaction to parse
            let mut parse_tasks = Vec::with_capacity(raw_txns.len());
            
            for raw_txn in raw_txns {
                let parser_registry = parser_registry.clone();
                let parsed_txns_mutex = Arc::clone(&parsed_txns_mutex);
                let parse_errors = Arc::clone(&parse_errors);
                
                // Spawn a Tokio task for parsing this transaction
                let handle = tokio::task::spawn(async move {
                    match parser_registry.parse_transaction(&raw_txn).await {
                        Ok(parsed) => {
                            // Store successful result
                            let mut guard = parsed_txns_mutex.lock().await;
                            guard.push(parsed);
                        },
                        Err(_) => {
                            // Track errors
                            let mut errors = parse_errors.lock().await;
                            *errors += 1;
                        }
                    }
                });
                
                parse_tasks.push(handle);
            }
            
            // Wait for all parsing tasks to complete
            for handle in parse_tasks {
                let _ = handle.await;
            }
            
            // Get the parsed transactions
            let parsed_txns = Arc::try_unwrap(parsed_txns_mutex)
                .expect("There should be no other references")
                .into_inner();
                
            let error_count = Arc::try_unwrap(parse_errors)
                .expect("There should be no other references")
                .into_inner();
            
            println!("Successfully parsed {} transactions in {:.2?} ({} errors)", 
                parsed_txns.len(), parse_start.elapsed(), error_count);
            
            // Run anomaly detection
            println!("Detecting anomalies...");
            
            use indy_sherlock::detector::{AnomalyDetector, AnomalySeverity};
            use indy_sherlock::detector::role_changes::RoleChangeDetector;
            
            if mode == "quick" {
                // Quick mode uses specialized scanning functions
                println!("Using quick scan mode");
                
                // Detect role elevations
                let role_anomalies = indy_sherlock::detector::quick_scan::detect_role_elevations(&parsed_txns);
                
                // Detect high frequency transactions 
                let freq_anomalies = indy_sherlock::detector::quick_scan::detect_high_frequency(
                    &parsed_txns, 
                    20,   // Flag if more than 20 transactions
                    3600  // In a 1-hour window
                );
                
                // Print findings
                let all_anomalies = [role_anomalies, freq_anomalies].concat();
                
                if all_anomalies.is_empty() {
                    println!("No anomalies detected!");
                } else {
                    println!("\nDetected {} anomalies:", all_anomalies.len());
                    
                    for (i, finding) in all_anomalies.iter().enumerate() {
                        println!("\n{}. {} - Severity: {:?}", 
                            i+1, 
                            finding.description, 
                            finding.severity
                        );
                        
                        if let Some(context) = &finding.context {
                            println!("   Context: {}", context);
                        }
                        
                        println!("   Related transactions: {:?}", finding.related_transactions);
                        println!("   Related DIDs: {:?}", finding.related_dids);
                    }
                }
            } else {
                // Thorough mode uses the AnomalyDetector 
                println!("Using thorough scan mode");
                
                // Create and configure the detector
                let mut detector = AnomalyDetector::new();
                
                // Build baseline from transactions
                println!("Building baseline from transaction data...");
                detector.build_baseline(&parsed_txns);
                
                // Run detection
                let anomalies = detector.detect_anomalies(&parsed_txns);
                
                // Also run specialized role change detection
                println!("Running specialized role change analysis...");
                let role_detector = RoleChangeDetector::new();
                let role_anomalies = role_detector.detect_suspicious_role_changes(&parsed_txns);
                
                // Combine findings
                let all_anomalies = [anomalies, role_anomalies].concat();
                
                if all_anomalies.is_empty() {
                    println!("No anomalies detected!");
                } else {
                    println!("\nDetected {} anomalies:", all_anomalies.len());
                    
                    // Group by severity
                    let mut critical = Vec::new();
                    let mut high = Vec::new();
                    let mut medium = Vec::new();
                    let mut low = Vec::new();
                    
                    for finding in &all_anomalies {
                        match finding.severity {
                            AnomalySeverity::Critical => critical.push(finding),
                            AnomalySeverity::High => high.push(finding),
                            AnomalySeverity::Medium => medium.push(finding),
                            AnomalySeverity::Low => low.push(finding),
                        }
                    }
                    
                    // Print by severity
                    if !critical.is_empty() {
                        println!("\n=== CRITICAL FINDINGS ({}) ===", critical.len());
                        for (i, finding) in critical.iter().enumerate() {
                            println!("\n{}. {} - Type: {:?}", 
                                i+1, 
                                finding.description, 
                                finding.anomaly_type
                            );
                            
                            if let Some(context) = &finding.context {
                                println!("   Context: {}", context);
                            }
                            
                            println!("   Related transactions: {:?}", finding.related_transactions);
                            println!("   Related DIDs: {:?}", finding.related_dids);
                        }
                    }
                    
                    if !high.is_empty() {
                        println!("\n=== HIGH SEVERITY FINDINGS ({}) ===", high.len());
                        for (i, finding) in high.iter().enumerate() {
                            println!("\n{}. {} - Type: {:?}", 
                                i+1, 
                                finding.description, 
                                finding.anomaly_type
                            );
                            
                            if let Some(context) = &finding.context {
                                println!("   Context: {}", context);
                            }
                            
                            println!("   Related transactions: {:?}", finding.related_transactions);
                            println!("   Related DIDs: {:?}", finding.related_dids);
                        }
                    }
                    
                    if !medium.is_empty() {
                        println!("\n=== MEDIUM SEVERITY FINDINGS ({}) ===", medium.len());
                        for (i, finding) in medium.iter().enumerate() {
                            println!("\n{}. {}", i+1, finding.description);
                            println!("   Type: {:?}", finding.anomaly_type);
                            
                            if let Some(context) = &finding.context {
                                println!("   Context: {}", context);
                            }
                        }
                    }
                    
                    if !low.is_empty() {
                        println!("\n=== LOW SEVERITY FINDINGS ({}) ===", low.len());
                        println!("Summary of low severity findings:");
                        for (i, finding) in low.iter().enumerate() {
                            println!("{}. {}", i+1, finding.description);
                        }
                    }
                }
            }
            
            println!("\nTotal operation completed in {:.2?}", start_time.elapsed());
        },
        Commands::RunAudit { 
            ledger, 
            start, 
            count, 
            output, 
            no_state_proofs, 
            no_formats, 
            no_permissions, 
            no_sequences, 
            no_anomalies, 
            force_full
        } => {
            // Get the ledger configuration
            let ledger_config = config.ledgers.get_ledger(&ledger)?;
            println!("Starting audit of ledger: {}", ledger_config.name);

            // Get the actual start value to use (for display purposes)
            let display_start = if force_full {
                1 // Force full always starts from 1
            } else {
                start.unwrap_or_else(|| {
                    // Try to load cache to get the next sequence number
                    if let Ok(cache) = indy_sherlock::cache::AuditCache::load(&config_dir, &ledger) {
                        cache.get_next_seq_no()
                    } else {
                        1 // Default to 1 if no cache exists
                    }
                })
            };
            
            if force_full && count == 1000 {
                println!("Transactions range: ALL (from #1 to end of ledger)");
            } else {
                println!("Transactions range: #{} to #{}", display_start, display_start + count - 1);
            }
   
            
            // Get genesis source
            let genesis_source = config.ledgers.get_genesis_source(&ledger)?;
            
            // Create a ledger fetcher
            let start_time = std::time::Instant::now();
            println!("Connecting to ledger...");
            let fetcher = indy_sherlock::fetcher::LedgerFetcher::new(&genesis_source).await?;
            
            // Set up the validation engine
            use indy_sherlock::validator::{
                ValidationEngine, 
                format_rules::FormatValidationRule,
                permission_rules::PermissionValidationRule,
                sequence_rules::SequenceValidationRule,
                state_proof_rule::StateProofValidationRule
            };
            use indy_sherlock::parser::Role;
            
            println!("Setting up validation engine...");
            let mut validation_engine = ValidationEngine::new();
            
            // Create an Arc around the trust store
            let trust_store = Arc::new(config.trust_store);
            
            if !no_state_proofs {
                // Add state proof validation rule
                println!("Adding state proof verification...");
                validation_engine.add_rule(StateProofValidationRule::new());
            }

            if !no_formats {
                // Add format validation rule
                println!("Adding format validation rules...");
                validation_engine.add_rule(FormatValidationRule::new());
            }
            
            if !no_permissions {
                // Create a permission validation rule
                // Extract DID roles from the trust store
                println!("Adding permission validation rules...");
                let mut did_roles = HashMap::new();
                
                // Convert trust store entries to role map
                for entry in &trust_store.trusted_dids {
                    if let Some(role_str) = entry.metadata.get("role_code") {
                        let role = match role_str.as_str() {
                            "0" => Role::Trustee,
                            "2" => Role::Steward,
                            "101" => Role::EndorserTrustAnchor,
                            "201" => Role::Network,
                            "" => Role::User,
                            _ => Role::Unknown(role_str.clone()),
                        };
                        did_roles.insert(entry.did.clone(), role);
                    }
                }
                
                println!("Loaded {} DID roles from trust store", did_roles.len());
                validation_engine.add_rule(PermissionValidationRule::with_roles(did_roles, false));
            }
            
            if !no_sequences {
                // Add sequence validation rule, but we'll first preload schemas during the audit process
                println!("Adding sequence validation rules...");
                let seq_rule = SequenceValidationRule::new();
                validation_engine.add_rule(seq_rule);
                
                // Note: During validation, we'll ensure CLAIM_DEF transactions following
                // a SCHEMA immediately will properly recognize the schema
            }
            
            // Set up anomaly detector factory
            let anomaly_detector_factory = if !no_anomalies {
                println!("Setting up anomaly detection...");
                Some(|| {
                    use indy_sherlock::detector::AnomalyDetector;
                    AnomalyDetector::new()
                })
            } else {
                None
            };
            
            // Create the audit engine
            let mut audit_engine = indy_sherlock::audit_engine::AuditEngine::new(
                fetcher,
                trust_store.clone(),  // Already an Arc now
                &ledger
            ).await
            .with_validation_engine(validation_engine);
            
            // Add anomaly detector if enabled
            if let Some(factory) = anomaly_detector_factory {
                audit_engine = audit_engine.with_anomaly_detector_factory(factory);
            }
            
            // Configure audit options
            let mut options = indy_sherlock::audit_engine::AuditOptions {
                start_seq_no: start.unwrap_or(0),  // Pass 0 if not specified, which will trigger cache usage
                count,
                validate_state_proofs: !no_state_proofs,
                validate_formats: !no_formats,
                validate_permissions: !no_permissions,
                validate_sequences: !no_sequences,
                detect_anomalies: !no_anomalies,
                ..Default::default()
            };
            
            // If force_full is specified, override count to scan all transactions
            if force_full && options.count == 1000 {  // Only override default count
                options.count = 0;  // This will make it scan the entire ledger
                println!("Force full audit enabled: Will scan ALL transactions from the beginning");
            }
            
            // Run the audit with caching
            println!("Starting audit...");
            let report = audit_engine.audit_with_cache(options, &config_dir, force_full).await?;
            
            // Check if the report has no transactions (empty audit)
            if report.statistics.total_transactions == 0 {
                println!("No new transactions to audit, preserving previous report.");
                
                // Only attempt to preserve the existing report if it exists
                let output_path = PathBuf::from(&output);
                if output_path.exists() {
                    // Create a backup with timestamp
                    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
                    let backup_filename = format!("{}.backup_{}", output, timestamp);
                    let backup_path = PathBuf::from(&backup_filename);
                    
                    // Copy the existing file to the backup
                    if std::fs::copy(&output_path, &backup_path).is_ok() {
                        println!("Previous report backed up to: {}", backup_path.display());
                    } else {
                        println!("Note: Could not create backup of previous report");
                    }
                    // Don't overwrite the existing report
                }
            } else {
                // Print summary to console
                report.print_summary();
                
                // Also print trust store summary when running a comprehensive audit
                println!("Trust store information for this ledger:");
                // Use the Arc clone that we already have
                let trust_config = Arc::clone(&trust_store);
                trust_config.print_summary();
                
                // Save report to file
                let output_path = PathBuf::from(output);
                report.save_to_file(&output_path)?;
                println!("Audit report saved to: {}", output_path.display());
            }
            
            // Print total execution time
            let total_duration = start_time.elapsed();
            println!("Total execution time: {:.2?}", total_duration);
        },
    }

    Ok(())
}