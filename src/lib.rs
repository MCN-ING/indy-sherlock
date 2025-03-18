pub mod config;
pub mod error;
pub mod fetcher;
pub mod parser;
pub mod validator;
pub mod detector;
pub mod reporter;
pub mod helpers;
pub mod audit_engine;
pub mod cache;

// Re-export main types for library users
pub use config::Config;
pub use helpers::genesis::GenesisSource;
pub use error::Result;
use std::sync::Arc;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Analyze a single transaction and print detailed information
pub async fn analyze_transaction(
    fetcher: &fetcher::LedgerFetcher, 
    seq_no: i32, 
    trust_store: Arc<config::trust_store::TrustStoreConfig>
) -> Result<()> {
    println!("Analyzing transaction #{}", seq_no);
    
    // Fetch the transaction
    let raw_txn = fetcher.get_transaction(seq_no).await?;
    println!("Raw transaction data for #{} (type {}): ", seq_no, raw_txn.txn_type);
    println!("{}", serde_json::to_string_pretty(&raw_txn.data).unwrap_or_else(|_| "Error serializing".to_string()));
    // Create a parser registry
    let parser_registry = parser::TransactionParserRegistry::new();
    
    // Parse the transaction
    let parsed_txn = parser_registry.parse_transaction(&raw_txn).await?;
    
    // Display transaction information
    println!("Transaction Type: {:?}", parsed_txn.txn_type);
    println!("Sequence Number: {}", parsed_txn.seq_no);
    println!("Timestamp: {}", parsed_txn.txn_time);
    println!("Author: {}", parsed_txn.identifier);
    
    // Get a human-readable description
    let description = parser::helpers::get_transaction_description(&parsed_txn);
    println!("Description: {}", description);
    
    // Handle specific transaction types
    match &parsed_txn.specific_data {
        parser::TransactionData::Nym(nym_data) => {
            println!("\nNYM Transaction Details:");
            println!("  Target DID: {}", nym_data.dest);
            
            if let Some(role) = &nym_data.role {
                let role_name = match role.as_str() {
                    "0" => "TRUSTEE",
                    "2" => "STEWARD",
                    "101" => "ENDORSER",
                    "201" => "NETWORK_MONITOR",
                    _ => "UNKNOWN",
                };
                println!("  Role: {} ({})", role_name, role);
            } else {
                println!("  Role: None (User)");
            }
            
            if let Some(verkey) = &nym_data.verkey {
                println!("  Verification Key: {}", verkey);
            }
            
            if let Some(alias) = &nym_data.alias {
                println!("  Alias: {}", alias);
            }
            
            // Check if this is a role change
            if parser::helpers::is_role_modification(&parsed_txn) {
                println!("  [IMPORTANT] This transaction modifies a DID's role!");
            }
        },
        parser::TransactionData::Schema(schema_data) => {
            println!("\nSCHEMA Transaction Details:");
            println!("  Name: {}", schema_data.data.name);
            println!("  Version: {}", schema_data.data.version);
            println!("  Attributes: {}", schema_data.data.attr_names.join(", "));
        },
        parser::TransactionData::ClaimDef(claim_def_data) => {
            println!("\nCLAIM_DEF Transaction Details:");
            println!("  Schema Reference: {}", claim_def_data.schema_ref);
            println!("  Signature Type: {}", claim_def_data.signature_type);
            println!("  Tag: {}", claim_def_data.tag);
        },
        parser::TransactionData::Node(node_data) => {
            println!("\nNODE Transaction Details:");
            println!("  Node Alias: {}", node_data.alias);
            
            if let Some(node_ip) = &node_data.node_ip {
                println!("  Node IP: {}", node_ip);
            }
            
            if let Some(node_port) = &node_data.node_port {
                println!("  Node Port: {}", node_port);
            }
            
            if let Some(services) = &node_data.services {
                println!("  Services: {}", services.join(", "));
            }
        },
        parser::TransactionData::Attrib(attrib_data) => {
            println!("\nATTRIB Transaction Details:");
            println!("  Target DID: {}", attrib_data.dest);
            
            if let Some(raw) = &attrib_data.raw {
                println!("  Raw Data: {}", raw);
            }
            
            if let Some(hash) = &attrib_data.hash {
                println!("  Hash: {}", hash);
            }
            
            if let Some(enc) = &attrib_data.enc {
                println!("  Encrypted: {}", enc);
            }
        },
        parser::TransactionData::RevocRegDef(revoc_reg_def_data) => {
            println!("\nREVOCATION REGISTRY DEFINITION Details:");
            println!("  ID: {}", revoc_reg_def_data.id);
            println!("  Type: {}", revoc_reg_def_data.revoc_def_type);
            println!("  Tag: {}", revoc_reg_def_data.tag);
            println!("  Credential Definition ID: {}", revoc_reg_def_data.cred_def_id);
            
            if let Some(issuance_type) = revoc_reg_def_data.value["issuanceType"].as_str() {
                println!("  Issuance Type: {}", issuance_type);
            }
            
            if let Some(max_cred_num) = revoc_reg_def_data.value["maxCredNum"].as_u64() {
                println!("  Maximum Credential Number: {}", max_cred_num);
            }
            
            if let Some(tails_hash) = revoc_reg_def_data.value["tailsHash"].as_str() {
                println!("  Tails Hash: {}", tails_hash);
            }
            
            if let Some(tails_location) = revoc_reg_def_data.value["tailsLocation"].as_str() {
                println!("  Tails Location: {}", tails_location);
            }
        },
        parser::TransactionData::RevocRegEntry(revoc_reg_entry_data) => {
            println!("\nREVOCATION REGISTRY ENTRY Details:");
            println!("  Revocation Registry ID: {}", revoc_reg_entry_data.revoc_reg_def_id);
            println!("  Type: {}", revoc_reg_entry_data.revoc_def_type);
            
            // If the value contains an "issued" or "revoked" field listing specific credential indices
            if let Some(issued) = revoc_reg_entry_data.value["issued"].as_array() {
                if !issued.is_empty() {
                    println!("  Newly Issued Credentials: {}", 
                            issued.iter()
                                .filter_map(|v| v.as_u64())
                                .map(|i| i.to_string())
                                .collect::<Vec<_>>()
                                .join(", "));
                }
            }
            
            if let Some(revoked) = revoc_reg_entry_data.value["revoked"].as_array() {
                if !revoked.is_empty() {
                    println!("  Newly Revoked Credentials: {}", 
                            revoked.iter()
                                .filter_map(|v| v.as_u64())
                                .map(|i| i.to_string())
                                .collect::<Vec<_>>()
                                .join(", "));
                }
            }
            
            // The "accum" field is a cryptographic accumulator value
            if revoc_reg_entry_data.value["accum"].is_string() || revoc_reg_entry_data.value["accum"].is_object() {
                println!("  Accumulator Updated: Yes");
            }
        },
        parser::TransactionData::Generic(_) => {
            println!("\nGeneric Transaction (no specific parser available)");
            println!("  Raw Data: {}", serde_json::to_string_pretty(&parsed_txn.raw_data)?);
        },
    }
    
     // Verify the transaction state proof
     println!("\nState proof verification:");
    
     let verifier = validator::state_proof::StateProofVerifier::new();
     match verifier.verify_transaction(&parsed_txn).await {
         Ok(result) => {
             println!("  Verified: {}", if result.verified { "✅ Yes" } else { "❌ No" });
             println!("  Details: {}", result.details);
             
             if !result.warnings.is_empty() {
                 println!("  Warnings:");
                 for warning in result.warnings {
                     println!("    - {}", warning);
                 }
             }
             
             // Add the detailed explanation
             println!("{}", verifier.explain_state_proof(&parsed_txn));
         },
         Err(e) => {
             println!("  Error verifying state proof: {}", e);
         }
     }
    
    // Fetch the raw transaction first to get related DIDs
    let raw_txn = fetcher.get_transaction(seq_no).await?;
    
    // Create a parser registry
    use parser::TransactionParserRegistry;
    let parser_registry = TransactionParserRegistry::new();
    
    // Parse the transaction to get DIDs
    match parser_registry.parse_transaction(&raw_txn).await {
        Ok(parsed_txn) => {
            // Get related DIDs
            let mut related_dids = vec![parsed_txn.identifier.clone()];
            
            // For NYM transactions, also include target DID
            if let parser::TransactionData::Nym(nym_data) = &parsed_txn.specific_data {
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
                                config::trust_store::TrustLevel::FullyTrusted => "✓ Fully Trusted",
                                config::trust_store::TrustLevel::ProvisionalTrust => "? Provisional Trust",
                                config::trust_store::TrustLevel::Untrusted => "✗ Untrusted",
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
    
    Ok(())
}