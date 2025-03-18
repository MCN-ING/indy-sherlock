use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc, Duration};
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustLevel {
    FullyTrusted,     // Always trusted
    ProvisionalTrust, // Temporarily trusted, pending review
    Untrusted,        // Not trusted
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDid {
    pub did: String,
    pub verification_key: Option<String>,
    pub trust_level: TrustLevel,
    pub metadata: HashMap<String, String>, // Province, role, etc.
    pub added_timestamp: DateTime<Utc>,       // Timestamp when added to trust store
    pub ledger_timestamp: Option<DateTime<Utc>>, // Timestamp from ledger transaction
    pub last_verified: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustStoreConfig {
    pub trusted_dids: Vec<TrustedDid>,
}

/// Statistics about the trust store contents
#[derive(Debug)]
pub struct TrustStoreStats {
    pub total_dids: usize,
    pub fully_trusted: usize,
    pub provisional_trust: usize,
    pub untrusted: usize,
    pub with_verification_key: usize,
    pub dids_by_role: HashMap<String, usize>,
    pub recently_added_dids: usize,
    pub recently_verified_dids: usize,
}

impl TrustStoreConfig {
    pub fn load(config_path: &Path) -> Result<Self> {
        if config_path.exists() {
            let config_str = fs::read_to_string(config_path)
                .with_context(|| format!("Failed to read trust store config from {:?}", config_path))?;
            
            let config: TrustStoreConfig = toml::from_str(&config_str)
                .with_context(|| "Failed to parse trust store config")?;
            
            Ok(config)
        } else {
            // Create default empty config
            let default_config = TrustStoreConfig {
                trusted_dids: Vec::new(),
            };
            
            // Write default config to file
            let config_str = toml::to_string(&default_config)
                .with_context(|| "Failed to serialize default trust store config")?;
            
            let parent_dir = config_path.parent().ok_or_else(|| 
                anyhow::anyhow!("Invalid trust store config path: {:?}", config_path)
            )?;
            
            std::fs::create_dir_all(parent_dir)
                .with_context(|| format!("Failed to create config directory: {:?}", parent_dir))?;
            
            std::fs::write(config_path, config_str)
                .with_context(|| format!("Failed to write default trust store config to {:?}", config_path))?;
            
            Ok(default_config)
        }
    }
    
    pub fn save(&self, config_path: &Path) -> Result<()> {
        let config_str = toml::to_string(self)
            .with_context(|| "Failed to serialize trust store config")?;
        
        std::fs::write(config_path, config_str)
            .with_context(|| format!("Failed to write trust store config to {:?}", config_path))
    }
    
    /// Calculate statistics about the trust store
    pub fn calculate_stats(&self) -> TrustStoreStats {
        let mut stats = TrustStoreStats {
            total_dids: self.trusted_dids.len(),
            fully_trusted: 0,
            provisional_trust: 0,
            untrusted: 0,
            with_verification_key: 0,
            dids_by_role: HashMap::new(),
            recently_added_dids: 0,
            recently_verified_dids: 0,
        };
        
        let now = Utc::now();
        let thirty_days_ago = now - Duration::days(30);
        
        for did in &self.trusted_dids {
            // Count by trust level
            match did.trust_level {
                TrustLevel::FullyTrusted => stats.fully_trusted += 1,
                TrustLevel::ProvisionalTrust => stats.provisional_trust += 1,
                TrustLevel::Untrusted => stats.untrusted += 1,
            }
            
            // Count DIDs with verification keys
            if did.verification_key.is_some() {
                stats.with_verification_key += 1;
            }
            
            // Count by role
            if let Some(role) = did.metadata.get("role") {
                *stats.dids_by_role.entry(role.clone()).or_insert(0) += 1;
            }
            
            // Count recently added DIDs (based on ledger timestamp if available)
            if let Some(ledger_ts) = did.ledger_timestamp {
                if ledger_ts > thirty_days_ago {
                    stats.recently_added_dids += 1;
                }
            } else if did.added_timestamp > thirty_days_ago {
                // Fallback to trust store timestamp if ledger timestamp not available
                stats.recently_added_dids += 1;
            }
            
            // Count recently verified DIDs
            if let Some(last_verified) = did.last_verified {
                if last_verified > thirty_days_ago {
                    stats.recently_verified_dids += 1;
                }
            }
        }
        
        stats
    }
    
    /// Print a summary of the trust store to the console
    pub fn print_summary(&self) {
        let stats = self.calculate_stats();
        
        println!("\n================================");
        println!("       TRUST STORE SUMMARY      ");
        println!("================================");
        
        // Trust level breakdown
        println!("DID Trust Levels:");
        println!("  - Fully Trusted: {}", stats.fully_trusted);
        println!("  - Provisional Trust: {}", stats.provisional_trust);
        println!("  - Untrusted: {}", stats.untrusted);
        println!("  - Total DIDs: {}", stats.total_dids);
        
        // Verification key stats
        if stats.total_dids > 0 {
            let percentage = (stats.with_verification_key as f64 / stats.total_dids as f64) * 100.0;
            println!("\nVerification Keys:");
            println!("  - DIDs with verification keys: {} ({:.1}%)", 
                stats.with_verification_key, percentage);
        }
        
        // Role breakdown
        if !stats.dids_by_role.is_empty() {
            println!("\nDID Roles:");
            
            // Sort roles by count (descending)
            let mut roles: Vec<(&String, &usize)> = stats.dids_by_role.iter().collect();
            roles.sort_by(|a, b| b.1.cmp(a.1));
            
            for (role, count) in roles {
                println!("  - {}: {}", role, count);
            }
        }
        
        // Recent activity
        println!("\nRecent Activity:");
        println!("  - DIDs added to ledger in last 30 days: {}", stats.recently_added_dids);
        println!("  - DIDs verified in last 30 days: {}", stats.recently_verified_dids);
        
        // Get top DIDs by role (focus on important roles like Trustee, Steward)
        let important_roles = ["Trustee", "Steward", "Endorser", "Network Monitor"];
        let mut has_important_dids = false;
        
        println!("\nImportant DIDs by Role:");
        for role in important_roles.iter() {
            // Filter DIDs by this role
            let role_dids: Vec<&TrustedDid> = self.trusted_dids.iter()
                .filter(|d| d.metadata.get("role").map_or(false, |r| r == *role))
                .collect();
            
            if !role_dids.is_empty() {
                has_important_dids = true;
                println!("  {}s:", role);
                
                // Sort by trust level (fully trusted first)
                let mut sorted_dids = role_dids.clone();
                sorted_dids.sort_by(|a, b| {
                    if a.trust_level == TrustLevel::FullyTrusted && b.trust_level != TrustLevel::FullyTrusted {
                        std::cmp::Ordering::Less
                    } else if a.trust_level != TrustLevel::FullyTrusted && b.trust_level == TrustLevel::FullyTrusted {
                        std::cmp::Ordering::Greater
                    } else {
                        a.added_timestamp.cmp(&b.added_timestamp)
                    }
                });
                
                // Display top 3 DIDs for this role
                for (i, did) in sorted_dids.iter().take(3).enumerate() {
                    let trust_indicator = match did.trust_level {
                        TrustLevel::FullyTrusted => "✓",
                        TrustLevel::ProvisionalTrust => "?",
                        TrustLevel::Untrusted => "✗",
                    };
                    
                    let alias = did.metadata.get("alias").map_or("", |a| a.as_str());
                    let alias_str = if !alias.is_empty() {
                        format!(" ({})", alias)
                    } else {
                        String::new()
                    };
                    
                    // Use substring only if the DID is long enough, otherwise use the full DID
                    let did_display = if did.did.len() > 22 {
                        &did.did[0..22]
                    } else {
                        &did.did
                    };
                    
                    println!("    {}. [{}] {}{}", i+1, trust_indicator, did_display, alias_str);
                }
                
                // If there are more than 3, show count of remaining
                if role_dids.len() > 3 {
                    println!("    ... and {} more", role_dids.len() - 3);
                }
            }
        }
        
        if !has_important_dids {
            println!("  No Trustees, Stewards, or Endorsers found in trust store");
        }
        
        println!("================================\n");
    }
}

// Define a trait for trust store summary functionality
pub trait TrustStoreSummary {
    fn print_summary(&self);
}

// Implement the trait for TrustStoreConfig
impl TrustStoreSummary for TrustStoreConfig {
    fn print_summary(&self) {
        // Use the existing implementation
        TrustStoreConfig::print_summary(self);
    }
}

// Implement the trait for Arc<TrustStoreConfig>
impl TrustStoreSummary for std::sync::Arc<TrustStoreConfig> {
    fn print_summary(&self) {
        // Delegate to the inner TrustStoreConfig's print_summary
        (**self).print_summary();
    }
}
