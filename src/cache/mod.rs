use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use anyhow::{Context, Result};
use std::fs;
use std::env;
use chrono::{DateTime, Utc};
use dirs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCache {
    pub ledger_id: String,
    pub last_audited_seq_no: i32,
    pub last_audit_time: DateTime<Utc>,
}

impl AuditCache {
    pub fn new(ledger_id: &str) -> Self {
        Self {
            ledger_id: ledger_id.to_string(),
            last_audited_seq_no: 0,
            last_audit_time: Utc::now(),
        }
    }
    
    pub fn load(config_dir: &Path, ledger_id: &str) -> Result<Self> {
        let cache_path = Self::cache_path(config_dir, ledger_id);
        
        if !cache_path.exists() {
            return Ok(Self::new(ledger_id));
        }
        
        let cache_str = fs::read_to_string(&cache_path)
            .with_context(|| format!("Failed to read cache file from {:?}", cache_path))?;
        
        let cache: AuditCache = serde_json::from_str(&cache_str)
            .with_context(|| "Failed to parse cache file")?;
        
        Ok(cache)
    }
    
    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let cache_path = Self::cache_path(config_dir, &self.ledger_id);
        
        let cache_str = serde_json::to_string_pretty(self)
            .with_context(|| "Failed to serialize cache")?;
        
        fs::write(&cache_path, cache_str)
            .with_context(|| format!("Failed to write cache to {:?}", cache_path))?;
        
        Ok(())
    }
    
    pub fn cache_path(config_dir: &Path, ledger_id: &str) -> PathBuf {
        // Try to get the user's home directory using dirs crate
        if let Some(home_dir) = dirs::home_dir() {
            // Use home directory for cache
            let cache_dir = home_dir.join(".indy-sherlock").join("cache");
            // Create cache directory if it doesn't exist
            let _ = fs::create_dir_all(&cache_dir);
            return cache_dir.join(format!("{}_audit.json", ledger_id));
        } else {
            // Fallback for environments without a home directory (like pipelines)
            // Use a temporary directory or specified config directory
            let cache_dir = if let Ok(tmp_dir) = env::var("TMPDIR").or_else(|_| env::var("TEMP")).or_else(|_| env::var("TMP")) {
                PathBuf::from(tmp_dir).join("indy-sherlock-cache")
            } else {
                config_dir.join("cache")
            };
            // Create cache directory if it doesn't exist
            let _ = fs::create_dir_all(&cache_dir);
            cache_dir.join(format!("{}_audit.json", ledger_id))
        }
    }
    
    pub fn update(&mut self, end_seq_no: i32) {
        self.last_audited_seq_no = end_seq_no;
        self.last_audit_time = Utc::now();
    }
    
    pub fn get_next_seq_no(&self) -> i32 {
        self.last_audited_seq_no + 1
    }
}

