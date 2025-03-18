pub mod ledgers;
pub mod trust_store;

use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use self::ledgers::LedgersConfig;
use self::trust_store::TrustStoreConfig;

pub struct Config {
    pub ledgers: LedgersConfig,
    pub trust_store: TrustStoreConfig,
    pub config_dir: PathBuf,
}

impl Config {
    pub fn load(config_dir: &Path) -> Result<Self> {
        // Ensure config directory exists
        if !config_dir.exists() {
            return Err(anyhow::anyhow!(
                "Configuration directory does not exist: {:?}", config_dir
            ));
        }
        
        // Load ledgers configuration
        let ledgers_path = config_dir.join("ledgers.toml");
        let ledgers = if ledgers_path.exists() {
            LedgersConfig::load(&ledgers_path)?
        } else {
            // Create a default config
            let default_config = LedgersConfig {
                ledgers: Default::default(),
            };
            // Write default config to file
            let config_str = toml::to_string(&default_config)
                .with_context(|| "Failed to serialize default ledgers config")?;
            std::fs::write(&ledgers_path, config_str)
                .with_context(|| format!("Failed to write default ledgers config to {:?}", ledgers_path))?;
            default_config
        };
        
        // Load trust store configuration
        let trust_store_path = config_dir.join("trusted_dids.toml");
        let trust_store = TrustStoreConfig::load(&trust_store_path)?;
        
        Ok(Self {
            ledgers,
            trust_store,
            config_dir: config_dir.to_path_buf(),
        })
    }
}