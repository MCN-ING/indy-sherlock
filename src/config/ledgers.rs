use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use dialoguer::{Select, theme::ColorfulTheme};
use anyhow::{Context, Result};

use crate::helpers::genesis::GenesisSource;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LedgerConfig {
    pub name: String,
    pub genesis_source: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LedgersConfig {
    pub ledgers: HashMap<String, LedgerConfig>,
}

impl LedgersConfig {
    pub fn load(config_path: &Path) -> Result<Self> {
        let config_str = fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read ledgers config from {:?}", config_path))?;
        
        let config: LedgersConfig = toml::from_str(&config_str)
            .with_context(|| "Failed to parse ledgers config")?;
        
        Ok(config)
    }
    
    pub fn get_ledger(&self, ledger_id: &str) -> Result<&LedgerConfig> {
        self.ledgers.get(ledger_id)
            .ok_or_else(|| anyhow::anyhow!("Ledger '{}' not found in configuration", ledger_id))
    }
    
    pub fn get_genesis_source(&self, ledger_id: &str) -> Result<GenesisSource> {
        let ledger = self.get_ledger(ledger_id)?;
        GenesisSource::from_str(&ledger.genesis_source)
            .with_context(|| format!("Invalid genesis source for ledger '{}'", ledger_id))
    }
    
    pub fn select_ledger_interactive(&self) -> Result<String> {
        if self.ledgers.is_empty() {
            return Err(anyhow::anyhow!("No ledgers configured"));
        }
        
        // Create sorted list of ledger IDs and configs for display
        let mut ledger_entries: Vec<(String, &LedgerConfig)> = self.ledgers
            .iter()
            .map(|(id, config)| (id.clone(), config))
            .collect();
        
        // Sort by name for consistent display
        ledger_entries.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        
        // Create display strings for each ledger
        let ledger_display: Vec<String> = ledger_entries
            .iter()
            .map(|(id, config)| {
                let desc = config.description.as_deref().unwrap_or("No description");
                format!("{} ({}) - {}", config.name, id, desc)
            })
            .collect();
        
        // Display interactive selection menu
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a ledger to investigate")
            .default(0)
            .items(&ledger_display)
            .interact()
            .with_context(|| "Failed to display interactive menu")?;
        
        // Return the selected ledger ID
        Ok(ledger_entries[selection].0.clone())
    }
}