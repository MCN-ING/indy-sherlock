pub use anyhow::{Result, Context, anyhow};

// We can define some helper functions for common error scenarios
// This maintains some of the categorization while leveraging anyhow

pub fn connection_error(msg: impl AsRef<str>) -> anyhow::Error {
    anyhow!("Connection error: {}", msg.as_ref())
}

pub fn transaction_error(msg: impl AsRef<str>) -> anyhow::Error {
    anyhow!("Transaction error: {}", msg.as_ref())
}

pub fn config_error(msg: impl AsRef<str>) -> anyhow::Error {
    anyhow!("Configuration error: {}", msg.as_ref())
}

pub fn validation_error(msg: impl AsRef<str>) -> anyhow::Error {
    anyhow!("Validation error: {}", msg.as_ref())
}

pub fn report_error(msg: impl AsRef<str>) -> anyhow::Error {
    anyhow!("Report generation error: {}", msg.as_ref())
}

// This is optional, but could be useful for categorizing errors when displaying them
pub fn get_error_category(err: &anyhow::Error) -> &'static str {
    let err_string = err.to_string().to_lowercase();
    
    if err_string.contains("connection") {
        "CONNECTION"
    } else if err_string.contains("transaction") {
        "TRANSACTION"
    } else if err_string.contains("config") {
        "CONFIGURATION"
    } else if err_string.contains("validation") {
        "VALIDATION"
    } else if err_string.contains("report") {
        "REPORTING"
    } else {
        "GENERAL"
    }
}