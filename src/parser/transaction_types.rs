// File: src/parser/transaction_types.rs
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// All possible Indy transaction types with their associated codes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionType {
    // Node transaction
    NODE,                  // "0"
    
    // Domain transactions
    NYM,                   // "1"
    ATTRIB,                // "100"
    SCHEMA,                // "101"
    CLAIM_DEF,             // "102"
    REVOC_REG_DEF,         // "113"
    REVOC_REG_ENTRY,       // "114"
    
    // Pool transactions
    POOL_UPGRADE,          // "109"
    POOL_CONFIG,           // "110"
    
    // Config transactions
    AUTH_RULE,             // "120"
    AUTH_RULES,            // "122"
    POOL_RESTART,          // "118"
    VALIDATOR_INFO,        // "119"
    
    // Config ledger transaction types
    SET_FEES,              // "20000"
    TXNS_AUTHR_AGRMT,      // "4"
    TXNS_AUTHR_AGRMT_AML,  // "5"
    GET_TXNS_AUTHR_AGRMT,  // "6"
    DISABLE_AUTHR_AGRMT,   // "8"
    
    // Unknown transaction type
    UNKNOWN(String),
}

impl From<&str> for TransactionType {
    fn from(s: &str) -> Self {
        match s {
            // Node
            "0" => TransactionType::NODE,
            
            // Domain
            "1" => TransactionType::NYM,
            "100" => TransactionType::ATTRIB,
            "101" => TransactionType::SCHEMA,
            "102" => TransactionType::CLAIM_DEF,
            "113" => TransactionType::REVOC_REG_DEF,
            "114" => TransactionType::REVOC_REG_ENTRY,
            
            // Pool
            "109" => TransactionType::POOL_UPGRADE,
            "110" => TransactionType::POOL_CONFIG,
            
            // Config
            "120" => TransactionType::AUTH_RULE,
            "122" => TransactionType::AUTH_RULES,
            "118" => TransactionType::POOL_RESTART,
            "119" => TransactionType::VALIDATOR_INFO,
            
            // Config ledger
            "20000" => TransactionType::SET_FEES,
            "4" => TransactionType::TXNS_AUTHR_AGRMT,
            "5" => TransactionType::TXNS_AUTHR_AGRMT_AML,
            "6" => TransactionType::GET_TXNS_AUTHR_AGRMT,
            "8" => TransactionType::DISABLE_AUTHR_AGRMT,
            
            // Unknown
            other => TransactionType::UNKNOWN(other.to_string()),
        }
    }
}

/// NYM transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NymData {
    pub dest: String,
    pub role: Option<String>,
    pub verkey: Option<String>,
    pub alias: Option<String>,
}

/// ATTRIB transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttribData {
    pub dest: String,
    pub raw: Option<String>,
    pub hash: Option<String>,
    pub enc: Option<String>,
}

/// SCHEMA transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaData {
    pub data: SchemaContent,
    pub dest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaContent {
    pub name: String,
    pub version: String,
    pub attr_names: Vec<String>,
}

/// CLAIM_DEF transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDefData {
    pub signature_type: String,
    pub schema_ref: String,
    pub tag: String,
    pub data: Value,
}

/// NODE transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeData {
    pub node_ip: Option<String>,
    pub node_port: Option<u32>,
    pub client_ip: Option<String>,
    pub client_port: Option<u32>,
    pub alias: String,
    pub services: Option<Vec<String>>,
    pub blskey: Option<String>,
    pub blskey_pop: Option<String>,
}

/// REVOC_REG_DEF transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocRegDefData {
    pub id: String,
    pub revoc_def_type: String,
    pub tag: String,
    pub cred_def_id: String,
    pub value: Value,
}

/// REVOC_REG_ENTRY transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocRegEntryData {
    pub revoc_reg_def_id: String,
    pub revoc_def_type: String,
    pub value: Value,
}

/// Transaction specific data based on transaction type
#[derive(Debug, Clone)]
pub enum TransactionData {
    Nym(NymData),
    Attrib(AttribData),
    Schema(SchemaData),
    ClaimDef(ClaimDefData),
    Node(NodeData),
    RevocRegDef(RevocRegDefData),
    RevocRegEntry(RevocRegEntryData),
    Generic(Value),  // For other transaction types or when specific parsing isn't implemented
}

/// Role definition for NYM transactions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Role {
    Trustee,          // "0"
    Steward,          // "2"
    EndorserTrustAnchor, // "101"
    Network,          // "201"
    User,             // Null role
    Unknown(String),  // Other roles
}

impl From<Option<&str>> for Role {
    fn from(role_str: Option<&str>) -> Self {
        match role_str {
            Some("0") => Role::Trustee,
            Some("2") => Role::Steward,
            Some("101") => Role::EndorserTrustAnchor,
            Some("201") => Role::Network,
            None => Role::User,
            Some(other) => Role::Unknown(other.to_string()),
        }
    }
}

/// Complete transaction metadata
#[derive(Debug, Clone)]
pub struct TransactionMetadata {
    pub seq_no: i32,
    pub txn_time: u64,
    pub req_id: Option<u64>,
    pub protocol_version: Option<u32>,
}

// File: src/parser/parsers.rs
use super::transaction_types::*;
use crate::error::Result;
use crate::fetcher::RawTransaction;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// Trait for parsing raw transactions
#[async_trait]
pub trait TransactionParser: Send + Sync {
    /// Check if this parser can handle the given transaction
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool;
    
    /// Parse the transaction into a structured format
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction>;
}

/// Parsed transaction with metadata and specific data
#[derive(Debug)]
pub struct ParsedTransaction {
    pub seq_no: i32,
    pub txn_time: u64, 
    pub txn_type: TransactionType,
    pub identifier: String,
    pub signature: Option<String>,
    pub metadata: TransactionMetadata,
    pub specific_data: TransactionData,
    pub raw_data: Value,
}

/// Parser for NYM transactions
pub struct NYMTransactionParser;

#[async_trait]
impl TransactionParser for NYMTransactionParser {
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool {
        raw_txn.txn_type == "1" || raw_txn.data["txn"]["type"].as_str() == Some("1")
    }
    
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        let txn = &raw_txn.data["txn"];
        let txn_metadata = &raw_txn.data["txnMetadata"];
        
        let identifier = txn["metadata"]["from"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'from' field in NYM transaction"))?
            .to_string();
        
        let signature = txn["metadata"]["signature"]
            .as_str()
            .map(|s| s.to_string());
        
        let data = &txn["data"];
        
        // Parse NYM specific data
        let nym_data = NymData {
            dest: data["dest"].as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'dest' field in NYM transaction"))?
                .to_string(),
            role: data["role"].as_str().map(|s| s.to_string()),
            verkey: data["verkey"].as_str().map(|s| s.to_string()),
            alias: data["alias"].as_str().map(|s| s.to_string()),
        };
        
        // Create transaction metadata
        let metadata = TransactionMetadata {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            req_id: txn_metadata["reqId"].as_u64(),
            protocol_version: txn_metadata["protocolVersion"].as_u64().map(|v| v as u32),
        };
        
        Ok(ParsedTransaction {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            txn_type: TransactionType::NYM,
            identifier,
            signature,
            metadata,
            specific_data: TransactionData::Nym(nym_data),
            raw_data: raw_txn.data.clone(),
        })
    }
}

/// Parser for ATTRIB transactions
pub struct ATTRIBTransactionParser;

#[async_trait]
impl TransactionParser for ATTRIBTransactionParser {
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool {
        raw_txn.txn_type == "100" || raw_txn.data["txn"]["type"].as_str() == Some("100")
    }
    
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        let txn = &raw_txn.data["txn"];
        let txn_metadata = &raw_txn.data["txnMetadata"];
        
        let identifier = txn["metadata"]["from"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'from' field in ATTRIB transaction"))?
            .to_string();
        
        let signature = txn["metadata"]["signature"]
            .as_str()
            .map(|s| s.to_string());
        
        let data = &txn["data"];
        
        // Parse ATTRIB specific data
        let attrib_data = AttribData {
            dest: data["dest"].as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'dest' field in ATTRIB transaction"))?
                .to_string(),
            raw: data["raw"].as_str().map(|s| s.to_string()),
            hash: data["hash"].as_str().map(|s| s.to_string()),
            enc: data["enc"].as_str().map(|s| s.to_string()),
        };
        
        // Create transaction metadata
        let metadata = TransactionMetadata {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            req_id: txn_metadata["reqId"].as_u64(),
            protocol_version: txn_metadata["protocolVersion"].as_u64().map(|v| v as u32),
        };
        
        Ok(ParsedTransaction {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            txn_type: TransactionType::ATTRIB,
            identifier,
            signature,
            metadata,
            specific_data: TransactionData::Attrib(attrib_data),
            raw_data: raw_txn.data.clone(),
        })
    }
}

/// Parser for SCHEMA transactions
pub struct SCHEMATransactionParser;

#[async_trait]
impl TransactionParser for SCHEMATransactionParser {
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool {
        raw_txn.txn_type == "101" || raw_txn.data["txn"]["type"].as_str() == Some("101")
    }
    
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        let txn = &raw_txn.data["txn"];
        let txn_metadata = &raw_txn.data["txnMetadata"];
        
        let identifier = txn["metadata"]["from"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'from' field in SCHEMA transaction"))?
            .to_string();
        
        let signature = txn["metadata"]["signature"]
            .as_str()
            .map(|s| s.to_string());
        
        let data = &txn["data"];
        
        // Parse the schema data JSON string into structured data
        let schema_json = data["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'data' field in SCHEMA transaction"))?;
        
        let schema_value: Value = serde_json::from_str(schema_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse schema JSON: {}", e))?;
        
        // Extract schema fields
        let schema_content = SchemaContent {
            name: schema_value["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'name' in schema data"))?
                .to_string(),
            version: schema_value["version"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'version' in schema data"))?
                .to_string(),
            attr_names: schema_value["attr_names"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Missing 'attr_names' in schema data"))?
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
        };
        
        let schema_data = SchemaData {
            data: schema_content,
            dest: identifier.clone(), // Usually the same as the transaction author
        };
        
        // Create transaction metadata
        let metadata = TransactionMetadata {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            req_id: txn_metadata["reqId"].as_u64(),
            protocol_version: txn_metadata["protocolVersion"].as_u64().map(|v| v as u32),
        };
        
        Ok(ParsedTransaction {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            txn_type: TransactionType::SCHEMA,
            identifier,
            signature,
            metadata,
            specific_data: TransactionData::Schema(schema_data),
            raw_data: raw_txn.data.clone(),
        })
    }
}

/// Parser for CLAIM_DEF transactions
pub struct CLAIMDEFTransactionParser;

#[async_trait]
impl TransactionParser for CLAIMDEFTransactionParser {
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool {
        raw_txn.txn_type == "102" || raw_txn.data["txn"]["type"].as_str() == Some("102")
    }
    
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        let txn = &raw_txn.data["txn"];
        let txn_metadata = &raw_txn.data["txnMetadata"];
        
        let identifier = txn["metadata"]["from"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'from' field in CLAIM_DEF transaction"))?
            .to_string();
        
        let signature = txn["metadata"]["signature"]
            .as_str()
            .map(|s| s.to_string());
        
        let data = &txn["data"];
        
        // Parse CLAIM_DEF specific data
        let claim_def_data = ClaimDefData {
            signature_type: data["signature_type"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'signature_type' field in CLAIM_DEF transaction"))?
                .to_string(),
            schema_ref: data["ref"]
                .as_str()
                .or_else(|| data["ref"].as_number().map(|n| n.to_string().as_str()))
                .ok_or_else(|| anyhow::anyhow!("Missing 'ref' field in CLAIM_DEF transaction"))?
                .to_string(),
            tag: data["tag"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'tag' field in CLAIM_DEF transaction"))?
                .to_string(),
            data: data["data"].clone(),
        };
        
        // Create transaction metadata
        let metadata = TransactionMetadata {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            req_id: txn_metadata["reqId"].as_u64(),
            protocol_version: txn_metadata["protocolVersion"].as_u64().map(|v| v as u32),
        };
        
        Ok(ParsedTransaction {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            txn_type: TransactionType::CLAIM_DEF,
            identifier,
            signature,
            metadata,
            specific_data: TransactionData::ClaimDef(claim_def_data),
            raw_data: raw_txn.data.clone(),
        })
    }
}

/// Parser for NODE transactions
pub struct NODETransactionParser;

#[async_trait]
impl TransactionParser for NODETransactionParser {
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool {
        raw_txn.txn_type == "0" || raw_txn.data["txn"]["type"].as_str() == Some("0")
    }
    
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        let txn = &raw_txn.data["txn"];
        let txn_metadata = &raw_txn.data["txnMetadata"];
        
        let identifier = txn["metadata"]["from"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'from' field in NODE transaction"))?
            .to_string();
        
        let signature = txn["metadata"]["signature"]
            .as_str()
            .map(|s| s.to_string());
        
        let data = &txn["data"];
        
        // Parse NODE specific data
        let node_data = NodeData {
            alias: data["alias"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'alias' field in NODE transaction"))?
                .to_string(),
            node_ip: data["node_ip"].as_str().map(|s| s.to_string()),
            node_port: data["node_port"].as_u64().map(|v| v as u32),
            client_ip: data["client_ip"].as_str().map(|s| s.to_string()),
            client_port: data["client_port"].as_u64().map(|v| v as u32),
            services: if data["services"].is_array() {
                Some(
                    data["services"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                )
            } else {
                None
            },
            blskey: data["blskey"].as_str().map(|s| s.to_string()),
            blskey_pop: data["blskey_pop"].as_str().map(|s| s.to_string()),
        };
        
        // Create transaction metadata
        let metadata = TransactionMetadata {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            req_id: txn_metadata["reqId"].as_u64(),
            protocol_version: txn_metadata["protocolVersion"].as_u64().map(|v| v as u32),
        };
        
        Ok(ParsedTransaction {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            txn_type: TransactionType::NODE,
            identifier,
            signature,
            metadata,
            specific_data: TransactionData::Node(node_data),
            raw_data: raw_txn.data.clone(),
        })
    }
}

/// Generic transaction parser for any transaction type
pub struct GenericTransactionParser;

#[async_trait]
impl TransactionParser for GenericTransactionParser {
    async fn can_parse(&self, _raw_txn: &RawTransaction) -> bool {
        // This parser can handle any transaction as a fallback
        true
    }
    
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        let txn = &raw_txn.data["txn"];
        let txn_metadata = &raw_txn.data["txnMetadata"];
        
        // Try to extract identifier and signature, but don't fail if they're missing
        let identifier = txn["metadata"]["from"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        
        let signature = txn["metadata"]["signature"]
            .as_str()
            .map(|s| s.to_string());
        
        // Determine transaction type
        let txn_type = TransactionType::from(
            txn["type"].as_str().unwrap_or("unknown")
        );
        
        // Create transaction metadata
        let metadata = TransactionMetadata {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            req_id: txn_metadata["reqId"].as_u64(),
            protocol_version: txn_metadata["protocolVersion"].as_u64().map(|v| v as u32),
        };
        
        Ok(ParsedTransaction {
            seq_no: raw_txn.seq_no,
            txn_time: raw_txn.txn_time,
            txn_type,
            identifier,
            signature,
            metadata,
            specific_data: TransactionData::Generic(txn["data"].clone()),
            raw_data: raw_txn.data.clone(),
        })
    }
}

// File: src/parser/mod.rs
mod transaction_types;
mod parsers;

pub use transaction_types::*;
pub use parsers::*;

use std::sync::Arc;
use crate::error::Result;
use crate::fetcher::RawTransaction;

/// Registry of transaction parsers
pub struct TransactionParserRegistry {
    parsers: Vec<Arc<dyn TransactionParser>>,
}

impl TransactionParserRegistry {
    /// Create a new registry with all available parsers
    pub fn new() -> Self {
        let parsers: Vec<Arc<dyn TransactionParser>> = vec![
            Arc::new(NYMTransactionParser),
            Arc::new(ATTRIBTransactionParser),
            Arc::new(SCHEMATransactionParser),
            Arc::new(CLAIMDEFTransactionParser),
            Arc::new(NODETransactionParser),
            // Add more specific parsers here
            
            // Generic parser as fallback - must be last
            Arc::new(GenericTransactionParser),
        ];
        
        Self { parsers }
    }
    
    /// Parse a raw transaction
    pub async fn parse_transaction(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        for parser in &self.parsers {
            if parser.can_parse(raw_txn).await {
                return parser.parse(raw_txn).await;
            }
        }
        
        // This should never happen since we have a GenericTransactionParser as fallback
        Err(anyhow::anyhow!("No parser found for transaction type: {}", raw_txn.txn_type))
    }
}

/// Helper functions for working with transactions
pub mod helpers {
    use super::*;
    
    /// Extracts a role from a NYM transaction
    pub fn get_role_from_nym(parsed_txn: &ParsedTransaction) -> Option<Role> {
        if let TransactionData::Nym(nym_data) = &parsed_txn.specific_data {
            return Some(Role::from(nym_data.role.as_deref()));
        }
        None
    }
    
    /// Check if a transaction modifies a DID's role
    pub fn is_role_modification(parsed_txn: &ParsedTransaction) -> bool {
        if let TransactionData::Nym(nym_data) = &parsed_txn.specific_data {
            return nym_data.role.is_some();
        }
        false
    }
    
    /// Get a human-readable description of the transaction
    pub fn get_transaction_description(parsed_txn: &ParsedTransaction) -> String {
        match &parsed_txn.specific_data {
            TransactionData::Nym(nym_data) => {
                let role_str = match &nym_data.role {
                    Some(role) => format!(" with role {}", role),
                    None => "".to_string(),
                };
                format!("NYM transaction for DID {}{}", nym_data.dest, role_str)
            },
            TransactionData::Attrib(attrib_data) => {
                format!("ATTRIB transaction for DID {}", attrib_data.dest)
            },
            TransactionData::Schema(schema_data) => {
                format!("SCHEMA transaction: {}", schema_data.data.name)
            },
            TransactionData::ClaimDef(claim_def_data) => {
                format!("CLAIM_DEF transaction for schema {}", claim_def_data.schema_ref)
            },
            TransactionData::Node(node_data) => {
                format!("NODE transaction for node {}", node_data.alias)
            },
            TransactionData::RevocRegDef(revoc_reg_def_data) => {
                format!("REVOC_REG_DEF transaction: {}", revoc_reg_def_data.id)
            },
            TransactionData::RevocRegEntry(revoc_reg_entry_data) => {
                format!("REVOC_REG_ENTRY transaction for: {}", revoc_reg_entry_data.revoc_reg_def_id)
            },
            TransactionData::Generic(_) => {
                format!("Transaction of type {:?}", parsed_txn.txn_type)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetcher::RawTransaction;
    use serde_json::json;

    // Helper function to create a raw NYM transaction for testing
    fn create_nym_transaction() -> RawTransaction {
        RawTransaction {
            seq_no: 123,
            txn_time: 1612345678,
            txn_type: "1".to_string(),
            data: json!({
                "txn": {
                    "type": "1",
                    "metadata": {
                        "from": "TWwCRQRZ2ZHMJFn9TzLp7W",
                        "signature": "3YVzDtSxxnowVwAXZmxCG2fz1A38j1qLrwKmGEG653GZw7KJRBX57Stc1Xq3phXn9psEHCvGVaW815NwcyKpWl5"
                    },
                    "data": {
                        "dest": "GBe4SZnF2aXPDHyU6bmYLWA",
                        "role": "0",
                        "verkey": "~7TYfekw4GUagBnBVCqPjiC",
                        "alias": "Alice"
                    }
                },
                "txnMetadata": {
                    "seqNo": 123,
                    "txnTime": 1612345678,
                    "reqId": 15163811881,
                    "protocolVersion": 2
                }
            })
        }
    }

    // Helper function to create a raw SCHEMA transaction for testing
    fn create_schema_transaction() -> RawTransaction {
        RawTransaction {
            seq_no: 124,
            txn_time: 1612345679,
            txn_type: "101".to_string(),
            data: json!({
                "txn": {
                    "type": "101",
                    "metadata": {
                        "from": "TWwCRQRZ2ZHMJFn9TzLp7W",
                        "signature": "4YVzDtSxxnowVwAXZmxCG2fz1A38j1qLrwKmGEG653GZw7KJRBX57Stc1Xq3phXn9psEHCvGVaW815NwcyKpWl6"
                    },
                    "data": {
                        "data": "{\"name\":\"Degree Schema\",\"version\":\"1.0\",\"attr_names\":[\"name\",\"degree\",\"year\"]}",
                    }
                },
                "txnMetadata": {
                    "seqNo": 124,
                    "txnTime": 1612345679,
                    "reqId": 15163811882
                }
            })
        }
    }

    // Helper function to create a raw CLAIM_DEF transaction for testing
    fn create_claim_def_transaction() -> RawTransaction {
        RawTransaction {
            seq_no: 125,
            txn_time: 1612345680,
            txn_type: "102".to_string(),
            data: json!({
                "txn": {
                    "type": "102",
                    "metadata": {
                        "from": "TWwCRQRZ2ZHMJFn9TzLp7W",
                        "signature": "5YVzDtSxxnowVwAXZmxCG2fz1A38j1qLrwKmGEG653GZw7KJRBX57Stc1Xq3phXn9psEHCvGVaW815NwcyKpWl7"
                    },
                    "data": {
                        "signature_type": "CL",
                        "ref": "124",
                        "tag": "TAG1",
                        "data": {
                            "primary": {"n": "987654321", "s": "123456789"},
                            "revocation": null
                        }
                    }
                },
                "txnMetadata": {
                    "seqNo": 125,
                    "txnTime": 1612345680,
                    "reqId": 15163811883
                }
            })
        }
    }

    // Helper function to create a raw NODE transaction for testing
    fn create_node_transaction() -> RawTransaction {
        RawTransaction {
            seq_no: 126,
            txn_time: 1612345681,
            txn_type: "0".to_string(),
            data: json!({
                "txn": {
                    "type": "0",
                    "metadata": {
                        "from": "TWwCRQRZ2ZHMJFn9TzLp7W",
                        "signature": "6YVzDtSxxnowVwAXZmxCG2fz1A38j1qLrwKmGEG653GZw7KJRBX57Stc1Xq3phXn9psEHCvGVaW815NwcyKpWl8"
                    },
                    "data": {
                        "alias": "Node1",
                        "node_ip": "10.0.0.100",
                        "node_port": 9701,
                        "client_ip": "10.0.0.100",
                        "client_port": 9702,
                        "services": ["VALIDATOR"],
                        "blskey": "4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba",
                        "blskey_pop": "RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1"
                    }
                },
                "txnMetadata": {
                    "seqNo": 126,
                    "txnTime": 1612345681,
                    "reqId": 15163811884
                }
            })
        }
    }

    // Test NYM transaction parsing
    #[tokio::test]
    async fn test_nym_parser() {
        let raw_txn = create_nym_transaction();
        let parser = NYMTransactionParser;
        
        assert!(parser.can_parse(&raw_txn).await);
        
        let parsed = parser.parse(&raw_txn).await.unwrap();
        
        assert_eq!(parsed.seq_no, 123);
        assert_eq!(parsed.txn_time, 1612345678);
        assert!(matches!(parsed.txn_type, TransactionType::NYM));
        assert_eq!(parsed.identifier, "TWwCRQRZ2ZHMJFn9TzLp7W");
        
        if let TransactionData::Nym(nym_data) = parsed.specific_data {
            assert_eq!(nym_data.dest, "GBe4SZnF2aXPDHyU6bmYLWA");
            assert_eq!(nym_data.role, Some("0".to_string()));
            assert_eq!(nym_data.verkey, Some("~7TYfekw4GUagBnBVCqPjiC".to_string()));
            assert_eq!(nym_data.alias, Some("Alice".to_string()));
        } else {
            panic!("Expected Nym data");
        }
    }

    // Test SCHEMA transaction parsing
    #[tokio::test]
    async fn test_schema_parser() {
        let raw_txn = create_schema_transaction();
        let parser = SCHEMATransactionParser;
        
        assert!(parser.can_parse(&raw_txn).await);
        
        let parsed = parser.parse(&raw_txn).await.unwrap();
        
        assert_eq!(parsed.seq_no, 124);
        assert_eq!(parsed.txn_time, 1612345679);
        assert!(matches!(parsed.txn_type, TransactionType::SCHEMA));
        
        if let TransactionData::Schema(schema_data) = parsed.specific_data {
            assert_eq!(schema_data.data.name, "Degree Schema");
            assert_eq!(schema_data.data.version, "1.0");
            assert_eq!(schema_data.data.attr_names, vec!["name", "degree", "year"]);
        } else {
            panic!("Expected Schema data");
        }
    }

    // Test CLAIM_DEF transaction parsing
    #[tokio::test]
    async fn test_claim_def_parser() {
        let raw_txn = create_claim_def_transaction();
        let parser = CLAIMDEFTransactionParser;
        
        assert!(parser.can_parse(&raw_txn).await);
        
        let parsed = parser.parse(&raw_txn).await.unwrap();
        
        assert_eq!(parsed.seq_no, 125);
        assert_eq!(parsed.txn_time, 1612345680);
        assert!(matches!(parsed.txn_type, TransactionType::CLAIM_DEF));
        
        if let TransactionData::ClaimDef(claim_def_data) = parsed.specific_data {
            assert_eq!(claim_def_data.signature_type, "CL");
            assert_eq!(claim_def_data.schema_ref, "124");
            assert_eq!(claim_def_data.tag, "TAG1");
            assert!(claim_def_data.data.is_object());
        } else {
            panic!("Expected ClaimDef data");
        }
    }

    // Test NODE transaction parsing
    #[tokio::test]
    async fn test_node_parser() {
        let raw_txn = create_node_transaction();
        let parser = NODETransactionParser;
        
        assert!(parser.can_parse(&raw_txn).await);
        
        let parsed = parser.parse(&raw_txn).await.unwrap();
        
        assert_eq!(parsed.seq_no, 126);
        assert_eq!(parsed.txn_time, 1612345681);
        assert!(matches!(parsed.txn_type, TransactionType::NODE));
        
        if let TransactionData::Node(node_data) = parsed.specific_data {
            assert_eq!(node_data.alias, "Node1");
            assert_eq!(node_data.node_ip, Some("10.0.0.100".to_string()));
            assert_eq!(node_data.node_port, Some(9701));
            assert_eq!(node_data.client_ip, Some("10.0.0.100".to_string()));
            assert_eq!(node_data.client_port, Some(9702));
            assert_eq!(node_data.services, Some(vec!["VALIDATOR".to_string()]));
            assert!(node_data.blskey.is_some());
        } else {
            panic!("Expected Node data");
        }
    }

    // Test transaction parser registry
    #[tokio::test]
    async fn test_parser_registry() {
        let registry = TransactionParserRegistry::new();
        
        // Test NYM transaction
        let nym_txn = create_nym_transaction();
        let parsed_nym = registry.parse_transaction(&nym_txn).await.unwrap();
        assert!(matches!(parsed_nym.txn_type, TransactionType::NYM));
        
        // Test SCHEMA transaction
        let schema_txn = create_schema_transaction();
        let parsed_schema = registry.parse_transaction(&schema_txn).await.unwrap();
        assert!(matches!(parsed_schema.txn_type, TransactionType::SCHEMA));
        
        // Test transaction description helper
        let nym_desc = helpers::get_transaction_description(&parsed_nym);
        assert!(nym_desc.contains("NYM transaction"));
        assert!(nym_desc.contains("GBe4SZnF2aXPDHyU6bmYLWA"));
        
        // Test role helper
        let role = helpers::get_role_from_nym(&parsed_nym);
        assert!(matches!(role, Some(Role::Trustee)));
        
        // Test role modification helper
        assert!(helpers::is_role_modification(&parsed_nym));
    }
}