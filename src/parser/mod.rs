use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;
use serde::{Serialize, Deserialize};

use crate::error::Result;
use crate::fetcher::RawTransaction;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionType {
    // Node transaction
    NODE,                  // "0"
    
    // Domain transactions
    NYM,                   // "1"
    ATTRIB,                // "100"
    SCHEMA,                // "101"
    ClaimDef,             // "102"
    RevocRegDef,         // "113"
    RevocRegEntry,       // "114"
    
    // Pool transactions
    PoolUpgrade,          // "109"
    PoolConfig,           // "110"
    
    // Config transactions
    AuthRule,             // "120"
    AuthRules,            // "122"
    PoolRestart,          // "118"
    ValidatorInfo,        // "119"
    
    // Config ledger transaction types
    SetFees,              // "20000"
    TxnsAuthrAgrmt,      // "4"
    TxnsAuthrAgrmtAml,  // "5"
    GetTxnsAuthrAgrmt,  // "6"
    DisableAuthrAgrmt,   // "8"
    
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
            "102" => TransactionType::ClaimDef,
            "113" => TransactionType::RevocRegDef,
            "114" => TransactionType::RevocRegEntry,
            
            // Pool
            "109" => TransactionType::PoolUpgrade,
            "110" => TransactionType::PoolConfig,
            
            // Config
            "120" => TransactionType::AuthRule,
            "122" => TransactionType::AuthRules,
            "118" => TransactionType::PoolRestart,
            "119" => TransactionType::ValidatorInfo,
            
            // Config ledger
            "20000" => TransactionType::SetFees,
            "4" => TransactionType::TxnsAuthrAgrmt,
            "5" => TransactionType::TxnsAuthrAgrmtAml,
            "6" => TransactionType::GetTxnsAuthrAgrmt,
            "8" => TransactionType::DisableAuthrAgrmt,
            
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

#[async_trait]
pub trait TransactionParser: Send + Sync {
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool;
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction>;
}

pub struct NYMTransactionParser;

#[async_trait]
impl TransactionParser for NYMTransactionParser {
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool {
        raw_txn.txn_type == "1" || raw_txn.data["txn"]["type"].as_str() == Some("1")
    }
    
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        let txn = &raw_txn.data["txn"];
        let txn_metadata = &raw_txn.data["txnMetadata"];
        
        // Try to get the identifier from the usual place first
        let identifier = if let Some(from) = txn["metadata"]["from"].as_str() {
            // Regular transaction with "from" field
            from.to_string()
        } else {
            // Genesis transaction - use dest as identifier
            let dest = txn["data"]["dest"].as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'dest' field in NYM transaction"))?;
            format!("{} (Genesis Transaction)", dest)
        };
        
        // Signature may not exist for genesis transactions
        let signature = txn["metadata"]["signature"].as_str().map(|s| s.to_string());
        
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
        
        // Try to get the identifier from the various possible locations
        let identifier = txn["metadata"]["from"].as_str()
            .or_else(|| txn["from"].as_str())
            .or_else(|| raw_txn.data["reqSignature"]["values"].as_array()
                .and_then(|values| values.get(0))
                .and_then(|v| v["from"].as_str()))
            .unwrap_or("UNKNOWN")
            .to_string();
        
        let signature = txn["metadata"]["signature"].as_str()
            .or_else(|| raw_txn.data["reqSignature"]["signature"].as_str())
            .or_else(|| raw_txn.data["reqSignature"]["values"].as_array()
                .and_then(|values| values.get(0))
                .and_then(|v| v["value"].as_str()))
            .map(|s| s.to_string());
        
        // Get the schema data - handle both formats
        let data_field = &txn["data"]["data"];
        
        // Extract schema fields - now handling both string and object formats
        let schema_content = if data_field.is_object() {
            // Direct JSON object format
            SchemaContent {
                name: data_field["name"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing 'name' in schema data"))?
                    .to_string(),
                version: data_field["version"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing 'version' in schema data"))?
                    .to_string(),
                attr_names: data_field["attr_names"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("Missing 'attr_names' in schema data"))?
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
            }
        } else if data_field.is_string() {
            // JSON string format that needs parsing
            let schema_json = data_field.as_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid 'data' field in SCHEMA transaction"))?;
            
            let schema_value: Value = serde_json::from_str(schema_json)
                .map_err(|e| anyhow::anyhow!("Failed to parse schema JSON: {}", e))?;
            
            SchemaContent {
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
            }
        } else {
            return Err(anyhow::anyhow!("Invalid 'data' field format in SCHEMA transaction"));
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


/// Parser for REVOC_REG_DEF transactions
pub struct REVOCREGDEFTransactionParser;

#[async_trait]
impl TransactionParser for REVOCREGDEFTransactionParser {
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool {
        raw_txn.txn_type == "113" || raw_txn.data["txn"]["type"].as_str() == Some("113")
    }
    
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        let txn = &raw_txn.data["txn"];
        let txn_metadata = &raw_txn.data["txnMetadata"];
        
        let identifier = txn["metadata"]["from"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'from' field in REVOC_REG_DEF transaction"))?
            .to_string();
        
        let signature = txn["metadata"]["signature"]
            .as_str()
            .map(|s| s.to_string());
        
        let data = &txn["data"];
        
        // Parse REVOC_REG_DEF specific data
        let revoc_reg_def_data = RevocRegDefData {
            id: data["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'id' field in REVOC_REG_DEF transaction"))?
                .to_string(),
            revoc_def_type: data["revocDefType"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'revocDefType' field in REVOC_REG_DEF transaction"))?
                .to_string(),
            tag: data["tag"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'tag' field in REVOC_REG_DEF transaction"))?
                .to_string(),
            cred_def_id: data["credDefId"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'credDefId' field in REVOC_REG_DEF transaction"))?
                .to_string(),
            value: data["value"].clone(),
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
            txn_type: TransactionType::RevocRegDef,
            identifier,
            signature,
            metadata,
            specific_data: TransactionData::RevocRegDef(revoc_reg_def_data),
            raw_data: raw_txn.data.clone(),
        })
    }
}

/// Parser for REVOC_REG_ENTRY transactions
pub struct REVOCREGENTRYTransactionParser;

#[async_trait]
impl TransactionParser for REVOCREGENTRYTransactionParser {
    async fn can_parse(&self, raw_txn: &RawTransaction) -> bool {
        raw_txn.txn_type == "114" || raw_txn.data["txn"]["type"].as_str() == Some("114")
    }
    
    async fn parse(&self, raw_txn: &RawTransaction) -> Result<ParsedTransaction> {
        let txn = &raw_txn.data["txn"];
        let txn_metadata = &raw_txn.data["txnMetadata"];
        
        let identifier = txn["metadata"]["from"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'from' field in REVOC_REG_ENTRY transaction"))?
            .to_string();
        
        let signature = txn["metadata"]["signature"]
            .as_str()
            .map(|s| s.to_string());
        
        let data = &txn["data"];
        
        // Parse REVOC_REG_ENTRY specific data
        let revoc_reg_entry_data = RevocRegEntryData {
            revoc_reg_def_id: data["revocRegDefId"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'revocRegDefId' field in REVOC_REG_ENTRY transaction"))?
                .to_string(),
            revoc_def_type: data["revocDefType"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'revocDefType' field in REVOC_REG_ENTRY transaction"))?
                .to_string(),
            value: data["value"].clone(),
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
            txn_type: TransactionType::RevocRegEntry,
            identifier,
            signature,
            metadata,
            specific_data: TransactionData::RevocRegEntry(revoc_reg_entry_data),
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
            schema_ref: match data["ref"] {
                Value::String(ref s) => s.clone(),
                Value::Number(ref n) => n.to_string(),
                _ => return Err(anyhow::anyhow!("Missing or invalid 'ref' field in CLAIM_DEF transaction"))
            },
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
            txn_type: TransactionType::ClaimDef,
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

/// Registry of transaction parsers
#[derive(Clone)]
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
            Arc::new(REVOCREGDEFTransactionParser),   
            Arc::new(REVOCREGENTRYTransactionParser), 
            
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
                    "reqId": 1516381181,
                    "protocolVersion": 2
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
}