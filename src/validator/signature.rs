// For src/validator/signature.rs

use crate::config::trust_store::{TrustStoreConfig, TrustedDid, TrustLevel};
use crate::parser::ParsedTransaction;
use crate::error::Result;
use indy_vdr::utils::base58;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use std::sync::Arc;
use serde_json::Value;
use tracing::{debug, info, warn};

pub struct SignatureVerificationResult {
    pub verified: bool,
    pub trust_level: Option<TrustLevel>,
    pub details: String,
    pub warnings: Vec<String>,
}

pub struct SignatureVerifier {
    trust_store: Arc<TrustStoreConfig>,
}

impl SignatureVerifier {
    pub fn new(trust_store: Arc<TrustStoreConfig>) -> Self {
        Self { trust_store }
    }
    
    // Find a DID in the trust store
    pub fn find_trusted_did(&self, did: &str) -> Option<&TrustedDid> {
        self.trust_store.trusted_dids.iter().find(|td| td.did == did)
    }
    
    // Main verification method
    pub async fn verify_transaction(&self, transaction: &ParsedTransaction) -> Result<SignatureVerificationResult> {
        let mut result = SignatureVerificationResult {
            verified: false,
            trust_level: None,
            details: String::new(),
            warnings: Vec::new(),
        };
        
        // Get the raw transaction data
        let raw_data = &transaction.raw_data;
        
        // Check if this transaction has signature(s)
        let req_signature = &raw_data["reqSignature"];
        if req_signature.is_null() {
            result.details = "Transaction has no signature".to_string();
            result.warnings.push("Missing signature".to_string());
            return Ok(result);
        }
        
        // Extract the txn part of the transaction
        let txn = &raw_data["txn"];
        if txn.is_null() || !txn.is_object() {
            result.details = "Missing or invalid txn field in transaction".to_string();
            result.warnings.push("Invalid transaction format".to_string());
            return Ok(result);
        }
        
        // Get the message to verify based on transaction type
        let transaction_type = txn["type"].as_str().unwrap_or("unknown");
        let signature_input = match transaction_type {
            "101" => self.get_schema_signature_input(txn),
            _ => {
                let msg = format!("Unsupported transaction type: {}. Only SCHEMA (101) transactions are supported currently.", transaction_type);
                warn!("{}", msg);
                result.details = msg;
                result.warnings.push("Unsupported transaction type".to_string());
                return Ok(result);
            }
        };
        
        info!("Using signature input for verification: {}", signature_input);
        
        // Verify based on signature type (single or multi)
        if let Some(values) = req_signature["values"].as_array() {
            // Multiple signatures
            result.details = "Transaction has multiple signatures:".to_string();
            let mut all_verified = true;
            
            debug!("Transaction has {} signatures", values.len());
            
            for (i, sig_entry) in values.iter().enumerate() {
                let signer_did = sig_entry["from"].as_str().unwrap_or("unknown");
                let signature = sig_entry["value"].as_str().unwrap_or("");
                
                debug!("Verifying signature {} from DID {}", i+1, signer_did);
                debug!("Signature value: {}", signature);
                
                let trusted_did = self.find_trusted_did(signer_did);
                
                // If we found a trusted DID, set the trust level
                if let Some(td) = trusted_did {
                    debug!("Found DID {} in trust store with trust level {:?}", 
                        signer_did, td.trust_level);
                    
                    if result.trust_level.is_none() {
                        result.trust_level = Some(td.trust_level.clone());
                    }
                }
                
                match self.verify_single_signature(
                    signer_did,
                    signature,
                    &signature_input,
                    trusted_did
                ) {
                    Ok((verified, msg)) => {
                        if verified {
                            info!("Signature {} from DID {} verified successfully", i+1, signer_did);
                        } else {
                            warn!("Signature {} from DID {} verification failed: {}", i+1, signer_did, msg);
                        }
                        
                        result.details.push_str(&format!("\n  Signer {}: DID {} - {}", i + 1, signer_did, msg));
                        
                        if !verified {
                            all_verified = false;
                            result.warnings.push(format!("Invalid signature from DID {}", signer_did));
                        }
                    },
                    Err(e) => {
                        warn!("Error verifying signature {} from DID {}: {}", i+1, signer_did, e);
                        
                        result.details.push_str(&format!(
                            "\n  Signer {}: DID {} - Verification error: {}", 
                            i + 1, signer_did, e
                        ));
                        all_verified = false;
                        result.warnings.push(format!("Verification error for DID {}", signer_did));
                    }
                }
            }
            
            result.verified = all_verified;
        } else if let Some(sig_value) = req_signature["value"].as_str() {
            // Single signature
            let signer_did = &transaction.identifier;
            
            debug!("Transaction has a single signature from DID {}", signer_did);
            debug!("Signature value: {}", sig_value);
            
            let trusted_did = self.find_trusted_did(signer_did);
            
            if let Some(td) = trusted_did {
                debug!("Found DID {} in trust store with trust level {:?}", 
                    signer_did, td.trust_level);
                
                result.trust_level = Some(td.trust_level.clone());
            }
            
            match self.verify_single_signature(
                signer_did, 
                sig_value, 
                &signature_input, 
                trusted_did
            ) {
                Ok((verified, msg)) => {
                    if verified {
                        info!("Signature from DID {} verified successfully", signer_did);
                    } else {
                        warn!("Signature from DID {} verification failed: {}", signer_did, msg);
                    }
                    
                    result.verified = verified;
                    result.details = msg;
                    
                    if !verified {
                        result.warnings.push("Invalid signature".to_string());
                    }
                },
                Err(e) => {
                    warn!("Error verifying signature from DID {}: {}", signer_did, e);
                    
                    result.details = format!("Signature verification error: {}", e);
                    result.warnings.push("Signature verification failed".to_string());
                }
            }
        } else {
            warn!("Unrecognized signature format");
            
            result.details = "Unrecognized signature format".to_string();
            result.warnings.push("Unknown signature format".to_string());
        }
        
        debug!("Signature verification result: verified={}, warnings={:?}", 
            result.verified, result.warnings);
        
        Ok(result)
    }
    
    // Generate the canonical message format for schema transactions
    fn get_schema_signature_input(&self, txn: &Value) -> String {
        format!(
            "data:data:attr_names:{}|name:{}|version:{}|metadata:digest:{}|endorser:{}|from:{}|payloadDigest:{}|reqId:{}|taaAcceptance:mechanism:{}|taaDigest:{}|time:{}|protocolVersion:{}|type:{}",
            txn["data"]["data"]["attr_names"].as_array().map_or("".to_string(), |a|
                a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(",")),
            txn["data"]["data"]["name"].as_str().unwrap_or(""),
            txn["data"]["data"]["version"].as_str().unwrap_or(""),
            txn["metadata"]["digest"].as_str().unwrap_or(""),
            txn["metadata"]["endorser"].as_str().unwrap_or(""),
            txn["metadata"]["from"].as_str().unwrap_or(""),
            txn["metadata"]["payloadDigest"].as_str().unwrap_or(""),
            txn["metadata"]["reqId"].as_u64().unwrap_or(0),
            txn["metadata"]["taaAcceptance"]["mechanism"].as_str().unwrap_or(""),
            txn["metadata"]["taaAcceptance"]["taaDigest"].as_str().unwrap_or(""),
            txn["metadata"]["taaAcceptance"]["time"].as_u64().unwrap_or(0),
            txn["protocolVersion"].as_u64().unwrap_or(0),
            txn["type"].as_str().unwrap_or("")
        )
    }
    
    fn verify_single_signature(
        &self,
        did: &str,
        signature_b58: &str,
        signature_input: &str,
        trusted_did: Option<&TrustedDid>,
    ) -> Result<(bool, String)> {
        // Check if we have the verification key
        let verkey = if let Some(trusted_did) = trusted_did {
            if let Some(ref vk) = trusted_did.verification_key {
                vk.clone()
            } else {
                return Ok((false, format!("DID {} is in trust store but verification key is missing", did)));
            }
        } else {
            return Ok((false, format!("DID {} is not in trust store, unable to verify signature", did)));
        };
        
        // Decode the base58 signature
        let signature_bytes = match base58::decode(signature_b58) {
            Ok(bytes) => {
                debug!("Decoded signature from base58, length: {}", bytes.len());
                bytes
            },
            Err(e) => {
                warn!("Failed to decode signature from base58: {}", e);
                return Ok((false, format!("Failed to decode signature from base58: {}", e)));
            }
        };
        
        // For debugging, show the raw signature bytes
        debug!("Signature bytes (first 8): {:?}", &signature_bytes.get(0..8.min(signature_bytes.len())));
        
        // Decode the base58 verification key
        let verkey_bytes = match base58::decode(&verkey) {
            Ok(bytes) => {
                debug!("Decoded verification key from base58, length: {}", bytes.len());
                bytes
            },
            Err(e) => {
                warn!("Failed to decode verification key from base58: {}", e);
                return Ok((false, format!("Failed to decode verification key from base58: {}", e)));
            }
        };
        
        // For debugging, show the raw verification key bytes
        debug!("Verification key bytes (first 8): {:?}", &verkey_bytes.get(0..8.min(verkey_bytes.len())));
        
        // Create a verification key from the decoded bytes
        if verkey_bytes.len() != 32 {
            warn!("Invalid verification key length: expected 32 bytes, got {}", verkey_bytes.len());
            return Ok((false, format!("Invalid verification key length: expected 32 bytes, got {}", verkey_bytes.len())));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&verkey_bytes);
        
        let verify_key = match VerifyingKey::from_bytes(&key_bytes) {
            Ok(key) => {
                debug!("Successfully created VerifyingKey from bytes");
                key
            },
            Err(e) => {
                warn!("Invalid verification key: {}", e);
                return Ok((false, format!("Invalid verification key: {}", e)));
            }
        };
        
        // Create a signature from the decoded bytes
        if signature_bytes.len() != 64 {
            warn!("Invalid signature length: expected 64 bytes, got {}", signature_bytes.len());
            return Ok((false, format!("Invalid signature length: expected 64 bytes, got {}", signature_bytes.len())));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&signature_bytes);
        
        let signature = match Signature::try_from(sig_bytes) {
            Ok(sig) => {
                debug!("Successfully created Signature from bytes");
                sig
            },
            Err(e) => {
                warn!("Invalid signature format: {}", e);
                return Ok((false, format!("Invalid signature format: {}", e)));
            }
        };
        
        // Debug: Print the message that will be verified
        debug!("Message to verify (length: {}): '{}'", signature_input.len(), signature_input);
        
        // Verify the signature against the canonical form of the transaction
        match verify_key.verify(signature_input.as_bytes(), &signature) {
            Ok(_) => {
                debug!("Signature verification successful for DID {}", did);
                Ok((true, format!("Signature verified with trusted key")))
            },
            Err(e) => {
                warn!("Signature verification failed for DID {}: {}", did, e);
                Ok((false, format!("Signature verification failed: {}", e)))
            }
        }
    }
}