use serde_json::Value;
use anyhow::{Context, Result};
use indy_vdr::pool::{LocalPool, PoolBuilder, Pool};
use indy_vdr::config::PoolConfig;
use indy_vdr::pool::helpers::perform_ledger_request;

use indy_vdr::pool::RequestResult;

use std::io::{self, Write};
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::helpers::genesis::GenesisSource;

#[derive(Debug)]
pub struct RawTransaction {
    pub seq_no: i32,
    pub txn_time: u64,
    pub txn_type: String,
    pub data: Value,
}

pub struct LedgerFetcher {
    pool: LocalPool,
}

impl LedgerFetcher {
    pub async fn new(genesis_source: &GenesisSource) -> Result<Self> {
        let transactions = genesis_source.load_transactions()
            .await
            .with_context(|| "Failed to load genesis transactions")?;

        let pool = PoolBuilder::new(PoolConfig::default(), transactions)
            .into_local()
            .with_context(|| "Failed to create pool")?;
        
        Ok(Self { pool })
    }
    
    pub async fn check_connection(&self) -> Result<bool> {
        // Get config transaction which should always be available (#1)
        let request = self.pool
            .get_request_builder()
            .build_get_txn_request(None, 1, 1) // Using DOMAIN ledger (1), seq_no = 1
            .with_context(|| "Failed to build connection test request")?;

        match perform_ledger_request(&self.pool, &request, None).await {
            Ok((RequestResult::Reply(_), _)) => Ok(true),
            Ok((RequestResult::Failed(err), _)) => {
                tracing::debug!("Connection check failed: {}", err);
                Ok(false)
            }
            Err(e) => {
                Err(anyhow::anyhow!("Connection check error: {}", e))
            }
        }
    }
    pub async fn get_transactions_in_range_with_progress(
        &self, 
        start: i32, 
        count: i32,
        batch_size: i32
    ) -> Result<Vec<RawTransaction>> {
        let mut transactions = Vec::with_capacity(count as usize);
        let mut processed = 0;
        let total_batches = (count + batch_size - 1) / batch_size; // Ceiling division
        let mut current_batch = 0;
        
        // Process in batches for better performance and progress reporting
        for batch_start in (start..start+count).step_by(batch_size as usize) {
            current_batch += 1;
            let batch_end = std::cmp::min(batch_start + batch_size, start + count);
            let batch_count = batch_end - batch_start;
            
            // Display progress
            print!("\rFetching batch {}/{}: transactions {}-{} of {}     ", 
                current_batch, total_batches, batch_start, batch_end-1, start+count-1);
            io::stdout().flush().unwrap_or(());
            
            let mut batch_txns = Vec::with_capacity(batch_count as usize);
            for seq_no in batch_start..batch_end {
                match self.get_transaction(seq_no).await {
                    Ok(txn) => batch_txns.push(txn),
                    Err(e) => {
                        // If the transaction is not found, we'll skip it
                        if e.to_string().contains("not found") {
                            continue;
                        }
                        // Otherwise propagate the error
                        return Err(e.context(format!("Error fetching transaction {}", seq_no)));
                    }
                }
            }
            
            processed += batch_txns.len() as i32;
            transactions.extend(batch_txns);
        }
        
        println!("\rFetched {} transactions                  ", processed);
        
        Ok(transactions)
    }
    pub async fn get_ledger_size(&self) -> Result<i32> {
        // Request transaction #1 to get the ledger size
        let request = self.pool
            .get_request_builder()
            .build_get_txn_request(None, 1, 1) // Domain ledger (1), seq_no=1
            .with_context(|| "Failed to build request for ledger size")?;
        
        // Submit the request
        let (request_result, _) = perform_ledger_request(&self.pool, &request, None)
            .await
            .with_context(|| "Failed to perform request for ledger size")?;
        
        // Process the result
        match request_result {
            RequestResult::Reply(response) => {
                let response_json: Value = serde_json::from_str(&response)
                    .with_context(|| "Failed to parse response for ledger size")?;
                
                // Extract the ledger size from the data
                if let Some(ledger_size) = response_json["result"]["data"]["ledgerSize"].as_i64() {
                    return Ok(ledger_size as i32);
                }
                
                Err(anyhow::anyhow!("Could not determine ledger size from response"))
            },
            RequestResult::Failed(err) => {
                Err(anyhow::anyhow!("Failed to determine ledger size: {}", err))
            }
        }
    }
    pub async fn get_transactions_in_range_parallel(
        &self, 
        start: i32, 
        count: i32,
        concurrency: usize
    ) -> Result<Vec<RawTransaction>> {
        // Create shared vector to collect results
        let transactions = Arc::new(Mutex::new(Vec::with_capacity(count as usize)));
        let progress = Arc::new(Mutex::new((0, 0))); // (found, processed)
        
        println!("Fetching transactions {}-{} with concurrency level {}", 
            start, start + count - 1, concurrency);
        
        // Create sequence numbers to process
        let seq_numbers: Vec<i32> = (start..start+count).collect();
        
        // Process in parallel with limited concurrency
        stream::iter(seq_numbers)
            .map(|seq_no| {
                let transactions = Arc::clone(&transactions);
                let progress = Arc::clone(&progress);
                
                async move {
                    let result = self.get_transaction(seq_no).await;
                    
                    let mut progress_guard = progress.lock().await;
                    progress_guard.1 += 1; // Increment processed count
                    
                    let processed = progress_guard.1;
                    let found = progress_guard.0;
                    
                    // Print progress
                    print!("\rProcessed: {}/{} | Found: {}     ", 
                        processed, count, found);
                    std::io::stdout().flush().unwrap_or(());
                    
                    match result {
                        Ok(txn) => {
                            // Add to our result vector
                            let mut txns = transactions.lock().await;
                            txns.push(txn);
                            
                            // Update found count
                            progress_guard.0 += 1;
                        },
                        Err(e) => {
                            // Skip "not found" errors as they're expected
                            if !e.to_string().contains("not found") {
                                // Log other errors but don't fail the entire process
                                eprintln!("\nError fetching transaction {}: {}", seq_no, e);
                            }
                        }
                    }
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<()>>()
            .await;
        
        println!("\nCompleted fetching transactions");
        
        // Get the final results
        let result = Arc::try_unwrap(transactions)
            .expect("There should be no other references")
            .into_inner();
        
        Ok(result)
    }

    pub async fn get_transaction(&self, seq_no: i32) -> Result<RawTransaction> {
        // Create a GET_TXN request
        let request = self.pool
            .get_request_builder()
            .build_get_txn_request(None, 1, seq_no) // Using DOMAIN ledger (1)
            .with_context(|| format!("Failed to build request for transaction {}", seq_no))?;
        
        // Submit the request
        let (request_result, _) = perform_ledger_request(&self.pool, &request, None)
            .await
            .with_context(|| format!("Failed to perform request for transaction {}", seq_no))?;
        
        // Process the result
        match request_result {
            RequestResult::Reply(response) => {
                // Parse the response
                let response_json: Value = serde_json::from_str(&response)
                    .with_context(|| format!("Failed to parse response for transaction {}", seq_no))?;
                
                // Extract transaction data
                let data = response_json["result"]["data"].clone();
                if data.is_null() {
                    return Err(anyhow::anyhow!("Transaction with seq_no {} not found", seq_no));
                }
                
                // Extract transaction metadata
                let txn_metadata = &data["txnMetadata"];
                let seq_no = txn_metadata["seqNo"].as_i64().unwrap_or(0) as i32;
                let txn_time = txn_metadata["txnTime"].as_u64().unwrap_or(0);
                
                // Extract transaction type
                let txn_type = data["txn"]["type"].as_str().unwrap_or("UNKNOWN").to_string();
                
                Ok(RawTransaction {
                    seq_no,
                    txn_time,
                    txn_type,
                    data,
                })
            },
            RequestResult::Failed(err) => {
                Err(anyhow::anyhow!("Ledger request failed: {}", err))
            }
        }
    }
    
    // We can add specific methods here as we need them
    // rather than adding unused functionality
    
    pub async fn get_transactions_in_range(&self, start: i32, count: i32) 
        -> Result<Vec<RawTransaction>> {
        let mut transactions = Vec::with_capacity(count as usize);
        
        for seq_no in start..(start + count) {
            match self.get_transaction(seq_no).await {
                Ok(txn) => transactions.push(txn),
                Err(e) => {
                    // If the transaction is not found, we'll skip it
                    if e.to_string().contains("not found") {
                        continue;
                    }
                    // Otherwise propagate the error
                    return Err(e.context(format!("Error fetching transaction {}", seq_no)));
                }
            }
        }
        
        Ok(transactions)
    }
}