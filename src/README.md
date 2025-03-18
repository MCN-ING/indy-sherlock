# Indy Sherlock

A Hyperledger Indy Ledger Auditing Tool for investigating and analyzing ledger transactions.

## Overview

Indy Sherlock is a robust Rust-based transaction investigation tool designed to scan, analyze, and report on Hyperledger Indy ledger transactions. It excels at identifying suspicious, unauthorized, or anomalous transactions that could indicate security breaches, protocol violations, or governance issues.

## Key Features

- **Connect to any Indy Network**: Works with any network that publishes a genesis file
- **Transaction Fetching**: Efficiently retrieve transactions from Indy ledgers 
- **Transaction Parsing**: Decode all Indy transaction types (NYM, ATTRIB, SCHEMA, CLAIM_DEF, etc.)
- **DID Trust Store**: Maintain a database of known DIDs and their verification keys
- **State Proof Validation**: Verify transaction state proofs to ensure ledger integrity
- **Anomaly Detection**: Identify suspicious patterns like unusual transaction frequencies and role elevations
- **Permission Validation**: Check if DIDs have appropriate permissions for their actions
- **Format Validation**: Ensure transactions follow expected data formats
- **Sequence Validation**: Verify correct dependencies between related transactions
- **Ledger Configuration**: Support for multiple ledgers with easy configuration
- **Interactive Analysis**: Investigate specific transactions or ranges of transactions
- **Comprehensive Auditing**: Run complete audits with customizable validation options
- **Caching**: Resume audits where they left off with intelligent checkpointing

### Running Audits

#### Run a comprehensive audit

```bash
indy-sherlock run-audit --ledger <LEDGER_ID> [--start <START_SEQ_NO>] --count <COUNT> --output <OUTPUT_FILE> [OPTIONS]
```

Run a complete audit with customizable validation options:

- `--no-state-proofs`: Skip state proof validation
- `--no-formats`: Skip format validation
- `--no-permissions`: Skip permission validation
- `--no-sequences`: Skip sequence validation
- `--no-anomalies`: Skip anomaly detection
- `--force-full`: Force audit from the beginning, ignoring cache

If `--start` is omitted, the audit will resume from where the previous audit left off (using cache).

The audit report will be saved in JSON format, containing:

- Statistics about transactions analyzed
- Findings categorized by severity (Critical, High, Medium, Low, Info)
- Detailed information about each finding
- Metadata about the audit process