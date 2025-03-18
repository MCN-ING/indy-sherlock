# Anomaly Detection Guide

This guide explains how to use the anomaly detection features of Indy Sherlock to identify suspicious or unauthorized transactions on a Hyperledger Indy ledger.

## Introduction

The anomaly detection system is designed to identify transactions that exhibit suspicious patterns, violate governance rules, or represent unusual behavior. Unlike strict cryptographic verification, this approach focuses on identifying governance violations and suspicious patterns that may indicate security issues.

## Anomaly Types

The tool can detect several types of anomalies:

### Permission and role anomalies
- **Unauthorized Role Change**: DIDs without proper authority changing roles
- **Role Elevation**: DIDs receiving higher privileges than normal

### Transaction pattern anomalies
- **High Transaction Frequency**: Unusual volume or spike in transactions from a single DID
- **Unexpected Transaction Sequence**: Transactions appearing in an invalid order

### Schema anomalies
- **Schema Modification**: Suspicious schema changes or attributes including:
  - Sensitive attributes (SSN, credit card, passwords, etc.)
  - Attribute removals between versions
  - Excessive or rapid versioning
  - Typosquatting (similar names to existing schemas)
  - Publisher changes (new DIDs publishing versions of existing schemas)

### Trust framework anomalies
- **Node Configuration Change**: Changes to node IP addresses, ports, or services
- **Configuration Change**: Changes to network configuration parameters

### Unauthorized actions
- **Unauthorized Action**: Any transaction performed by an entity without proper authority

## Setting Up for Anomaly Detection

### 1. Update your trust store

Before running anomaly detection, you should update your trust store to include DIDs from the ledger along with their roles:

```bash
indy-sherlock update-trust-store --ledger LEDGER_ID --count 5000
```

This command scans the first 5000 transactions on the ledger to build a database of DIDs and their roles for use in anomaly detection.

### 2. Run anomaly detection

Once your trust store is updated, you can run anomaly detection:

```bash
indy-sherlock detect-anomalies --ledger LEDGER_ID --start 1 --count 10000
```

This command will:
1. Fetch the specified range of transactions
2. Parse the transactions into structured data
3. Apply anomaly detection rules
4. Report any findings

You can choose between quick and thorough detection modes:

```bash
indy-sherlock detect-anomalies --ledger LEDGER_ID --start 1 --count 10000 --mode thorough
```

### 3. Examining the results

The findings are organized by severity level:
- **Critical**: High-impact governance violations requiring immediate attention
- **High**: Serious anomalies that should be investigated
- **Medium**: Suspicious patterns that may require follow-up
- **Low**: Minor observations that could be benign

## Example Usage Scenarios

### Monitoring role changes

```bash
# Detect any unauthorized role elevations
indy-sherlock detect-anomalies --ledger sovrin-main --start 1 --count 10000
```

### Detecting suspicious schemas

```bash
# Look for schemas with potentially sensitive attributes or other anomalies
indy-sherlock detect-anomalies --ledger sovrin-main --start 1 --count 10000 --mode thorough
```

### Auditing a particular timeframe

```bash
# First, find transactions in the time period of interest
indy-sherlock analyze-range --ledger sovrin-main --start 5000 --count 1000

# Then run anomaly detection on those transactions
indy-sherlock detect-anomalies --ledger sovrin-main --start 5000 --count 1000
```

### Comprehensive audit with anomaly detection

```bash
# Run a full audit including anomaly detection
indy-sherlock run-audit --ledger sovrin-main --start 1 --count 10000 --output audit-report.json
```

### Disabling specific validations

```bash
# Run anomaly detection without signature validation
indy-sherlock run-audit --ledger sovrin-main --start 1 --count 10000 --no-signatures
```

## Advanced Usage

### Using different detection modes

The tool supports two detection modes:
- **quick**: Faster analysis focusing on common anomalies (default)
- **thorough**: Comprehensive analysis using all available detectors

```bash
indy-sherlock detect-anomalies --ledger sovrin-main --start 1 --count 10000 --mode thorough
```

### False positive handling

If you encounter false positives, you can:
1. Update your trust store to include more authorized DIDs
2. Configure the trust levels in the trust store
3. Use the thorough mode for more accurate detection

## Next Steps

With the anomaly detection results in hand, typical next steps include:
1. Investigating critical and high severity findings
2. Verifying suspicious transactions with network governance authorities
3. Monitoring patterns of activity from DIDs involved in anomalies
4. Setting up regular auditing schedules to detect issues early