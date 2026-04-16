# Surveyor Prioritisation Report

- Generated: 2026-04-22T03:00:00Z
- Profile: migration-readiness
- Source report kind: audit
- Source generated: 2026-04-20T01:30:00Z
- Total items: 3

## Scope

- Scope kind: remote
- Input kind: targets_file
- Targets file: examples/approved-hosts.txt
- Ports: 443

## Severity summary

- low: 1
- medium: 2

## Code summary

- audit-selection-skipped: 1
- classical-certificate-identity: 1
- endpoint-warnings: 1

## Priorities

### 1. remote|example.com|443|tcp

- Code: classical-certificate-identity
- Severity: medium
- Summary: The observed certificate identity remains classical.
- Reason: Classical certificate identity is a direct migration dependency.
- Recommendation: Inventory certificate replacement and related PKI dependencies as part of migration planning.

#### Evidence

- leaf_key_algorithm=rsa

### 2. remote|10.0.0.10|443|tcp

- Code: audit-selection-skipped
- Severity: medium
- Summary: The endpoint was not scanned during audit.
- Reason: endpoint did not respond during remote discovery
- Recommendation: Confirm the endpoint, network path and whether a TLS service is still expected at this address.

#### Evidence

- connection refused

### 3. remote|example.com|443|tcp

- Code: endpoint-warnings
- Severity: low
- Summary: The endpoint emitted warnings during TLS collection.
- Reason: Warnings reduce confidence in the current result and should be reviewed.
- Recommendation: Review the warnings before treating this result as complete.

#### Evidence

- certificate metadata incomplete
