# Surveyor TLS Inventory Report

- Generated: 2026-04-14T01:45:00Z
- Total targets: 1
- Reachable targets: 1
- Unreachable targets: 0

## Classification summary

- `modern_tls_classical_identity`: 1

## Targets

### primary-site

- Host: `example.com`
- Port: `443`
- Scanned at: `2026-04-14T01:00:00Z`
- Reachable: `true`
- Classification: `modern_tls_classical_identity`
- Address: `203.0.113.10:443`
- TLS version: `TLS 1.3`
- Cipher suite: `TLS_AES_128_GCM_SHA256`
- Leaf key algorithm: `rsa`
- Leaf key size: `2048`
- Leaf signature algorithm: `sha256-rsa`

#### Findings

- `classical-certificate-identity` (medium): The observed certificate identity remains classical.
  - evidence: `leaf_key_algorithm=rsa`
  - evidence: `leaf_signature_algorithm=sha256-rsa`
  - recommendation: Inventory certificate replacement and related PKI dependencies as part of migration planning.
