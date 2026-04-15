# Surveyor Audit Report

- Generated: 2026-04-18T01:30:00Z
- Total endpoints: 3
- TLS candidates: 2
- Scanned endpoints: 2
- Skipped endpoints: 1

## Selection summary

- tls: 2

## Verified classification summary

- modern_tls_classical_identity: 2

## Endpoints

### 10.0.0.10:443/tcp

- Scope kind: remote
- Host: 10.0.0.10
- Port: 443
- Transport: tcp
- State: responsive

#### Hints

- tls (low)
  - evidence: transport=tcp
  - evidence: port=443

#### Selection

- Status: selected
- Selected scanner: tls
- Reason: tls hint on tcp/443

#### Verified TLS Result

- Classification: modern_tls_classical_identity
- Reachable: true
- TLS version: TLS 1.3
- Cipher suite: TLS_AES_128_GCM_SHA256
- Leaf key algorithm: rsa
- Leaf key size: 2048
- Leaf signature algorithm: sha256-rsa

### 10.0.0.11:443/tcp

- Scope kind: remote
- Host: 10.0.0.11
- Port: 443
- Transport: tcp
- State: candidate

#### Selection

- Status: skipped
- Reason: endpoint did not respond during remote discovery

#### Errors

- connection refused

### 10.0.0.12:8443/tcp

- Scope kind: remote
- Host: 10.0.0.12
- Port: 8443
- Transport: tcp
- State: responsive

#### Hints

- tls (low)
  - evidence: transport=tcp
  - evidence: port=8443

#### Selection

- Status: selected
- Selected scanner: tls
- Reason: tls hint on tcp/8443

#### Verified TLS Result

- Classification: modern_tls_classical_identity
- Reachable: true
- TLS version: TLS 1.3
- Cipher suite: TLS_AES_128_GCM_SHA256
- Leaf key algorithm: rsa
- Leaf key size: 2048
- Leaf signature algorithm: sha256-rsa
