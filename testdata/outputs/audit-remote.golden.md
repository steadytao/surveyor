# Surveyor Audit Report

- Generated: 2026-04-20T01:30:00Z
- Total endpoints: 2
- TLS candidates: 1
- Scanned endpoints: 1
- Skipped endpoints: 1

## Scope

- Scope kind: remote
- Input kind: targets_file
- Targets file: examples/approved-hosts.txt
- Ports: 443

## Execution

- Profile: cautious
- Max hosts: 256
- Max concurrency: 8
- Timeout per attempt: 3s

## Selection summary

- tls: 1

## Verified classification summary

- modern_tls_classical_identity: 1

## Endpoints

### example.com:443/tcp

- Scope kind: remote
- Host: example.com
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

### 10.0.0.10:443/tcp

- Scope kind: remote
- Host: 10.0.0.10
- Port: 443
- Transport: tcp
- State: candidate

#### Selection

- Status: skipped
- Reason: endpoint did not respond during remote discovery

#### Errors

- connection refused
