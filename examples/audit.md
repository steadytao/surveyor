# Surveyor Local Audit Report

- Generated: 2026-04-16T02:30:00Z
- Total endpoints: 2
- TLS candidates: 1
- Scanned endpoints: 1
- Skipped endpoints: 1

## Selection summary

- tls: 1

## Verified classification summary

- modern_tls_classical_identity: 1

## Endpoints

### 0.0.0.0:443/tcp

- Scope kind: local
- Host: 0.0.0.0
- Port: 443
- Transport: tcp
- State: listening
- PID: 4321
- Process name: local-service
- Executable: C:\Program Files\Surveyor Test\local-service.exe

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

### 127.0.0.1:5353/udp

- Scope kind: local
- Host: 127.0.0.1
- Port: 5353
- Transport: udp
- State: bound
- PID: 9876

#### Selection

- Status: skipped
- Reason: no supported scanner for udp endpoint

#### Warnings

- process metadata unavailable
