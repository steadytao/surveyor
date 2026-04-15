# Surveyor Discovery Report

- Generated: 2026-04-18T01:15:00Z
- Total endpoints: 3
- TCP endpoints: 3
- UDP endpoints: 0

## Hint summary

- tls: 2

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

### 10.0.0.11:443/tcp

- Scope kind: remote
- Host: 10.0.0.11
- Port: 443
- Transport: tcp
- State: candidate

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
