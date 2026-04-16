# Surveyor Discovery Report

- Generated: 2026-04-20T01:15:00Z
- Total endpoints: 2
- TCP endpoints: 2
- UDP endpoints: 0

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

## Hint summary

- tls: 1

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

### 10.0.0.10:443/tcp

- Scope kind: remote
- Host: 10.0.0.10
- Port: 443
- Transport: tcp
- State: candidate

#### Errors

- connection refused
