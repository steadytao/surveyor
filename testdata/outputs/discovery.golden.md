# Surveyor Discovery Report

- Generated: 2026-04-15T01:45:00Z
- Total endpoints: 2
- TCP endpoints: 1
- UDP endpoints: 1

## Scope

- Scope kind: local

## Hint summary

- tls: 1

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

### 127.0.0.1:5353/udp

- Scope kind: local
- Host: 127.0.0.1
- Port: 5353
- Transport: udp
- State: bound
- PID: 9876

#### Warnings

- process metadata unavailable
