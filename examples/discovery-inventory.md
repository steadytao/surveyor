# Surveyor Discovery Report

- Generated: 2026-04-23T01:15:00Z
- Total endpoints: 2
- TCP endpoints: 2
- UDP endpoints: 0

## Scope

- Scope kind: remote
- Input kind: inventory_file
- Inventory file: examples/inventory.yaml

## Execution

- Profile: cautious
- Max hosts: 256
- Max concurrency: 8
- Timeout per attempt: 3s

## Hint summary

- tls: 1

## Endpoints

### api.example.com:443/tcp

- Scope kind: remote
- Host: api.example.com
- Port: 443
- Transport: tcp
- State: responsive

#### Inventory

- Imported ports: 443,8443
- Name: Payments API
- Owner: payments
- Environment: prod
- Tags: critical,external
- Notes: Internet-facing service
- Provenance:
  - inventory_file | yaml | examples/inventory.yaml | entries[0]

#### Hints

- tls (low)
  - evidence: transport=tcp
  - evidence: port=443

### 10.0.0.10:8443/tcp

- Scope kind: remote
- Host: 10.0.0.10
- Port: 8443
- Transport: tcp
- State: candidate

#### Inventory

- Imported ports: 8443
- Name: Admin Console
- Owner: platform
- Environment: prod
- Tags: internal
- Provenance:
  - inventory_file | yaml | examples/inventory.yaml | entries[1]

#### Errors

- connection refused
