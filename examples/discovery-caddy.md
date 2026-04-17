# Surveyor Discovery Report

- Generated: 2026-04-26T01:15:00Z
- Total endpoints: 1
- TCP endpoints: 1
- UDP endpoints: 0

## Scope

- Scope kind: remote
- Input kind: inventory_file
- Inventory file: examples/caddy.json
- Adapter: caddy
- Ports: per-entry inventory ports

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

- Imported ports: 443,444
- Provenance:
  - kind=inventory_file, format=json, source=examples/caddy.json, record=apps.http.servers.edge.routes[0], adapter=caddy, object=server edge @id site-api
- Adapter warnings:
  - non-tcp-listener-ignored: Caddy listener does not use TCP and cannot be mapped into Surveyor remote scope.
    - evidence: adapter=caddy
    - evidence: source_name=examples/caddy.json
    - evidence: source_object=server edge
    - evidence: listener=udp/:443
  - non-concrete-host-ignored: Caddy route contains a wildcard or placeholder host that Surveyor cannot map to a concrete remote target.
    - evidence: adapter=caddy
    - evidence: source_name=examples/caddy.json
    - evidence: source_object=server edge @id wildcard-route
    - evidence: host=*.example.com

#### Hints

- tls (low)
  - evidence: transport=tcp
  - evidence: port=443
