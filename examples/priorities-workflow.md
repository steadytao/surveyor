# Surveyor Prioritisation Report

- Generated: 2026-04-25T03:00:00Z
- Profile: migration-readiness
- Source report kind: audit
- Source generated: 2026-04-25T01:30:00Z
- Total items: 1

## Scope

- Scope kind: remote
- Input kind: inventory_file
- Inventory file: examples/inventory.yaml
- Ports: per-entry inventory ports

## Workflow View

- Group by: owner
- Filter tag: external

## Severity summary

- high: 1

## Code summary

- legacy-tls-version: 1

## Grouped Summaries

### By owner

#### payments

- Total items: 1
- Severity breakdown: high=1
- Code breakdown: legacy-tls-version=1

## Workflow Findings

### weak-provenance (remote|prod.example.com|443|tcp)

- Severity: low
- Summary: The imported endpoint has no recorded source provenance.
- Reason: Without provenance, later review and source reconciliation become weaker.
- Recommendation: Preserve source file and record metadata when importing inventory.

#### Evidence

- host=prod.example.com
- port=443
- inventory_file=examples/inventory.yaml

## Priorities

### 1. remote|prod.example.com|443|tcp

- Code: legacy-tls-version
- Severity: high
- Summary: Legacy TLS remains enabled.
- Reason: Legacy TLS exposure should be addressed before treating transport posture as migration-ready. In inventory context, it is in the production environment, it is owned by payments, it is tagged external.
- Recommendation: Upgrade the endpoint to a modern TLS baseline.

#### Evidence

- tls_version=TLS 1.0
