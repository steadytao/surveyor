# Surveyor Diff Report

- Generated: 2026-04-25T03:00:00Z
- Baseline report kind: audit
- Current report kind: audit
- Total baseline entities: 1
- Total current entities: 1
- Added entities: 0
- Removed entities: 0
- Changed entities: 1
- Unchanged entities: 0
- Scope changed: false

## Comparison

- Baseline generated: 2026-04-25T01:00:00Z
- Current generated: 2026-04-25T02:00:00Z
- Baseline scope: remote audit from inventory file examples/inventory.yaml
- Current scope: remote audit from inventory file examples/inventory.yaml

## Workflow View

- Group by: owner
- Filter environment: prod

## Change Summary

- selection_changed: 1

## Direction Summary

- changed: 1

## Grouped Summaries

### By owner

#### payments

- Total items: 1
- Severity breakdown: low=1
- Direction breakdown: changed=1
- Change breakdown: selection_changed=1

## Changes

### remote|prod.example.com|443|tcp

- Code: selection_changed
- Direction: changed
- Severity: low
- Summary: The audit selection decision changed.
- Baseline value:

```json
{
  "status": "selected",
  "selected_scanner": "tls",
  "reason": "tls hint on tcp/443"
}
```
- Current value:

```json
{
  "status": "skipped",
  "reason": "endpoint did not respond during remote discovery"
}
```
