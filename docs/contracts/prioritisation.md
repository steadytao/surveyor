<div align="center">
  <img src="../.github/banner.svg" alt="BANNER" width="720">
</div>

# Prioritisation

This document defines the current prioritisation contract.

It builds on the current canonical report outputs. It does not require diff input in the first release.

British English is used in prose in this document. Code-facing identifiers should use American English, and the CLI should support both spellings for the command.

## Goal

`surveyor prioritize` ranks what deserves human attention first.

The first version focuses on practical migration work, not on becoming a policy engine.

It should help answer:

- what matters first
- what should be investigated immediately
- what looks like a migration blocker
- what appears to have improved

## Command Surface

Canonical command:

```bash
surveyor prioritize current.json -o priorities.md -j priorities.json
```

Profile support:

```bash
surveyor prioritize current.json --profile migration-readiness -o priorities.md -j priorities.json
surveyor prioritize current.json --profile change-risk -o priorities.md -j priorities.json
```

CLI alias support:

```bash
surveyor prioritise current.json -o priorities.md -j priorities.json
surveyor prioritise current.json --profile migration-readiness -o priorities.md -j priorities.json
surveyor prioritise current.json --profile change-risk -o priorities.md -j priorities.json
```

Workflow view examples:

```bash
surveyor prioritize current.json --group-by owner -o priorities.md -j priorities.json
surveyor prioritize current.json --group-by environment --include-environment prod -o priorities.md -j priorities.json
```

The current version supports current TLS and audit reports.

Diff-report input remains deferred. The current contract does not require it.

## Prioritisation Profiles

The first version ships with two lightweight profiles.

### `migration-readiness`

Bias towards:

- classical dependencies
- migration blockers
- classification regressions
- newly discovered exposed endpoints

### `change-risk`

Bias towards:

- new endpoints
- removed endpoints
- changed TLS versions
- changed certificates
- new warnings and errors

These profiles should shape ranking, not redefine the underlying report facts.

For inventory-backed audit reports, the current engine also uses imported metadata conservatively:

- production environment raises priority
- `external` and `critical` tags raise priority
- reasons can cite owner, environment and tags when present

## Current Ranking Sources

The first version ranks current-report items derived from:

- findings
- warnings
- errors
- skipped audit selections

It does not compare baseline and current state inside the prioritisation engine. That comparison boundary belongs to `surveyor diff`.

## Prioritisation Item Shape

Each prioritised item contains:

- rank
- severity
- code
- summary
- target identity
- reason
- evidence
- recommendation

Ranking should be deterministic. Equal-priority items should not be reordered arbitrarily across runs.

## Scope of Interpretation

Prioritisation operates over current report data conservatively.

Current behaviour:

- rank meaningful findings
- rank degraded posture
- surface skipped or incomplete audit coverage
- surface manual review items
- emit workflow findings for weak imported inventory metadata on audit input
- emit grouped summaries when `--group-by` is requested on inventory-backed audit input

It should not:

- claim compliance
- replace human review
- act as an automatic remediation engine
- become a large rules engine in the first release

## Non-Goals

The first prioritisation release does not include:

- policy-as-code
- remediation workflows
- central approval systems
- organisation-wide aggregation
- arbitrary external data sources
- diff-input prioritisation

This milestone is about making Surveyor outputs more operationally useful, not about building a governance platform.

## Workflow Controls and Findings

Current workflow controls:

- `--group-by owner|environment|source`
- repeated `--include-owner`
- repeated `--include-environment`
- repeated `--include-tag`

Current workflow finding codes for inventory-backed audit input:

- `missing-owner`
- `missing-environment`
- `weak-provenance`
- `inventory-ports-overridden`

Important boundary:

- workflow controls apply only to inventory-backed audit input
- TLS input rejects workflow controls clearly
- prioritisation remains a lightweight decision-support layer
- it still does not become policy-as-code or require a dashboard or database

See [policy-workflows.md](policy-workflows.md) for the current workflow contract.
