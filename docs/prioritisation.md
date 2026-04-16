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

## Command surface

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

The first version supports current TLS and audit reports.

Diff-report input can come later if it stays clean, but it should not be required to ship `v0.6.0`.

## Prioritisation profiles

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

## Current ranking sources

The first version ranks current-report items derived from:

- findings
- warnings
- errors
- skipped audit selections

It does not compare baseline and current state inside the prioritisation engine. That comparison boundary belongs to `surveyor diff`.

## Prioritisation item shape

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

## Scope of interpretation

Prioritisation operates over current report data conservatively.

Current behaviour:

- rank meaningful findings
- rank degraded posture
- surface skipped or incomplete audit coverage
- surface manual review items

It should not:

- claim compliance
- replace human review
- act as an automatic remediation engine
- become a large rules engine in the first release

## Non-goals

The first prioritisation release does not include:

- policy-as-code
- remediation workflows
- central approval systems
- organisation-wide aggregation
- arbitrary external data sources
- diff-input prioritisation

This milestone is about making Surveyor outputs more operationally useful, not about building a governance platform.
