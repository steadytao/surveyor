# Prioritisation

This document defines the planned prioritisation contract for `v0.6.0`.

It builds on the current canonical report outputs and the planned diffing layer.

British English is used in prose in this document. Code-facing identifiers should use American English, and the CLI should support both spellings for the command.

## Goal

`surveyor prioritize` should rank what deserves human attention first.

The first version should focus on practical migration work, not on becoming a policy engine.

It should help answer:

- what matters first
- what should be investigated immediately
- what looks like a migration blocker
- what appears to have improved

## Planned command surface

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

The first version should support current TLS and audit reports.

Diff-report input can come later if it stays clean, but it should not be required to ship `v0.6.0`.

## Prioritisation profiles

The first version should ship with two lightweight profiles.

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

## Prioritisation buckets

The first version should rank items across four buckets:

1. exposure and inventory changes
2. posture regressions
3. migration blockers
4. improvements

Improvements should still be reported, but they should sort below active regressions and blockers.

## Prioritisation item shape

Each prioritised item should contain:

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

Prioritisation should operate over current report data conservatively.

It should:

- rank meaningful findings
- rank degraded posture
- rank new exposure
- surface manual review items

It should not:

- claim compliance
- replace human review
- act as an automatic remediation engine
- become a large rules engine in the first release

## Non-goals

The first prioritisation release should not include:

- policy-as-code
- remediation workflows
- central approval systems
- organisation-wide aggregation
- arbitrary external data sources

This milestone is about making Surveyor outputs more operationally useful, not about building a governance platform.
