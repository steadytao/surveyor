<div align="center">
  <img src="../.github/banner.svg" alt="BANNER" width="720">
</div>

# Policy Refinement and Organisational Workflows

This document defines the current `v0.8.0` workflow contract.

The current repository already carries richer organisational metadata through
structured inventory, diffing and prioritisation, and now uses that metadata
more deliberately without turning Surveyor into a governance platform.

## Goal

`v0.8.0` makes Surveyor outputs more useful for teams.

It should help answer:

- what matters first for a specific team
- what matters first in production
- what changed for a specific owner or environment
- which inventory inputs are incomplete or weak
- which items deserve operational follow-up rather than only technical note

## Why this layer

This workflow layer sits above:

- saved-report diffing
- current-report prioritisation
- structured imported inventory with owner, environment, tags, notes and provenance

`v0.7.0` solved how richer inventory data gets in.
`v0.8.0` solves how teams act on that data.

## Current behaviour

`v0.8.0` adds:

- metadata-aware prioritisation profiles
- grouped summaries for diff and prioritisation output
- workflow findings for inventory metadata quality
- restrained grouping and filtering controls on the CLI
- clearer ranking reasons and recommendations that cite organisational context

Examples of useful behaviour:

- rank `prod` above `dev` where the profile calls for it
- highlight newly exposed prod endpoints above unchanged dev issues
- surface imported assets with missing owner or environment
- summarise changes by owner, environment or source inventory

## Current command surface

Current commands should stay.

Current workflow controls:

```bash
surveyor prioritize current.json --group-by owner
surveyor prioritize current.json --group-by environment --include-environment prod
surveyor diff baseline.json current.json --group-by owner
surveyor diff baseline.json current.json --group-by environment --include-environment prod
```

The CLI should stay narrow:

- no query language
- no embedded policy DSL
- no arbitrary expression syntax

## Metadata-aware prioritisation

The current prioritisation profiles remain:

- `migration-readiness`
- `change-risk`

They now become more useful by considering:

- owner
- environment
- tags
- provenance and source context where relevant

This improves ranking and reason text, not the underlying
technical evidence.

## Grouped summaries

Grouped summaries now sit above the underlying canonical technical models.

Examples:

- prioritised items by owner
- prioritised items by environment
- changes by owner
- changes by environment
- changes by source inventory file

The grouped view should be derived from the same canonical JSON, not from a
second reporting path.

## Workflow findings

Structured imported inventory makes metadata-quality problems operationally
useful to report.

Examples:

- missing owner
- missing environment
- conflicting imported metadata
- weak or unclear provenance
- inventory ports overridden by run-level ports

These are workflow findings, not deep scanner findings.

Current population boundary:

- workflow findings are currently emitted by prioritisation for inventory-backed audit input
- diff reports carry the optional field in the canonical shape, but the current diff engine does not yet emit diff-side workflow findings

## Important boundaries

This milestone should not become:

- policy-as-code
- a dashboard
- a database
- a live connector layer
- a platform-specific adapter milestone
- another deep scanner milestone

Surveyor should keep:

- one canonical JSON output
- one derived Markdown output

The improvement should be in how those outputs organise and interpret the data
already present.

## Relationship to later work

The cleaner sequence after `v0.8.0` is:

- `v0.9.0` — platform-specific import adapters
- `v1.0.0` — first stable narrow Surveyor contract

That keeps the generic substrate strong before vendor-specific adapters start
shaping the product.
