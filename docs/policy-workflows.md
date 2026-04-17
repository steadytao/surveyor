# Policy Refinement and Organisational Workflows

This document defines the planned `v0.8.0` contract.

It does not describe current shipped behaviour.

The current repository already carries richer organisational metadata through
structured inventory, diffing and prioritisation. The next step should be to
use that metadata more deliberately without turning Surveyor into a governance
platform.

## Goal

`v0.8.0` should make Surveyor outputs more useful for teams.

It should help answer:

- what matters first for a specific team
- what matters first in production
- what changed for a specific owner or environment
- which inventory inputs are incomplete or weak
- which items deserve operational follow-up rather than only technical note

## Why this next

This is the right next layer after:

- saved-report diffing
- current-report prioritisation
- structured imported inventory with owner, environment, tags, notes and provenance

`v0.7.0` solved how richer inventory data gets in.
`v0.8.0` should solve how teams act on that data.

## Planned scope

`v0.8.0` should add:

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

## Planned command surface

Current commands should stay.

Recommended additions:

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

The current prioritisation profiles should remain:

- `migration-readiness`
- `change-risk`

But they should become more useful by considering:

- owner
- environment
- tags
- provenance/source
- scope metadata

That should improve ranking and reason text, not replace the underlying
technical evidence.

## Grouped summaries

The next layer should add grouped summaries without changing the underlying
canonical technical models.

Examples:

- findings by owner
- findings by environment
- changes by owner
- changes by environment
- changes by source inventory file
- highest-priority items by group

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
- manual review required because source context is incomplete

These are workflow findings, not deep scanner findings.

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

The cleaner sequence after `v0.7.0` is:

- `v0.8.0` — policy refinement and organisational workflows
- `v0.9.0` — platform-specific import adapters
- `v1.0.0` — first stable narrow Surveyor contract

That keeps the generic substrate strong before vendor-specific adapters start
shaping the product.
