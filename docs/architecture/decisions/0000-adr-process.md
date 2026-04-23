# ADR Process

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor already depends on deliberate decisions about scope, output semantics, remote behaviour, adapter boundaries, release integrity and safety posture.

Those decisions currently exist across code, release notes and documentation, but without a compact decision record they are easier to erode or reinterpret over time.

The project needs a clear and lightweight way to record material technical decisions and their consequences.

## Decision

Surveyor uses Architecture Decision Records, or ADRs, to record material technical and project-boundary decisions.

ADRs are stored under [`docs/architecture/decisions/`](README.md).

They are numbered in ascending order, starting at `0000`.

Each ADR should be concise, specific and written so a future maintainer can understand:
- the problem or context
- the decision that was made
- the main consequences of that decision

## When an ADR Is Required

An ADR is required for decisions that materially affect:
- project scope or boundary
- safety model or trust assumptions
- public interfaces or output semantics
- major dependency choices with architectural impact
- release, signing, provenance or verification model
- deployment or connector model
- core policy semantics

## When an ADR Is Not Required

An ADR is not required for:
- routine refactors
- small implementation details
- documentation-only edits that do not record a new project direction
- naming changes without architectural effect
- short-lived experiments that are not adopted
- ordinary bug fixes that do not change project direction or assumptions

## ADR Structure

Each ADR should contain:
- title
- status
- context
- decision
- consequences

Optional sections may be added when helpful but ADRs should remain compact.

## ADR Status Badges

Surveyor ADRs should express status with a single badge rather than a plain text status line.

The following badge forms are the standard set:

```md
<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
<!-- ![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge) -->
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->
```

Only one status badge should be active in an ADR at a time.

## ADR Status Meanings

Surveyor ADRs should use one of the following statuses:

- `proposed`
  - A decision is being considered, but is not yet in force.
- `accepted`
  - The decision has been made and is the current project direction.
- `superseded`
  - The decision was previously accepted, but has been replaced by a later ADR that now governs.
- `deprecated`
  - The decision is no longer preferred and should be phased out, but has not yet been fully replaced or removed.
- `denied`
  - A materially considered proposal was explicitly rejected and should not be treated as an undecided open question.

## ADR Lifecycle

An accepted ADR remains in force until it is replaced or superseded by another ADR.

ADRs should not be rewritten to hide historical decisions. If a decision changes, a new ADR should be created and the older ADR should be marked accordingly.

## Consequences

This process creates a stable record of important Surveyor decisions and reduces the risk of undocumented architectural drift as the tool evolves.
