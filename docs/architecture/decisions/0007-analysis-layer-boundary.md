# Analysis Layer Boundary

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor already supports saved-report diffing, current-report prioritisation and workflow-oriented grouping over inventory-backed audit inputs.

Those capabilities are useful, but they risk turning Surveyor into a policy engine, governance platform or second data model if their boundary is not explicit.

## Decision

Surveyor keeps its current analysis layer narrow.

Current analysis work:
- operates on canonical JSON reports
- supports diffing for compatible `tls_scan` and `audit` reports
- supports prioritisation for current `tls_scan` and `audit` reports
- supports workflow grouping and filtering only for inventory-backed audit analysis where the metadata exists

The analysis layer is interpretation and organisation over existing evidence. It is not:
- a policy engine
- a database
- a dashboard
- a second technical report model

The canonical documents are [`../../contracts/diffing.md`](../../contracts/diffing.md), [`../../contracts/prioritisation.md`](../../contracts/prioritisation.md), [`../../contracts/policy-workflows.md`](../../contracts/policy-workflows.md) and [`../../contracts/baselines.md`](../../contracts/baselines.md).

## Consequences

This decision means that:
- diffing and prioritisation stay grounded in the canonical report model
- workflow controls remain a restrained organisational layer, not an embedded policy DSL
- future analysis expansion should be judged against this boundary rather than added incrementally without review
- unsupported report kinds or broader governance features require deliberate new decisions
