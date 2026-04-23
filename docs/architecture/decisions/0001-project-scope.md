# Project Scope

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor is already presented as a TLS-first cryptographic inventory and migration-readiness tool.

Without a clear scope decision, the project could drift into adjacent categories such as generic vulnerability scanning, live connector platforms, dashboard systems, policy engines or broad network-scanning tooling.

That would weaken the product's clarity, raise the verification burden and make its claims less defensible.

## Decision

Surveyor is defined as a TLS-first cryptographic inventory and migration-readiness tool.

Its intended scope is:
- explicit TLS inventory
- local discovery and local audit
- remote discovery and remote audit within explicitly declared scope
- structured imported inventory for declared remote scope
- conservative classification
- diffing and prioritisation over supported report kinds

Surveyor is not defined as:
- a generic vulnerability scanner
- a dashboard or storage platform
- a live connector platform
- a policy engine
- a broad multi-protocol scanner
- an internet-wide discovery tool

The canonical human-facing scope documents are [`README.md`](../../../README.md), [`../README.md`](../README.md) and [`../../reference/safety.md`](../../reference/safety.md).

## Consequences

This decision means that:
- feature proposals that widen Surveyor into unrelated product categories may be declined
- implementation should prioritise defensible inventory and migration-readiness outputs over breadth
- safety claims should remain tied to explicit scope and conservative behaviour
- future expansion beyond the current product boundary should require a deliberate new decision rather than gradual drift
