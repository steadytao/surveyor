# Non-TLS Protocol Boundary

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor v1.0.0 shipped as a TLS-first cryptographic inventory and migration-readiness tool.

The project can plausibly expand into adjacent protocol observations such as SSH host keys, SSH key-exchange algorithms, RDP TLS surfaces or other transport-facing cryptographic signals.

Those observations may be useful, but adding them casually would risk turning Surveyor into a broad multi-protocol scanner. That would weaken the project's scope, increase its safety and verification burden and make its output contracts harder to defend.

Surveyor already has accepted decisions for project scope, remote scope, scanner boundaries and analysis boundaries. Non-TLS protocol expansion needs the same deliberate treatment rather than incremental drift.

## Decision

Surveyor remains TLS-first after v1.0.0.

TLS remains the only deep verified scanner in the current product line.

Surveyor will not add broad non-TLS scanning as an incremental feature.

Non-TLS protocol support may only be added when all of the following are true:
- the protocol observation is cryptographic-inventory work, not vulnerability scanning
- the scope model remains explicit and conservative
- the output model can represent the evidence without weakening existing TLS contracts
- the implementation has a clear scanner boundary equivalent to the TLS scanner boundary
- the feature has tests, fixtures and documentation before release
- the addition is accepted through a dedicated ADR or an update to this one

SSH is recognised as a plausible future candidate because host keys and key-exchange algorithms are relevant to cryptographic inventory. It is not accepted as part of the v1.0.0 product surface by this decision.

The canonical documents are [`0001-project-scope.md`](0001-project-scope.md), [`0004-remote-scope-model.md`](0004-remote-scope-model.md), [`0006-audit-and-scanner-boundary.md`](0006-audit-and-scanner-boundary.md), [`../../commands/discovery.md`](../../commands/discovery.md), [`../../commands/audit.md`](../../commands/audit.md) and [`../../contracts/output-schema.md`](../../contracts/output-schema.md).

## Consequences

This decision means that:
- Surveyor stays TLS-first after v1.0.0
- SSH and similar protocol work cannot enter as casual scope creep
- future protocol additions must be deliberate, documented and separately testable
- protocol hints remain distinct from verified scanner results
- output-schema changes for future protocol observations require explicit compatibility review
- adjacent projects, including Waymark, can proceed without forcing Surveyor to become a general network platform
