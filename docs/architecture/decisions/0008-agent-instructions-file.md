# Agent Instructions File

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor already has substantial human-facing documentation covering scope, contribution rules, security policy, release expectations and verification standards.

However, coding agents do not reliably read or follow a repository's full documentation set unless there is a predictable agent-oriented entrypoint.

That creates a practical risk that agent-assisted changes will ignore Surveyor's scope, safety, DCO and documentation rules.

## Decision

Surveyor keeps a root [`AGENTS.md`](../../../AGENTS.md) file as an agent-facing instruction entrypoint.

[`AGENTS.md`](../../../AGENTS.md):
- restates the most important operational constraints for agent-assisted work
- directs agents to the canonical project documents
- does not replace the canonical human-facing documentation set

Canonical authority remains with the repository documentation, including:
- [`README.md`](../../../README.md)
- [`CONTRIBUTING.md`](../../../CONTRIBUTING.md)
- [`SECURITY.md`](../../../SECURITY.md)
- [`DCO.md`](../../../DCO.md)
- the ADR set

## Consequences

This decision means that:
- Surveyor gains a practical entrypoint for coding agents without creating a parallel policy system
- agent-assisted changes are more likely to respect scope, DCO, security and verification expectations
- maintainers need to keep [`AGENTS.md`](../../../AGENTS.md) aligned with the canonical documents as repository policy evolves
