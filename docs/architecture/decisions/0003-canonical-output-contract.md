# Canonical Output Contract

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor already emits both JSON and Markdown across TLS inventory, discovery, audit, diffing and prioritisation.

If those outputs are treated as parallel products, the project risks drift between machine-readable and human-readable results, ambiguous schema changes and documentation that no longer matches emitted behaviour.

## Decision

Surveyor treats JSON as the canonical output contract.

Markdown is derived from the same canonical model and must not contain facts that are absent from the canonical JSON representation.

Schema changes are treated as public contract changes and must be reflected deliberately in:
- the code
- documentation
- examples
- tests

The canonical contract document is [`../../contracts/output-schema.md`](../../contracts/output-schema.md).

## Consequences

This decision means that:
- new output facts should be added to the canonical JSON model first
- Markdown renderers remain presentation layers, not independent data sources
- schema changes need deliberate review and documentation rather than casual field drift
- compatibility work such as baseline parsing, diffing and prioritisation can rely on one canonical model
