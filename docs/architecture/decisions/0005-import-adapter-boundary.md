# Import Adapter Boundary

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor already had a generic imported-inventory path through `--inventory-file`.

Platform-aware parsing for systems such as Caddy and Kubernetes adds real operator value, but it also creates a risk that vendor-specific formats become the internal model or that the project grows a second import-specific command family.

## Decision

Surveyor keeps one canonical imported-inventory model.

Platform adapters:
- extend the existing `--inventory-file` path
- map external product formats into Surveyor's canonical imported-inventory model
- preserve provenance and warnings
- feed the existing `discover remote` and `audit remote` workflows

Adapters are not:
- a second remote-scope model
- a second output contract
- live connectors
- proof that imported targets are reachable or externally exposed

The canonical documents are [`../../adapters/README.md`](../../adapters/README.md), [`../../adapters/contract.md`](../../adapters/contract.md) and [`../../contracts/inventory-inputs.md`](../../contracts/inventory-inputs.md).

## Consequences

This decision means that:
- Surveyor's downstream logic remains grounded in one canonical inventory model
- new adapters should conform to the canonical model rather than teach the rest of the system product-specific semantics
- live connectors or a parallel import command family would require a deliberate new decision
- vendor-specific convenience must not weaken provenance or warning rules
