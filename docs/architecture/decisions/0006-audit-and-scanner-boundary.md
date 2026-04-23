# Audit and Scanner Boundary

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor already has distinct layers for discovery, TLS collection and report rendering.

Without a clear audit boundary, the project could collapse discovery facts, protocol hints, scanner selection and verified scan results into one opaque flow. That would make outputs harder to defend and future scanner work harder to reason about.

## Decision

Surveyor treats audit as a discovery-led orchestration layer, not as a second scanner implementation.

Audit:
- runs discovery first
- preserves discovered endpoint facts and protocol hints
- makes explicit scanner-selection decisions
- hands only the supported subset into the existing TLS scanner
- records verified TLS results separately from discovery and selection
- records skipped endpoints and reasons explicitly

TLS remains the only deep verified scanner in the current line.

The canonical documents are [`../../commands/audit.md`](../../commands/audit.md), [`../../commands/discovery.md`](../../commands/discovery.md) and [`../README.md`](../README.md).

## Consequences

This decision means that:
- hints are not treated as verified scans
- scanner selection is not treated as verification
- future scanner additions should fit the same orchestrated boundary rather than blur layers together
- audit reports remain easier to interpret, test and defend
