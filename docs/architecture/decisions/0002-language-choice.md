# Language Choice

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor is already implemented as a small systems-oriented CLI with network-facing collection, deterministic reporting and straightforward release expectations.

The project needs:
- a language suited to network and systems tooling
- simple static binaries and portable releases
- a mature testing and tooling story
- long-term maintainability for a small maintainer-led project

## Decision

The Surveyor core is implemented in Go.

## Consequences

This decision means that:
- the core implementation follows Go tooling and project conventions
- repository structure, testing and release workflows should continue to align with Go
- future language-specific documentation should treat Go as the primary implementation language
- major non-Go runtime dependencies should be justified deliberately rather than introduced casually
