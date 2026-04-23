# Remote Scope Model

<!-- ![Proposed](https://img.shields.io/badge/status-proposed-informational?style=for-the-badge) -->
![Accepted](https://img.shields.io/badge/status-accepted-brightgreen?style=for-the-badge)
<!-- ![Superseded](https://img.shields.io/badge/status-superseded-yellow?style=for-the-badge) -->
<!-- ![Deprecated](https://img.shields.io/badge/status-deprecated-orange?style=for-the-badge) -->
<!-- ![Denied](https://img.shields.io/badge/status-denied-red?style=for-the-badge) -->

## Context

Surveyor supports remote discovery and remote audit, which means scope declaration and safety behaviour are core product concerns rather than implementation detail.

Without a clear remote-scope decision, the project could drift into implicit widening, ambiguous scope grammars or unsafe scanning behaviour.

## Decision

Surveyor uses one explicit remote-scope model for both `discover remote` and `audit remote`.

That model requires exactly one of:
- `--cidr`
- `--targets-file`
- `--inventory-file`

Additional rules:
- `--ports` is required for `--cidr` and `--targets-file`
- `--ports` overrides imported ports when `--inventory-file` is used
- profiles affect pace, not scope
- `--dry-run` performs no network I/O
- compatibility aliases such as `discover subnet` and `audit subnet` remain CIDR-only compatibility affordances, not the long-term design centre

The canonical contract document is [`../../commands/remote-scope.md`](../../commands/remote-scope.md).

## Consequences

This decision means that:
- remote scope remains explicit and reviewable
- safety controls constrain execution pace without silently changing declared scope
- new remote input forms should extend the same model rather than inventing parallel command families
- future widening of remote behaviour should be treated as a deliberate project decision
