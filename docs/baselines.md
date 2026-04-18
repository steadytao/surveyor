<div align="center">
  <img src="../.github/banner.svg" alt="BANNER" width="720">
</div>

# Baselines

This document defines the current baseline model.

It sits beside the current inventory and audit boundary described in:

- [remote-inventory.md](remote-inventory.md)
- [remote-scope.md](remote-scope.md)
- [audit.md](audit.md)
- [discovery.md](discovery.md)

## Why baselines now

Surveyor can already produce canonical JSON reports for:

- explicit TLS inventory
- local discovery
- local audit
- remote discovery
- remote audit

The useful step after collection was to turn those reports into stable baseline artefacts that later commands can compare and interpret over time.

## Baseline model

Any compatible canonical Surveyor JSON report should be able to act as a baseline.

That means:

- no baseline database
- no baseline registration flow
- no background storage service
- no conversion step before comparison

A baseline is just a saved canonical Surveyor JSON report plus enough metadata to determine whether comparison is valid.

## Required report metadata

Current reports already include:

- `generated_at`
- `results`
- `summary`

The baseline-compatible contract now includes:

- `schema_version`
- `tool_version`
- `report_kind`
- `scope_kind`
- `scope_description`
- structured `scope` metadata when relevant

That metadata is now present before diffing is attempted.

## Report kinds

Report identity should be semantic, not command-shaped.

Current values:

- `report_kind = tls_scan | discovery | audit | diff | prioritization`

Do not use:

- `audit_subnet`
- `discover_remote`
- other command-level names

Those values would leak CLI naming and compatibility aliases into a longer-lived comparison model.

Use American English for code-facing identifiers such as:

- package names
- function names
- enum values
- `report_kind`

The CLI may still support both British and American spelling where that improves usability.

## Scope metadata

Scope metadata should stay distinct from report kind.

Current values:

- `scope_kind = explicit | local | remote`
- `input_kind = config | targets | cidr | targets_file`

That keeps comparison semantics honest:

- report kind describes what type of report it is
- scope kind describes where it came from
- input kind describes how the scope or target set was declared

## Stable identity keys

Diffing only works if Surveyor can answer whether two entries represent the same entity.

Current identity keys:

### TLS reports

- `host`
- `port`

Optional display fields such as `name` should not be identity.

### Audit and discovery reports

- `scope_kind`
- `host`
- `port`
- `transport`

Important current constraint:

- use `host`, not `address`

The codebase already generalised discovery and audit to `host`. The baseline model should follow the current contract rather than revive the older field name.

## Compatibility rules

Baseline compatibility should fail clearly on unsupported comparisons.

Current checks:

- same `report_kind`
- same supported `schema_version` major
- same supported identity model
- no unsupported cross-kind comparison

Examples:

- `tls_scan` vs `tls_scan` works
- `audit` vs `audit` works when the identity model is supported
- `tls_scan` vs `audit` fails clearly
- `discovery` vs `audit` fails clearly

Current deliberate limit:

- `audit` local vs `audit` remote is rejected as incompatible in the first release

That failure is intentional. It is better to reject a weak comparison than to emit a fuzzy diff.

## Scope differences

Two otherwise compatible reports may still describe different declared scope.

That should not be silently ignored.

Scope differences should be surfaced in:

- compatibility checks where they invalidate comparison
- diff metadata where comparison is still supported
- human-readable summaries

## Non-goals

The baseline layer should not include:

- a central store
- cross-repo history
- retention policy management
- automatic baseline promotion
- organisation-wide aggregation

This milestone is about making saved Surveyor reports comparable, not turning Surveyor into a fleet service.
