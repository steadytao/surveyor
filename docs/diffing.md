# Diffing

This document defines the current diffing contract.

It builds on the baseline model in [baselines.md](baselines.md) and the current report contracts in [output-schema.md](output-schema.md).

## Goal

`surveyor diff` compares two compatible Surveyor JSON reports and answers:

- what is new
- what disappeared
- what changed
- what appears worse
- what appears better

It should fail clearly on incompatible inputs rather than producing misleading output.

## Command surface

Canonical command:

```bash
surveyor diff baseline.json current.json -o diff.md -j diff.json
```

Workflow view examples:

```bash
surveyor diff baseline.json current.json --group-by owner -o diff.md -j diff.json
surveyor diff baseline.json current.json --group-by environment --include-environment prod -o diff.md -j diff.json
```

The interface stays narrow:

- two input files
- one canonical JSON output
- one derived Markdown output
- restrained workflow controls for inventory-backed audit comparisons only

## Supported comparisons

The current version supports:

- TLS report to TLS report
- audit report to audit report

Discovery-only diffing is still deferred.

Unsupported comparisons must fail clearly.

Examples:

- `tls_scan` vs `audit` must fail
- `discovery` vs `audit` must fail
- unsupported schema-version combinations must fail

## Summary model

The diff report includes a top-level summary with:

- total entities in baseline
- total entities in current
- entities added
- entities removed
- entities changed
- entities unchanged

That summary should be derived from stable identity matching, not from presentation-only fields.

For inventory-backed audit comparisons, the current diff layer can also derive grouped summaries over the same technical change set:

- changes by owner
- changes by environment
- changes by source

Those grouped summaries do not replace the main technical summary. They layer on top of it.

## Change categories

Current change categories:

- `new_endpoint`
- `removed_endpoint`
- `reachability_changed`
- `hint_changed`
- `selection_changed`
- `tls_version_changed`
- `cipher_suite_changed`
- `classification_changed`
- `certificate_chain_changed`
- `leaf_key_algorithm_changed`
- `leaf_signature_algorithm_changed`
- `findings_changed`
- `warnings_changed`
- `errors_changed`

The current version prefers a smaller correct change vocabulary over an impressive but unstable one.

## Change direction

Each change is tagged as one of:

- `worsened`
- `improved`
- `changed`
- `informational`

That direction model is what prioritisation consumes.

It stays conservative:

- use `worsened` or `improved` only when the direction is defensible
- otherwise fall back to `changed` or `informational`

## Diff report shape

Current top-level fields:

- `generated_at`
- `schema_version`
- `tool_version`
- `report_kind = diff`
- `baseline_report_kind`
- `current_report_kind`
- `baseline_generated_at`
- `current_generated_at`
- `baseline_scope_description`
- `current_scope_description`
- `baseline_scope`
- `current_scope`
- `workflow_view`
- `summary`
- `grouped_summaries`
- `workflow_findings`
- `changes`

Current population rules:

- `workflow_view` is present when workflow grouping or filtering was requested
- `grouped_summaries` are currently emitted for inventory-backed audit comparisons when usable metadata exists
- `workflow_findings` is part of the canonical diff report shape but is not currently emitted by the diff engine

Each change entry contains:

- stable identity key
- change code
- change direction
- severity
- summary
- baseline value
- current value
- evidence
- recommendation when useful

## Compatibility failures

Compatibility failures should be explicit and actionable.

They should name why comparison is rejected, for example:

- unsupported report-kind comparison
- incompatible schema version
- unsupported identity model

Do not degrade silently into partial or fuzzy comparison.

## Workflow controls

Current workflow controls:

- `--group-by owner|environment|source`
- repeated `--include-owner`
- repeated `--include-environment`
- repeated `--include-tag`

Important boundary:

- workflow controls apply only to inventory-backed audit comparisons
- TLS comparisons reject workflow controls clearly
- grouped summaries remain derived from the existing technical changes
- diffing still does not become a policy engine

## Non-goals

The current diff layer still does not include:

- arbitrary cross-kind comparison
- fuzzy entity matching
- historical storage
- automatic baseline selection
- policy-engine logic

Diffing should explain change, not pretend to decide everything about it.

See [policy-workflows.md](policy-workflows.md) for the current workflow contract.
