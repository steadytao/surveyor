# Diffing

This document defines the planned diffing contract for `v0.6.0`.

It builds on the baseline model in [baselines.md](baselines.md) and the current report contracts in [output-schema.md](output-schema.md).

## Goal

`surveyor diff` should compare two compatible Surveyor JSON reports and answer:

- what is new
- what disappeared
- what changed
- what appears worse
- what appears better

It should fail clearly on incompatible inputs rather than producing misleading output.

## Planned command surface

Canonical command:

```bash
surveyor diff baseline.json current.json -o diff.md -j diff.json
```

Optional profile support:

```bash
surveyor diff baseline.json current.json --profile migration-readiness -o diff.md -j diff.json
```

The first version should keep the interface narrow:

- two input files
- one canonical JSON output
- one derived Markdown output

## Supported comparisons

The first version should support:

- TLS report to TLS report
- audit report to audit report

Discovery-only diffing is optional and should not block the release.

Unsupported comparisons must fail clearly.

Examples:

- `tls_scan` vs `audit` must fail
- `discovery` vs `audit` must fail
- unsupported schema-version combinations must fail

## Summary model

The diff report should include a top-level summary with:

- total entities in baseline
- total entities in current
- entities added
- entities removed
- entities changed
- entities unchanged

That summary should be derived from stable identity matching, not from presentation-only fields.

## Change categories

At minimum, the diff engine should support:

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

The first version should prefer a smaller correct change vocabulary over an impressive but unstable one.

## Change direction

Each change should be tagged as one of:

- `worsened`
- `improved`
- `changed`
- `informational`

That direction model is what later prioritisation should consume.

It should stay conservative:

- use `worsened` or `improved` only when the direction is defensible
- otherwise fall back to `changed` or `informational`

## Diff report shape

Recommended top-level fields:

- `generated_at`
- `schema_version`
- `tool_version`
- `report_kind = diff`
- `baseline_report_kind`
- `current_report_kind`
- `baseline_generated_at`
- `current_generated_at`
- `summary`
- `changes`

Each change entry should contain:

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

## Non-goals

The first diffing release should not include:

- arbitrary cross-kind comparison
- fuzzy entity matching
- historical storage
- automatic baseline selection
- policy-engine logic

Diffing should explain change, not pretend to decide everything about it.
