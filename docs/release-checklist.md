# Release Checklist

This checklist exists to keep releases honest.

`v0.1.0` established this checklist around the initial TLS inventory MVP work. Future releases should meet the same bar of coherence and verification.

## Functional baseline

Before a release, confirm that Surveyor can:
- load and validate explicit TLS targets from config
- perform TLS collection against explicit targets
- extract certificate metadata from presented peer certificates
- classify results using the current conservative rule set
- produce canonical JSON output
- produce Markdown derived from the same canonical report model

## Documentation

Before a release, confirm that:
- `README.md` describes the actual shipped state, not planned behaviour that no longer matches
- `docs/architecture.md` matches the code
- `docs/output-schema.md` matches the current JSON contract
- `docs/classification.md` matches the implemented rule set
- `docs/references.md` exists and is still the right reference set
- `docs/safety.md` still matches the tool's actual behaviour
- `examples/targets.yaml`, `examples/report.json` and `examples/report.md` reflect the current implementation

## Verification

Before a release, confirm that:
- `go build ./cmd/surveyor` passes
- `go vet ./...` passes
- `go test ./...` passes
- example outputs remain representative
- deterministic tests exist for config validation, TLS collection, classification and outputs
- CI is green across all runners

If a release changes behaviour without updating tests or examples, it is not ready.

## Scope discipline

Before a release, confirm that the release has not silently drifted into:
- range scanning
- broad discovery features
- generic vulnerability scanning
- trust or compliance claims the implementation cannot support

The release should stay narrow and defensible.

## Final release preparation

Before tagging:
- review open milestone items
- confirm branch protection and required CI checks on `master`
- update release notes
- update `CHANGELOG.md`
- confirm the version to tag
- confirm the examples and docs from a clean checkout

If the README still needs to explain away missing core behaviour, the release is not ready.
