# Release Checklist

This checklist exists to keep `v0.1.0` honest.

The first release should represent a coherent TLS inventory MVP, not just a pile of merged slices.

## Functional baseline

Before `v0.1.0`, confirm that Surveyor can:
- load and validate explicit TLS targets from config
- perform TLS collection against explicit targets
- extract certificate metadata from presented peer certificates
- classify results using the current conservative rule set
- produce canonical JSON output
- produce Markdown derived from the same canonical report model

## Documentation

Before `v0.1.0`, confirm that:
- `README.md` describes the actual shipped state, not planned behaviour that no longer matches
- `docs/architecture.md` matches the code
- `docs/output-schema.md` matches the current JSON contract
- `docs/classification.md` matches the implemented rule set
- `docs/references.md` exists and is still the right reference set
- `docs/safety.md` still matches the tool's actual behaviour
- `examples/targets.yaml`, `examples/report.json` and `examples/report.md` reflect the current implementation

## Verification

Before `v0.1.0`, confirm that:
- `go test ./...` passes
- example outputs remain representative
- deterministic tests exist for config validation, TLS collection, classification and outputs

If a release changes behaviour without updating tests or examples, it is not ready.

## Scope discipline

Before `v0.1.0`, confirm that the release has not silently drifted into:
- range scanning
- broad discovery features
- generic vulnerability scanning
- trust or compliance claims the implementation cannot support

The release should stay narrow and defensible.

## Final release preparation

Before tagging:
- review open milestone items
- update release notes
- confirm the version to tag
- confirm the examples and docs from a clean checkout

If the README still needs to explain away missing core behaviour, the release is not ready.
