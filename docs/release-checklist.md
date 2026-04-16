# Release Checklist

This checklist exists to keep releases honest.

`v0.1.0` established this checklist around the initial TLS inventory MVP work. Future releases should meet the same bar of coherence and verification.

## Functional baseline

Before a release, confirm that Surveyor can:
- run `surveyor diff`
- run `surveyor prioritize`
- support `surveyor prioritise` as a CLI alias
- run `surveyor audit local`
- run `surveyor audit remote`
- chain discovery into the supported TLS scanner conservatively
- produce canonical JSON and derived Markdown for audit output
- enumerate local endpoints through `surveyor discover local`
- enumerate explicitly declared remote scope through `surveyor discover remote`
- attach conservative protocol hints without treating them as verified scans
- produce canonical JSON and derived Markdown for discovery output
- validate remote scope and dry-run plans without network I/O
- load and validate explicit TLS targets from config
- perform TLS collection against explicit targets
- extract certificate metadata from presented peer certificates
- classify results using the current conservative rule set
- produce canonical JSON output
- produce Markdown derived from the same canonical report model
- compare compatible saved TLS and audit reports deterministically
- rank current TLS and audit reports with the current prioritisation profiles

## Documentation

Before a release, confirm that:
- `README.md` describes the actual shipped state, not planned behaviour that no longer matches
- `docs/audit.md` matches the implemented audit slice
- `docs/discovery.md` matches the implemented discovery slice
- `docs/remote-inventory.md` matches the implemented remote slice
- `docs/remote-scope.md` matches the implemented remote scope model
- `docs/architecture.md` matches the code
- `docs/output-schema.md` matches the current JSON contract
- `docs/baselines.md` matches the implemented baseline layer
- `docs/diffing.md` matches the implemented diff surface
- `docs/prioritisation.md` matches the implemented prioritisation surface
- `docs/classification.md` matches the implemented rule set
- `docs/references.md` exists and is still the right reference set
- `docs/safety.md` still matches the tool's actual behaviour
- `examples/targets.yaml`, `examples/report.json`, `examples/report.md`, `examples/discovery.json`, `examples/discovery.md`, `examples/discovery-remote.json`, `examples/discovery-remote.md`, `examples/discovery-subnet.json`, `examples/discovery-subnet.md`, `examples/audit.json`, `examples/audit.md`, `examples/audit-remote.json`, `examples/audit-remote.md`, `examples/audit-subnet.json`, `examples/audit-subnet.md`, `examples/diff.json`, `examples/diff.md`, `examples/priorities.json`, `examples/priorities.md` and `examples/approved-hosts.txt` reflect the current implementation

## Verification

Before a release, confirm that:
- `go build ./cmd/surveyor` passes
- `go vet ./...` passes
- `go test ./...` passes
- example outputs remain representative
- deterministic tests exist for audit, discovery, baseline compatibility, diffing, prioritisation, config validation, TLS collection, classification and outputs
- CI is green across all runners

If a release changes behaviour without updating tests or examples, it is not ready.

## Scope discipline

Before a release, confirm that the release has not silently drifted into:
- undeclared or implicit range scanning
- active probing hidden inside discovery
- non-TLS scanner execution hidden inside audit
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
