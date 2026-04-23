<div align="center">
  <img src="../../.github/banner.svg" alt="BANNER" width="720">
</div>

# Release Checklist

This checklist exists to keep releases honest.

`v0.1.0` established this checklist around the initial TLS inventory MVP work. Future releases should meet the same bar of coherence and verification.

## Functional Baseline

Before a release, confirm that Surveyor can:
- run `surveyor diff`
- run `surveyor prioritize`
- support `surveyor prioritise` as a CLI alias
- run `surveyor audit local`
- run `surveyor audit remote`
- run inventory-backed `surveyor audit remote --inventory-file ...`
- chain discovery into the supported TLS scanner conservatively
- produce canonical JSON and derived Markdown for audit output
- enumerate local endpoints through `surveyor discover local`
- enumerate explicitly declared remote scope through `surveyor discover remote`
- enumerate structured inventory-backed remote scope through `surveyor discover remote --inventory-file ...`
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
- apply workflow grouping and filtering to inventory-backed audit diff and prioritisation views

## Documentation

Before a release, confirm that:
- `README.md` describes the actual shipped state, not planned behaviour that no longer matches
- `docs/README.md` gives a coherent map of the current docs surface
- `CONTRIBUTORS` matches the reachable non-bot commit history for the release commit
- `docs/commands/audit.md` matches the implemented audit slice
- `docs/commands/discovery.md` matches the implemented discovery slice
- `docs/commands/remote-inventory.md` matches the implemented remote slice
- `docs/commands/remote-scope.md` matches the implemented remote scope model
- `docs/contracts/inventory-inputs.md` matches the implemented structured inventory input layer
- `docs/adapters/README.md` matches the implemented adapter surface
- `docs/adapters/contract.md` matches the implemented adapter contract
- `docs/adapters/caddy.md` matches the implemented Caddy adapter
- `docs/adapters/kubernetes.md` matches the implemented Kubernetes adapter
- `docs/architecture/README.md` matches the code
- `docs/contracts/output-schema.md` matches the current JSON contract
- `docs/contracts/baselines.md` matches the implemented baseline layer
- `docs/contracts/diffing.md` matches the implemented diff surface
- `docs/contracts/prioritisation.md` matches the implemented prioritisation surface
- `docs/contracts/policy-workflows.md` matches the implemented workflow surface
- `docs/contracts/classification.md` matches the implemented rule set
- `docs/reference/references.md` exists and is still the right reference set
- `docs/reference/safety.md` still matches the tool's actual behaviour
- `examples/targets.yaml`, `examples/report.json`, `examples/report.md`, `examples/discovery.json`, `examples/discovery.md`, `examples/discovery-remote.json`, `examples/discovery-remote.md`, `examples/discovery-inventory.json`, `examples/discovery-inventory.md`, `examples/discovery-subnet.json`, `examples/discovery-subnet.md`, `examples/discovery-caddy.json`, `examples/discovery-caddy.md`, `examples/audit.json`, `examples/audit.md`, `examples/audit-remote.json`, `examples/audit-remote.md`, `examples/audit-inventory.json`, `examples/audit-inventory.md`, `examples/audit-kubernetes.json`, `examples/audit-kubernetes.md`, `examples/audit-subnet.json`, `examples/audit-subnet.md`, `examples/diff.json`, `examples/diff.md`, `examples/diff-workflow.json`, `examples/diff-workflow.md`, `examples/priorities.json`, `examples/priorities.md`, `examples/priorities-workflow.json`, `examples/priorities-workflow.md`, `examples/approved-hosts.txt`, `examples/inventory.yaml`, `examples/caddy.json` and `examples/ingress.yaml` reflect the current implementation

## Verification

Before a release, confirm that:
- `go build ./cmd/surveyor` passes
- `go vet ./...` passes
- `staticcheck ./...` passes
- `gosec ./...` passes
- `govulncheck ./...` passes
- `go test ./...` passes
- bounded fuzz targets pass under `go test -run=^$ -tags debugassert -fuzz=...`
- example outputs remain representative
- deterministic tests exist for audit, discovery, baseline compatibility, diffing, prioritisation, config validation, TLS collection, classification and outputs
- dynamic analysis runs with debug assertions enabled so parser and normalisation invariants fail fast during fuzzing
- CI is green across all runners

If a release changes behaviour without updating tests or examples, it is not ready.

## Supply Chain Integrity

Before closing a release, confirm that:
- GoReleaser generates `dist/checksums.txt`
- GoReleaser generates `dist/checksums.txt.sigstore.json`
- each shipped archive has a matching `*.spdx.json` SBOM
- each shipped SBOM has a matching `.sigstore.json` bundle
- the published archives verify cleanly against `checksums.txt`
- GitHub provenance attestations are published for the released checksum manifest
- the verification commands documented in [the project README](../../README.md) and [the release docs index](README.md) were tested against the release assets

## Scope Discipline

Before a release, confirm that the release has not silently drifted into:
- undeclared or implicit range scanning
- active probing hidden inside discovery
- non-TLS scanner execution hidden inside audit
- generic vulnerability scanning
- trust or compliance claims the implementation cannot support

The release should stay narrow and defensible.

## Final Release Preparation

Before tagging:
- review open milestone items
- confirm branch protection and required CI checks on `master`
- confirm `CI / Cleanup` is the required repository CI gate if the master workflow is in use
- confirm GitHub DCO app enforcement is active if the repository relies on signed-off commits
- regenerate `CONTRIBUTORS` and commit any real changes before tagging
- update release notes
- update `CHANGELOG.md`
- confirm the version to tag
- confirm the examples and docs from a clean checkout

If the README still needs to explain away missing core behaviour, the release is not ready.
