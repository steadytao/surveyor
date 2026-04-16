# Changelog

All notable changes to Surveyor will be documented in this file.

The format is intentionally simple. Surveyor is still in early development so the goal is to keep release notes accurate and reviewable rather than decorative.

## v0.6.0

### Added
- `surveyor diff` now compares compatible saved `tls_scan` and `audit` reports and emits canonical JSON plus derived Markdown output
- `surveyor prioritize` now ranks current `tls_scan` and `audit` reports with the `migration-readiness` and `change-risk` profiles, and `surveyor prioritise` is supported as a CLI alias
- baseline-compatible report metadata, compatibility validation, stable identity keys, prioritisation examples and diff examples are now part of the shipped repository surface

### Changed
- README, architecture, schema, baseline, diffing, prioritisation and release-checklist docs now describe the implemented analysis layer rather than the earlier milestone design draft
- the public docs no longer imply unsupported behaviour such as `surveyor diff --profile`; the documented `v0.6.0` surface now matches the actual CLI and report contracts

## v0.5.0

### Added
- canonical `surveyor discover remote` and `surveyor audit remote` commands now support both explicitly declared CIDR scope and simple file-backed host scope
- remote discovery and audit reports now exercise `input_kind=targets_file` with checked-in examples and golden outputs for the canonical remote command family

### Changed
- `surveyor discover subnet` and `surveyor audit subnet` are now explicitly documented as CIDR-only compatibility aliases from `v0.4.x` rather than the canonical remote command surface
- README, architecture, remote inventory, remote scope, discovery, audit, safety and release-checklist docs now describe the shipped generalised remote scope model instead of the earlier subnet-only remote boundary

## v0.4.1

### Changed
- report assembly and audit-selection cloning now deep-copy nested report data such as discovery hint evidence, certificate metadata and finding evidence so canonical reports cannot alias caller-owned slice storage
- added regression coverage around report cloning so the JSON-first and Markdown-derived reporting paths keep stable copied data rather than depending on mutable upstream inputs

## v0.4.0

### Added
- `surveyor discover subnet` now performs bounded remote TCP reachability discovery within explicitly declared CIDR scope and explicit port sets
- `surveyor audit subnet` now chains scoped remote discovery into the existing TLS scanner and emits one combined audit report
- discovery and audit reports now carry explicit scope metadata, and remote runs also carry execution metadata describing the effective profile, host cap, concurrency and timeout

### Changed
- the `v0.4.0` remote inventory contract is now explicitly CIDR-only; deferred `--targets-file` mode is removed from the current public CLI surface
- remote audit now passes the effective remote timeout through to TLS connection attempts as well as remote discovery probes
- README, remote-inventory docs, discovery docs, audit docs, output-schema docs, safety docs, classification docs, examples and golden outputs now describe the actual remote release boundary, including the fact that remote IP-target TLS results are literal connection-path observations rather than hostname-validation or full virtual-host coverage claims

## v0.3.1

### Changed
- clarified internal contracts across the config, core, discovery, audit, scanner and output packages with higher-signal doc comments and invariant comments
- tightened the architecture and audit docs so the current local-audit runner, selection rules and discovery-to-scan boundary are easier to understand and maintain
- preserved the current CLI, JSON and Markdown behaviour while making the codebase easier to review and extend safely

## v0.3.0

### Added
- `surveyor audit local` now chains local discovery into the supported TLS scanner and emits one combined audit report
- audit output now preserves discovered facts, protocol hints, scanner selection decisions, verified TLS results and explicit skip reasons in one canonical JSON-first model
- canonical audit JSON and derived Markdown reports, including checked-in example outputs

### Changed
- README, audit docs, architecture docs, discovery docs, output schema docs, safety docs and release checklist now describe the implemented local audit workflow rather than a planned one
- the repository now presents local audit, local discovery and explicit-target TLS inventory as the current shipped CLI surface

## v0.2.0

### Added
- `surveyor discover local` now enumerates local TCP listening endpoints and UDP bound endpoints
- discovery output now includes best-effort process metadata where available
- discovery output now includes conservative low-confidence protocol hints derived from observed facts
- canonical discovery JSON and derived Markdown reports, including checked-in example outputs

### Changed
- discovery docs, architecture docs, safety docs and output schema docs now describe the implemented discovery slice rather than a planned one
- release checklist now treats discovery as part of the shipped functional surface

## v0.1.1

### Changed
- README build and run instructions now use an explicit output binary name, note the Windows invocation form and avoid claiming unpublished releases
- `examples/targets.yaml` now matches the single-target example report surface instead of including a guaranteed unreachable target
- Markdown report output now reads more like a report and less like API-shaped text by removing unnecessary backticks from ordinary values
- the manual release workflow now appends a generated commit changelog between releases, so checked-in release notes can stay editorial

## v0.1.0

### Added
- initial CLI under `surveyor scan tls`
- YAML config parsing and validation for explicit TLS targets
- TLS handshake collection and X.509 metadata extraction
- conservative readiness classification
- canonical JSON and derived Markdown reporting
- deterministic test fixtures and golden outputs
- cross-platform CI with `go vet` and Linux race detection

### Documentation
- architecture, schema, classification, references, safety and release-checklist docs
- repository README updated to match the shipped implementation

### Scope
- initial TLS inventory MVP scope
- explicit TLS targets only
- no discovery across ranges, non-TLS surfaces, trust validation or compliance claims beyond the current documented boundaries
