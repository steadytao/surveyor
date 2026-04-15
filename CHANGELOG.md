# Changelog

All notable changes to Surveyor will be documented in this file.

The format is intentionally simple. Surveyor is still in early development so the goal is to keep release notes accurate and reviewable rather than decorative.

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
