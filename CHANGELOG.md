# Changelog

All notable changes to Surveyor will be documented in this file.

The format is intentionally simple. Surveyor is still in early development so the goal is to keep release notes accurate and reviewable rather than decorative.

## Unreleased

### Changed
- README build and run instructions now use an explicit output binary name and note the Windows invocation form
- `examples/targets.yaml` now matches the single-target example report surface instead of including a guaranteed unreachable target
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
- first public release of the TLS inventory MVP
- explicit TLS targets only
- no discovery across ranges, non-TLS surfaces, trust validation or compliance claims beyond the current documented boundaries
