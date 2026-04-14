# Surveyor

Surveyor is a cryptographic inventory and migration-readiness tool.

It starts with a narrow question: what does a TLS-facing service actually present today, and what does that imply for post-quantum migration work tomorrow?

The point is not to produce a vague “PQ score”. The point is to give teams a clear inventory of what they are running, where classical public-key dependencies still exist, and what probably needs attention first.

## Status

Surveyor is in early development.

The first milestone is intentionally narrow. It is a TLS inventory MVP for explicitly provided targets.

The current repository already includes:
- target parsing and validation
- TLS connection and protocol inspection
- certificate chain parsing
- public-key and signature algorithm inventory
- conservative readiness classification
- machine-readable and human-readable reporting

The repository now includes a first usable CLI path for the TLS inventory slice, with both config-driven and explicit command-line targets.

## Why this project exists

Post-quantum migration is not mainly a cryptography-library problem. For most teams it is an inventory and prioritisation problem.

Before anything can be migrated, someone needs to answer practical questions:
- where classical public-key cryptography is in use
- which services, certificates, and trust paths depend on it
- what is externally exposed
- what is straightforward to replace
- what needs manual review or architectural change

Surveyor exists to make that visible.

## Current scope

Version one is intentionally limited to TLS-facing services that are explicitly provided as targets.

That means Surveyor currently aims to:
- connect to explicit TLS targets
- collect handshake and certificate facts
- classify migration posture conservatively
- emit structured results and a readable report

It does not currently aim to:
- implement post-quantum cryptography
- replace PKI systems
- scan arbitrary address ranges by default
- act as a general-purpose vulnerability scanner
- produce exploit tooling
- flatten complex migration work into a binary “quantum-safe” label

## Current implementation

Surveyor currently has implemented internal slices for:
- YAML config parsing and validation for explicit TLS targets
- TLS handshake collection against explicit targets
- X.509 certificate and chain metadata extraction
- conservative readiness classification
- canonical JSON report assembly
- derived Markdown reporting

The current code and docs are organised around JSON as the canonical result contract and Markdown as derived output.

## CLI

The current CLI supports the TLS inventory path:
```bash
surveyor scan tls -c examples/targets.yaml -o report.md -j report.json
```

For ad hoc local or one-off scans, explicit command-line targets are also supported:
```bash
surveyor scan tls -t example.com:443,127.0.0.1:8000
```

Rules:
- use exactly one of `--config` or `--targets`
- `--targets` requires explicit `host:port` entries
- IPv6 targets must use bracket form, for example `[::1]:443`
- if no output paths are given, Markdown is written to stdout

For the current implementation boundaries, see:
- [docs/architecture.md](docs/architecture.md)
- [docs/output-schema.md](docs/output-schema.md)
- [docs/classification.md](docs/classification.md)
- [docs/references.md](docs/references.md)
- [docs/safety.md](docs/safety.md)
- [docs/release-checklist.md](docs/release-checklist.md)

## Roadmap

### Milestone 1: TLS Inventory MVP
<https://github.com/steadytao/surveyor/milestone/1>
- repository baseline
- configuration loading and validation
- TLS target connection
- certificate chain parsing
- public-key and signature algorithm inventory
- initial readiness classification
- JSON reporting
- Markdown reporting

Later milestones may expand into other cryptographic surfaces, but not before the TLS path is solid.

## Development

Surveyor is written in Go.

The repository currently contains a working `cmd/surveyor` entrypoint for the TLS inventory slice, plus the internal packages and tests behind it.

For now, the most useful verification command is:
```bash
go test ./...
```

The expected local build flow is:
```bash
git clone https://github.com/steadytao/surveyor.git
cd surveyor
go build ./cmd/surveyor
```

## Contributing

Well-scoped contributions are welcome.

If you want to work on Surveyor, start by reading [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md). For larger changes, please open an issue first so the scope and direction can be discussed before work starts.

## Security

If you believe you have found a security issue in Surveyor itself, do not open a public issue.

See [.github/SECURITY.md](.github/SECURITY.md) for reporting instructions.

## Licence

Surveyor is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
