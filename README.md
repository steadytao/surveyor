# Surveyor

Surveyor is a cryptographic inventory and migration-readiness tool.

It currently starts with two narrow questions:

- what endpoints is this machine exposing locally
- what does a TLS-facing service actually present today, and what does that imply for post-quantum migration work tomorrow

The point is not to produce a vague “PQ score”. The point is to give teams a clear inventory of what they are running, where classical public-key dependencies still exist, and what probably needs attention first.

## Status

Surveyor is in early development.

The first milestone was intentionally narrow. It completed as a TLS inventory MVP for explicitly provided targets.

The current repository now includes the discovery foundation work around `surveyor discover local`.

The current repository already includes:

- local endpoint discovery
- conservative protocol hints for discovery results
- target parsing and validation
- TLS connection and protocol inspection
- certificate chain parsing
- public-key and signature algorithm inventory
- conservative readiness classification
- machine-readable and human-readable reporting

The repository now includes usable CLI paths for both local discovery and the TLS inventory slice.

## Releases

Published releases appear here:

<https://github.com/steadytao/surveyor/releases>

When releases are published, assets include downloadable binaries for Linux, macOS and Windows on amd64 and arm64.

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

The current repository is still intentionally narrow.

That means Surveyor currently aims to:

- enumerate local listening or bound endpoints without active probing
- attach conservative protocol hints to discovered local endpoints
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

The current CLI supports discovery and explicit-target TLS inventory.

Discovery:

```bash
surveyor discover local -o discovery.md -j discovery.json
```

TLS inventory:

```bash
surveyor scan tls -c examples/targets.yaml -o report.md -j report.json
```

For ad hoc local or one-off scans, explicit command-line targets are also supported:

```bash
surveyor scan tls -t example.com:443,127.0.0.1:8000,[::1]:443
```

Rules:

- `discover local` is observational only, it does not perform active probing or verified protocol scans
- use exactly one of `--config` or `--targets`
- `--targets` requires explicit `host:port` entries
- IPv6 targets must use bracket form, for example `[::1]:443`
- if no output paths are given, Markdown is written to stdout

Example local verification:

```bash
go build -o surveyor ./cmd/surveyor
./surveyor discover local -o discovery.md -j discovery.json
./surveyor scan tls -c examples/targets.yaml -o report.md -j report.json
```

For the current implementation boundaries, see:

- [docs/audit.md](docs/audit.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/discovery.md](docs/discovery.md)
- [docs/output-schema.md](docs/output-schema.md)
- [docs/classification.md](docs/classification.md)
- [docs/references.md](docs/references.md)
- [docs/safety.md](docs/safety.md)
- [docs/release-checklist.md](docs/release-checklist.md)

## Roadmap

The current architectural focus is `Local Audit MVP`, chaining local discovery into the existing TLS scanner rather than adding another standalone deep scanner first.

## Development

Surveyor is written in Go.

The repository currently contains a working `cmd/surveyor` entrypoint for both the discovery and TLS inventory slices, plus the internal packages and tests behind them.

For now, the most useful verification command is:

```bash
go build -o surveyor ./cmd/surveyor
go vet ./...
go test ./...
```

The expected local build flow is:

```bash
git clone https://github.com/steadytao/surveyor.git
cd surveyor
go build -o surveyor ./cmd/surveyor
```

Then run:

```bash
./surveyor discover local -o discovery.md -j discovery.json
./surveyor scan tls -c examples/targets.yaml -o report.md -j report.json
```

On Windows, run `.\surveyor.exe` instead of `./surveyor`.

## Contributing

Well-scoped contributions are welcome.

If you want to work on Surveyor, start by reading [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md). For larger changes, please open an issue first so the scope and direction can be discussed before work starts.

## Security

If you believe you have found a security issue in Surveyor itself, do not open a public issue.

See [.github/SECURITY.md](.github/SECURITY.md) for reporting instructions.

## Licence

Surveyor is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
