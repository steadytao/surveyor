# Surveyor

Surveyor is a cryptographic inventory and migration-readiness tool.

It currently starts with two narrow questions:

- what endpoints is this machine exposing locally
- what does a TLS-facing service actually present today, and what does that imply for post-quantum migration work tomorrow

The point is not to produce a vague “PQ score”. The point is to give teams a clear inventory of what they are running, where classical public-key dependencies still exist, and what probably needs attention first.

## Status

Surveyor is in early development.

The first milestone was intentionally narrow. It completed as a TLS inventory MVP for explicitly provided targets.

The current repository now includes a generalised remote inventory surface around `surveyor discover remote` and `surveyor audit remote`.

The current repository already includes:

- local and remote audit orchestration for supported TLS-like endpoints
- local endpoint discovery
- scoped remote discovery across CIDR, simple file-backed host scope and structured inventory manifests
- baseline-compatible report metadata on current JSON reports
- saved-report diffing for compatible TLS and audit reports
- current-report prioritisation for compatible TLS and audit reports
- conservative protocol hints for discovery results
- remote scope parsing and validation
- structured imported inventory parsing from YAML, JSON and CSV
- target parsing and validation
- TLS connection and protocol inspection
- certificate chain parsing
- public-key and signature algorithm inventory
- conservative readiness classification
- machine-readable and human-readable reporting

The repository now includes usable CLI paths for local audit, remote audit, local discovery, remote discovery and the explicit-target TLS inventory slice.

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

- run local audit by chaining discovery into the existing TLS scanner conservatively
- run remote audit within explicitly declared remote scope and explicit port surface
- enumerate local listening or bound endpoints without active probing
- enumerate remote TCP reachability within explicitly declared CIDR, file-backed host or structured inventory scope and explicit port surface
- attach conservative protocol hints to discovery results
- compare compatible saved TLS and audit reports deterministically
- rank current TLS and audit reports for migration-readiness or change-risk
- connect to explicit TLS targets
- collect handshake and certificate facts
- classify migration posture conservatively
- emit structured results and a readable report

It does not currently aim to:

- implement post-quantum cryptography
- replace PKI systems
- scan undeclared or implicit address ranges
- act as a general-purpose vulnerability scanner
- produce exploit tooling
- flatten complex migration work into a binary “quantum-safe” label

## Current implementation

Surveyor currently has implemented internal slices for:

- local and remote audit orchestration for discovery-to-TLS handoff
- local discovery and scoped remote discovery
- remote scope parsing and validation
- YAML config parsing and validation for explicit TLS targets
- TLS handshake collection against explicit targets
- X.509 certificate and chain metadata extraction
- conservative readiness classification
- canonical JSON report assembly
- derived Markdown reporting

The current code and docs are organised around JSON as the canonical result contract and Markdown as derived output.

## CLI

The current CLI supports local audit, remote audit, local discovery, remote discovery and explicit-target TLS inventory.

Analysis:

```bash
surveyor diff baseline.json current.json -o diff.md -j diff.json
surveyor prioritize current.json --profile migration-readiness -o priorities.md -j priorities.json
surveyor prioritise current.json --profile change-risk -o priorities.md -j priorities.json
```

Audit:

```bash
surveyor audit local -o audit.md -j audit.json
surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443 -o audit-remote.md -j audit-remote.json
surveyor audit remote --targets-file examples/approved-hosts.txt --ports 443 -o audit-remote.md -j audit-remote.json
surveyor audit remote --inventory-file examples/inventory.yaml -o audit-inventory.md -j audit-inventory.json
```

Discovery:

```bash
surveyor discover local -o discovery.md -j discovery.json
surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443 -o discovery-remote.md -j discovery-remote.json
surveyor discover remote --targets-file examples/approved-hosts.txt --ports 443 -o discovery-remote.md -j discovery-remote.json
surveyor discover remote --inventory-file examples/inventory.yaml -o discovery-inventory.md -j discovery-inventory.json
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

- `audit local` only hands supported TLS-like endpoints into the current TLS scanner and keeps discovered facts, hints and verified scan results separate
- `audit remote` only walks explicitly declared remote scope and declared ports, then hands supported TLS-like remote endpoints into the current TLS scanner
- `discover local` is observational only, it does not perform active probing or verified protocol scans
- `discover remote` performs bounded remote TCP reachability probing within explicitly declared scope, and it does not perform verified protocol scans
- `diff` currently supports `tls_scan` to `tls_scan` and `audit` to `audit` comparisons only
- `prioritize` currently supports current `tls_scan` and `audit` reports only
- `prioritise` is a CLI alias for `prioritize`
- use exactly one of `--config` or `--targets`
- `--targets` requires explicit `host:port` entries
- the canonical remote commands require exactly one of `--cidr`, `--targets-file` or `--inventory-file`
- `--ports` is required for `--cidr` and `--targets-file`, and overrides per-entry inventory ports when set
- `discover subnet` and `audit subnet` remain CIDR-only compatibility aliases from `v0.4.x`
- `--profile` sets default remote pace, explicit `--max-hosts`, `--max-concurrency` and `--timeout` override it
- `--dry-run` performs no network I/O and prints the execution plan
- `--json` is not supported with `--dry-run`
- discovery and audit reports now carry explicit scope metadata, and remote runs also carry execution metadata
- remote IP-target TLS results should be read as literal connection-path observations, not hostname-validation or virtual-host coverage claims
- IPv6 targets must use bracket form, for example `[::1]:443`
- if no output paths are given, Markdown is written to stdout

Example verification:

```bash
go build -o surveyor ./cmd/surveyor
./surveyor audit local -o audit.md -j audit.json
./surveyor discover local -o discovery.md -j discovery.json
./surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443 --dry-run
./surveyor discover remote --targets-file examples/approved-hosts.txt --ports 443 --dry-run
./surveyor discover remote --inventory-file examples/inventory.yaml --dry-run
./surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443 --dry-run
./surveyor audit remote --targets-file examples/approved-hosts.txt --ports 443 --dry-run
./surveyor audit remote --inventory-file examples/inventory.yaml --dry-run
./surveyor diff baseline.json current.json -o diff.md -j diff.json
./surveyor prioritize current.json --profile migration-readiness -o priorities.md -j priorities.json
./surveyor scan tls -c examples/targets.yaml -o report.md -j report.json
```

For the current implementation boundaries, see:

- [docs/audit.md](docs/audit.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/discovery.md](docs/discovery.md)
- [docs/output-schema.md](docs/output-schema.md)
- [docs/baselines.md](docs/baselines.md)
- [docs/diffing.md](docs/diffing.md)
- [docs/prioritisation.md](docs/prioritisation.md)
- [docs/classification.md](docs/classification.md)
- [docs/references.md](docs/references.md)
- [docs/safety.md](docs/safety.md)
- [docs/release-checklist.md](docs/release-checklist.md)
- [docs/inventory-inputs.md](docs/inventory-inputs.md) for the current structured inventory input contract

## Remote boundary

Generalised remote scope is now part of the current repository surface.

The current remote boundary is still intentionally narrow:

- explicit `--cidr`, `--targets-file` or `--inventory-file` scope required
- explicit ports required for `--cidr` and `--targets-file`
- inventory manifests may carry per-entry ports, and `--ports` overrides them when supplied
- cautious by default
- existing TLS scanner only for verified remote scanning
- discovered facts, hints, selection decisions and verified scan results kept separate
- `discover subnet` and `audit subnet` retained as CIDR-only compatibility aliases from `v0.4.x`

See:

- [docs/remote-inventory.md](docs/remote-inventory.md) for the current remote inventory boundary
- [docs/remote-scope.md](docs/remote-scope.md) for the current remote scope model
- [docs/inventory-inputs.md](docs/inventory-inputs.md) for the current structured inventory input layer

## Current analysis layer

The current repository now includes a baseline, diffing and prioritisation layer over canonical Surveyor JSON reports.

Current boundary:

- current reports carry baseline-compatible metadata
- `surveyor diff baseline.json current.json` is implemented
- `surveyor prioritize current.json` is implemented
- `surveyor prioritise current.json` is supported as a CLI alias
- prioritisation profiles currently include `migration-readiness` and `change-risk`
- diffing currently supports only compatible `tls_scan` and `audit` input
- prioritisation currently supports current `tls_scan` and `audit` input

It still does not include:

- a database
- a dashboard
- policy-as-code complexity
- diff-input prioritisation
- discovery-only diffing
- another deep scanner in the same milestone

See:

- [docs/baselines.md](docs/baselines.md)
- [docs/diffing.md](docs/diffing.md)
- [docs/prioritisation.md](docs/prioritisation.md)

## Development

Surveyor is written in Go.

The repository currently contains a working `cmd/surveyor` entrypoint for local and remote audit and discovery, explicit-target TLS inventory, saved-report diffing and current-report prioritisation, plus the internal packages and tests behind them.

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
./surveyor audit local -o audit.md -j audit.json
./surveyor discover local -o discovery.md -j discovery.json
./surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443 --dry-run
./surveyor discover remote --targets-file examples/approved-hosts.txt --ports 443 --dry-run
./surveyor discover remote --inventory-file examples/inventory.yaml --dry-run
./surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443 --dry-run
./surveyor audit remote --targets-file examples/approved-hosts.txt --ports 443 --dry-run
./surveyor audit remote --inventory-file examples/inventory.yaml --dry-run
./surveyor diff baseline.json current.json -o diff.md -j diff.json
./surveyor prioritize current.json --profile migration-readiness -o priorities.md -j priorities.json
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
