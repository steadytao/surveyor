<div align="center">
  <img src="./.github/banner.svg" alt="BANNER" width="720">
</div>

Surveyor is a TLS-first cryptographic inventory and migration-readiness tool.

It is built for a narrow, practical question set:

- what transport-facing endpoints exist
- what does a TLS service actually present today
- where do classical certificate and PKI dependencies still exist
- what should a team look at first for migration readiness or change risk

Surveyor is not trying to collapse that work into a vague “PQ score”. It is
trying to produce a defensible inventory and a clear next-action surface.

## Menu

- [Status](#status)
- [What Surveyor Is](#what-surveyor-is)
- [What Surveyor Is Not](#what-surveyor-is-not)
- [Install](#install)
- [Quick Start](#quick-start)
- [Command Surface](#command-surface)
- [Remote Scope](#remote-scope)
- [Import Adapters](#import-adapters)
- [Reports And Analysis](#reports-and-analysis)
- [Documentation](#documentation)
- [Development](#development)
- [Contributing](#contributing)
- [Security](#security)
- [Licence](#licence)
- [Changelog](#changelog)

## Status

Surveyor is in early development.

The current shipped surface includes:

- explicit TLS inventory through `surveyor scan tls`
- local discovery and local audit
- remote discovery and remote audit
- structured imported inventory through `--inventory-file`
- platform-specific import adapters for Caddy and Kubernetes Ingress v1
- saved-report diffing for compatible `tls_scan` and `audit` reports
- current-report prioritisation for compatible `tls_scan` and `audit` reports
- workflow grouping and filtering for inventory-backed audit diff and prioritisation views

Published releases appear here:

<https://github.com/steadytao/surveyor/releases>

## What Surveyor Is

Surveyor currently aims to be:

- a TLS-first cryptographic inventory tool
- a local and remote discovery tool for explicitly declared scope
- an audit tool that chains discovery into the existing TLS scanner conservatively
- a report generator with canonical JSON and derived Markdown
- a narrow decision-support layer for diffing and prioritisation

## What Surveyor Is Not

Surveyor is not currently:

- a general-purpose vulnerability scanner
- a post-quantum cryptography implementation
- a PKI replacement system
- a dashboard or storage platform
- a live connector platform
- a policy engine
- a multi-protocol scanner

It also does not scan undeclared address ranges or silently widen scope.

## Install

You may install our builds at:
<https://github.com/steadytao/surveyor/releases>

OR

You can build Surveyor from source:
```bash
git clone https://github.com/steadytao/surveyor.git
cd surveyor
go build -o surveyor ./cmd/surveyor
```

On Windows, use `.\surveyor.exe` instead of `./surveyor`.

## Quick Start

Explicit TLS inventory:

```bash
surveyor scan tls -c examples/targets.yaml -o report.md -j report.json
```

Local discovery and audit:

```bash
surveyor discover local -o discovery.md -j discovery.json
surveyor audit local -o audit.md -j audit.json
```

Remote dry run inside declared scope:

```bash
surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443 --dry-run
surveyor audit remote --targets-file examples/approved-hosts.txt --ports 443 --dry-run
```

Adapter-backed remote audit:

```bash
surveyor audit remote --inventory-file examples/ingress.yaml --adapter kubernetes-ingress-v1 -o audit-kubernetes.md -j audit-kubernetes.json
surveyor audit remote --inventory-file Caddyfile --adapter-bin /path/to/caddy -o audit-caddy.md -j audit-caddy.json
```

Analysis:

```bash
surveyor diff baseline.json current.json -o diff.md -j diff.json
surveyor prioritize current.json --profile migration-readiness -o priorities.md -j priorities.json
```

## Command Surface

Canonical commands:

```bash
surveyor scan tls
surveyor discover local
surveyor discover remote
surveyor audit local
surveyor audit remote
surveyor diff
surveyor prioritize
```

Compatibility aliases:

- `surveyor discover subnet`
- `surveyor audit subnet`
- `surveyor prioritise`

Primary docs and examples should use the canonical forms. The aliases remain for
compatibility and usability, not as separate features.

Current command examples:

```bash
surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443
surveyor discover remote --targets-file examples/approved-hosts.txt --ports 443
surveyor discover remote --inventory-file examples/inventory.yaml
surveyor discover remote --inventory-file examples/caddy.json --adapter caddy

surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443
surveyor audit remote --targets-file examples/approved-hosts.txt --ports 443
surveyor audit remote --inventory-file examples/inventory.yaml
surveyor audit remote --inventory-file examples/ingress.yaml --adapter kubernetes-ingress-v1

surveyor diff baseline.json current.json
surveyor prioritize current.json --profile change-risk
```

## Remote Scope

Remote commands require exactly one of:

- `--cidr`
- `--targets-file`
- `--inventory-file`

CIDR is the standard notation for an IP range, for example:

- `192.168.1.0/24` for a typical subnet
- `10.0.0.5/32` for a single host

`discover subnet` and `audit subnet` exist because many operators recognise
“subnet” more readily than “CIDR”. They are plain-language aliases for the
CIDR-backed remote path.

Current rules:

- `--ports` is required for `--cidr` and `--targets-file`
- `--ports` overrides per-entry ports when `--inventory-file` is used
- `--dry-run` performs no network I/O and prints an execution plan
- remote IP-literal TLS results are literal connection-path observations, not hostname-validation or virtual-host coverage claims

## Import Adapters

Surveyor supports generic imported inventory through `--inventory-file`, plus
the first stable adapter layer on top of that path.

Current adapter surface:

- `--adapter caddy` for Caddy JSON and Caddyfile input
- auto-detected `caddy` adapter for `Caddyfile` and `*.caddyfile`
- `--adapter kubernetes-ingress-v1` for Kubernetes Ingress v1 manifests
- `--adapter-bin PATH` when the selected adapter needs an external executable

Current limits remain deliberate:

- no live cloud or CMDB connectors
- no generic Kubernetes parser
- no second import command family

## Reports And Analysis

JSON is Surveyor’s canonical output. Markdown is derived from the same model.

Current report kinds:

- `tls_scan`
- `discovery`
- `audit`
- `diff`
- `prioritization`

Current analysis boundaries:

- diffing supports compatible `tls_scan` and `audit` reports only
- prioritisation supports current `tls_scan` and `audit` reports only
- workflow grouping and filtering apply only to inventory-backed audit diff and prioritisation views
- discovery is a shipped report kind, but not currently a supported diff or prioritisation input

The current `schema_version` line is `1.x`. Within `1.x`, contract changes
should be additive. Removals, renames, semantic changes, requiredness changes
and identity-key changes should require a breaking schema bump.

## Documentation

Start here for the docs map:

- [docs/README.md](docs/README.md)

Key documents:

- [docs/discovery.md](docs/discovery.md)
- [docs/audit.md](docs/audit.md)
- [docs/remote-scope.md](docs/remote-scope.md)
- [docs/import-adapters.md](docs/import-adapters.md)
- [docs/output-schema.md](docs/output-schema.md)
- [docs/baselines.md](docs/baselines.md)
- [docs/diffing.md](docs/diffing.md)
- [docs/prioritisation.md](docs/prioritisation.md)
- [docs/safety.md](docs/safety.md)
- [docs/release-checklist.md](docs/release-checklist.md)

## Development

The main verification commands are:

```bash
go build ./cmd/surveyor
go vet ./...
go test ./...
```

Representative local checks:

```bash
./surveyor discover local -o discovery.md -j discovery.json
./surveyor audit local -o audit.md -j audit.json
./surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443 --dry-run
./surveyor audit remote --inventory-file examples/inventory.yaml --dry-run
./surveyor diff baseline.json current.json -o diff.md -j diff.json
./surveyor prioritize current.json --profile migration-readiness -o priorities.md -j priorities.json
./surveyor scan tls -c examples/targets.yaml -o report.md -j report.json
```

## Contributing

Well-scoped contributions are welcome.

Start with [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md). For larger
changes, open an issue first so scope and direction can be discussed before
implementation starts.

## Security

If you believe you have found a security issue in Surveyor itself, do not open a
public issue.

See [.github/SECURITY.md](.github/SECURITY.md) for reporting instructions.

## Licence

Surveyor is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
