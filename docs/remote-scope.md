<div align="center">
  <img src="../.github/banner.svg" alt="BANNER" width="720">
</div>

# Generalised Remote Scope

Generalised remote scope is now part of Surveyor's current repository surface.

This document defines the current remote scope model that sits underneath
[docs/remote-inventory.md](remote-inventory.md).

## Current command surface

Canonical remote commands:

```bash
surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o discovery.md -j discovery.json
surveyor discover remote --targets-file approved-hosts.txt --ports 443,8443 --profile cautious -o discovery.md -j discovery.json
surveyor discover remote --inventory-file inventory.yaml --profile cautious -o discovery.md -j discovery.json
surveyor discover remote --inventory-file Caddyfile --adapter-bin /path/to/caddy -o discovery.md -j discovery.json

surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o audit.md -j audit.json
surveyor audit remote --targets-file approved-hosts.txt --ports 443,8443 --profile cautious -o audit.md -j audit.json
surveyor audit remote --inventory-file inventory.yaml --profile cautious -o audit.md -j audit.json
surveyor audit remote --inventory-file ingress.yaml --adapter kubernetes-ingress-v1 -o audit.md -j audit.json
```

Compatibility aliases:

```bash
surveyor discover subnet ...
surveyor audit subnet ...
```

Those aliases continue to mean the CIDR-backed remote path only. They are
compatibility affordances, not the long-term design centre.

CIDR is the standard notation for an IP range, for example:

- `192.168.1.0/24` for a typical subnet
- `10.0.0.5/32` for a single host

The `subnet` aliases remain because many operators recognise “subnet” more
readily than “CIDR”.

## Scope model

The current remote scope model represents:

- remote scope kind
- declared input kind
- declared source details
- effective host set
- declared ports
- effective execution controls

Current report and planning fields:

- `scope_kind: remote`
- `input_kind: cidr | targets_file | inventory_file`
- `cidr` when relevant
- `targets_file` when relevant
- `inventory_file` when relevant
- `adapter` when remote scope came from adapter-backed inventory input
- `host_count`
- `ports`

These fields should be reflected consistently in:

- CLI execution planning
- config parsing
- discovery report metadata
- audit report metadata

## Targets-file rules

The file-backed scope grammar stays deliberately simple.

Current rules:

- one host or IP per line
- blank lines allowed
- `#` comments allowed
- no implicit ports in the file
- `--ports` remains required

Do not add host:port tuples, YAML or multiple competing file grammars in the current line.

That keeps the remote model explicit:

- the file defines scope
- `--ports` defines surface

## Inventory-file rules

The structured inventory grammar is now part of the current remote model.

Current rules:

- supported formats are `.yaml`, `.yml`, `.json` and `.csv`
- YAML and JSON manifests require `version: 1`
- YAML and JSON manifests require a non-empty `entries` array
- CSV requires a header row with `host` or `address`
- supported CSV headers are `host`, `address`, `ports`, `name`, `owner`, `environment`, `tags` and `notes`
- imported entries may declare `host` or `address`, and if both are present they must agree
- imported entries may declare `ports`
- if `--ports` is supplied it overrides imported entry ports for the run
- if `--ports` is omitted, imported entry ports are used
- if neither exists for an entry, remote-scope parsing fails clearly

The structured inventory model remains narrow on purpose. It is a generic imported-inventory layer, not a platform-adapter framework.

Current adapter-backed extension:

- `--adapter caddy`
- `--adapter kubernetes-ingress-v1`
- `--adapter-bin PATH` when the selected adapter needs an external executable
- auto-detected `caddy` adapter for `Caddyfile` and `*.caddyfile`

## Safety model

Generalised remote scope keeps the current remote safety controls:

- `--profile cautious|balanced|aggressive`
- `--dry-run`
- `--max-hosts`
- `--max-concurrency`
- `--timeout`
- `--ports`

Rules:

- `--profile` sets defaults
- explicit flags override profile defaults
- profiles change pace, not scope
- scope remains explicit
- `--dry-run` performs no network I/O

For `--targets-file`, `--max-hosts` still applies after the file is parsed
and normalised.

For `--inventory-file`, `--max-hosts` applies after inventory parsing,
normalisation and deduplication.

## Discovery and audit boundaries

Generalised remote scope does not blur the existing architectural separation.

Discovery should still do:

- observed remote facts
- conservative hints

Audit should still do:

- selection
- scanner handoff
- verified TLS results

TLS remains the only deep verified scanner in the current milestone line.

## What must remain true

These rules remain true in the current implementation:

- discovery records facts before hinting
- hints stay separate from verified scans
- audit remains orchestration, not a second scanner implementation
- JSON remains canonical
- Markdown contains no facts absent from JSON
- compatibility aliases do not become the product's long-term centre of gravity
- ambiguous observations fall back to skip or manual review rather than overclaiming

## Non-goals

The current remote scope model does not include:

- a second deep scanner
- STARTTLS or multi-protocol probing
- trust-store validation
- hostname validation
- history, diffing or stateful storage
- policy engines
- cloud connectors
- undeclared or internet-wide scanning
- complex scope-file grammars

## Relationship to the current remote surface

The current remote surface is now:

- canonical `surveyor discover remote`
- canonical `surveyor audit remote`
- explicit `--cidr`, `--targets-file` or `--inventory-file`
- explicit `--ports` for `--cidr` and `--targets-file`, with override semantics for `--inventory-file`
- `surveyor discover subnet` and `surveyor audit subnet` retained as CIDR-only compatibility aliases from `v0.4.x`

That makes remote scope first-class without weakening the existing discovery,
hinting, selection and verified-scanning boundaries.

## Relationship to structured inventory inputs

Structured imported inventory now extends the same canonical remote command family.

That layer:

- preserves the current canonical `remote` command family
- keeps `--targets-file` as the simple host-list input
- adds a structured imported-inventory model rather than overloading the existing line-list grammar

That contract is documented in [docs/inventory-inputs.md](inventory-inputs.md).

The current adapter layer extends the same `inventory_file` path with explicit
adapter selection for stable platform exports rather than inventing a second
import command family. That current boundary is documented in
[docs/import-adapters.md](import-adapters.md) and
[docs/adapter-contract.md](adapter-contract.md).
