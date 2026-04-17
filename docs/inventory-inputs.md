# Structured Inventory Inputs

This document defines the current structured inventory input layer.

It is part of the current repository surface and extends the remote scope
model documented in [docs/remote-scope.md](remote-scope.md).

## Why this layer exists

Surveyor already has the core operational loop:

- explicit TLS inventory
- local discovery and audit
- scoped remote discovery and audit
- saved-report diffing
- current-report prioritisation

The next high-leverage gap is not scanner breadth. It is input quality.

Surveyor now consumes approved imported inventory and feeds it into the
existing remote discovery, remote audit, diffing and prioritisation flow
without redesigning the core again.

## Current command surface

The canonical commands are:

```bash
surveyor discover remote --inventory-file inventory.yaml -o discovery.md -j discovery.json
surveyor discover remote --inventory-file inventory.yaml --ports 443,8443 -o discovery.md -j discovery.json

surveyor audit remote --inventory-file inventory.yaml -o audit.md -j audit.json
surveyor audit remote --inventory-file inventory.yaml --ports 443,8443 -o audit.md -j audit.json
```

Important rule:

- remote commands should accept exactly one of:
  - `--cidr`
  - `--targets-file`
  - `--inventory-file`

`--inventory-file` is for structured imported inventory.

`--targets-file` remains the lowest-common simple host-list input:

- one host or IP per line
- blank lines allowed
- `#` comments allowed
- no ports in the file
- `--ports` required

That split keeps the public contract honest. `--inventory-file` should not be
taught a second weaker line-list grammar.

## Current input forms

Structured imported inventory supports:

- YAML
- JSON
- constrained CSV

Those are the right generic file forms before `v1.0.0`.

Platform-specific import adapters should come later, on top of the same
internal model, rather than driving the generic contract now.

## Current manifest model

The structured manifest schema stays narrow intentionally.

Recommended YAML shape:

```yaml
version: 1
entries:
  - host: api.example.com
    ports: [443, 8443]
    name: Payments API
    owner: payments
    environment: prod
    tags:
      - external
      - critical
    notes: Internet-facing service
```

Recommended JSON shape:

```json
{
  "version": 1,
  "entries": [
    {
      "host": "api.example.com",
      "ports": [443, 8443],
      "name": "Payments API",
      "owner": "payments",
      "environment": "prod",
      "tags": ["external", "critical"],
      "notes": "Internet-facing service"
    }
  ]
}
```

Recommended CSV header set:

```csv
host,ports,name,owner,environment,tags,notes
api.example.com,"443,8443",Payments API,payments,prod,"external,critical",Internet-facing service
```

Per-entry fields:

- required:
  - `host` or `address`
- optional:
  - `ports`
  - `name`
  - `owner`
  - `environment`
  - `tags`
  - `notes`

Do not add in this layer:

- nested scanner configuration
- arbitrary user-defined metadata maps
- multiple competing structured manifest schemas

## Port rules

Structured imported inventory supports optional per-entry ports, because
real inventory exports often already know service surface.

The rules should be explicit:

- imported entries may carry optional `ports`
- `--ports` may also be supplied at the CLI
- if `--ports` is supplied, it overrides imported entry ports for the run
- if `--ports` is omitted, imported entry ports are used
- if neither is present for an entry, that entry is invalid

This keeps run-level control available without forcing every imported inventory
into one global port set.

## Canonical internal model

Surveyor uses one stable internal model for imported inventory, not a
collection of vendor-shaped flows.

That model should cover:

- imported target identity
- imported metadata
- provenance
- normalisation
- deduplication

Important boundary:

- execution scope stays execution scope
- imported metadata should not be crammed directly into the remote execution
  contract

The better shape is:

- `RemoteScope` remains focused on executable scope
- a separate imported-inventory or inventory-annotation model carries the
  structured metadata and provenance
- imported entries compile into executable host-port targets plus attached
  inventory context

## Provenance

Every imported entry should record where it came from.

Current provenance fields:

- `source_kind = inventory_file`
- `source_format = yaml | json | csv`
- `source_name = inventory.yaml`
- `source_record = entries[3]` or equivalent stable reference

That provenance should survive:

- inventory parsing
- remote discovery
- remote audit
- report output where relevant

## Normalisation and deduplication

Imported inventories will be messy. The first release needs clear rules.

### Host normalisation

Use the same conservative host normalisation model already used for remote
scope:

- canonicalise IP literals via `netip`
- lower-case hostnames

### Deduplication

Use stable host identity for imported target deduplication:

- canonical IP literals via `netip`
- lower-case hostnames

Current rules:

- exact duplicate entries collapse
- duplicate entries for the same host may merge port sets deterministically
- duplicates with conflicting non-port metadata fail clearly
- deterministic ordering follows first valid appearance in the manifest

Do not silently merge conflicting owner, environment or note fields in the
first release.

## Reporting and analysis implications

The imported inventory layer should preserve existing product discipline:

- declared scope first
- observed facts second
- conservative hints third
- selection decisions fourth
- verified TLS results only for the supported subset

For inventory-backed remote reports, Surveyor now includes:

- top-level `input_kind=inventory_file`
- `inventory_file` when relevant
- per-endpoint imported annotation fields where present
- provenance where present

The existing reporting rule should remain unchanged:

- JSON is canonical
- Markdown is derived

This layer does not redesign `diff` or `prioritize`. It only adds the minimum
needed so imported inventory is usable with the existing analysis layer.

## Non-goals

This layer does not include:

- live cloud connectors
- CMDB APIs
- passive ingestion
- a database
- a dashboard
- another deep scanner
- policy-engine expansion
- organisation-wide aggregation
- platform-native output formats

## Relationship to later adapter work

The generic ingestion substrate now exists before vendor-specific adapters.

That means:

- `v0.7.0` focuses on generic imported inventory support
- `v0.9.0` is the right place for the first stable platform-specific adapters

The first stable adapter set should stay narrow:

- Caddy JSON
- Kubernetes Ingress v1 manifests

Important boundary:

- not generic Kubernetes
- not `Service` import
- not Gateway API
- not live cloud or CMDB connectors

Those adapters should extend the existing `--inventory-file` path with
explicit adapter selection, not replace the generic imported-inventory model.

Examples of later, broader adapter work:

- AWS-style exports
- Azure-style exports
- GCP-style exports
- CMDB exports
- certificate inventory exports

That sequencing keeps the hard architectural work in the generic layer and
turns later platform support into adapter work instead of a core rewrite.
