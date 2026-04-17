# Platform-Specific Import Adapters

This document defines the planned `v0.9.0` adapter contract.

It does not describe current shipped behaviour.

The current repository already has a generic imported-inventory layer through
`--inventory-file`. The next step should be to add a small, stable set of
platform adapters on top of that substrate without changing Surveyor's
canonical JSON and Markdown contract.

## Goal

`v0.9.0` should let Surveyor consume stable platform exports directly and map
them into the same imported-inventory model already used by generic YAML, JSON
and CSV inventory files.

It should help answer:

- can I feed a Caddy config directly into the current remote model
- can I feed Kubernetes Ingress manifests directly into the current remote model
- can Surveyor preserve where each imported endpoint came from
- can it explain adapter limitations honestly

## Why this next

This is the right next layer after:

- generic imported inventory support
- saved-report diffing
- current-report prioritisation
- workflow grouping, filtering and metadata-aware interpretation

`v0.7.0` established the generic ingestion substrate.
`v0.8.0` made that metadata more useful for teams.
`v0.9.0` should make stable platform exports feed that same model directly.

## First stable adapter set

The first adapter set should stay deliberately small:

- `Caddy`
- `Kubernetes Ingress v1`

Important tightening:

- `Kubernetes` is too broad
- generic `Service` import is out
- Gateway API is out
- controller-specific CRDs are out
- live cloud or CMDB connectors are out

That keeps the adapter contract anchored to stable, standardised inputs before
`v1.0.0`.

## Planned command surface

The existing canonical remote commands should stay.

Recommended additions:

```bash
surveyor discover remote --inventory-file caddy.json --adapter caddy
surveyor audit remote --inventory-file caddy.json --adapter caddy

surveyor discover remote --inventory-file ingress.yaml --adapter kubernetes-ingress-v1
surveyor audit remote --inventory-file ingress.yaml --adapter kubernetes-ingress-v1
```

Important constraints:

- `--adapter` should be explicit in the first release
- autodetection can come later if it remains predictable
- the adapter should feed the existing `inventory_file` path
- do not add a second import-specific command family

## Adapter contract

This is the most important part of the milestone.

The adapter boundary should define:

- adapter name
- supported source shape
- canonical imported-target mapping rules
- provenance preservation rules
- adapter warning rules
- conflict and deduplication behaviour
- failure rules for invalid or unsupported input

Important boundaries:

- adapter output must be canonical imported inventory, not a parallel remote model
- provenance must preserve platform, file and source-record identity where practical
- adapter warnings must be explicit rather than implied
- adapter output must not overclaim exposure, reachability or TLS support

## Provenance and warnings

Every adapter-derived target should preserve:

- source platform
- source file
- source object or record identity where practical
- adapter warnings
- relevant original metadata that influenced normalisation

Warnings should be explicit when:

- host or port mapping is ambiguous
- the source implies routing but not clearly auditable TLS exposure
- multiple source objects collapse to one imported endpoint
- the source is internal-only or otherwise weakly mapped into Surveyor's model

## Caddy adapter

The `Caddy` adapter should map stable Caddy input into the canonical
imported-inventory model.

It should extract conservatively:

- declared hostnames
- relevant listener ports
- useful source labels where available
- source file and adapted record provenance

It should warn clearly when:

- host or port mapping is ambiguous
- the config is internal-only or not clearly auditable from Surveyor's remote model
- TLS intent cannot be mapped cleanly to a concrete imported endpoint

Important boundary:

- this is import, not proof of reachability
- Surveyor still runs its normal discovery and audit flow after import

## Kubernetes Ingress v1 adapter

The `Kubernetes Ingress v1` adapter should parse resources with:

- `apiVersion: networking.k8s.io/v1`
- `kind: Ingress`

It should extract conservatively:

- `spec.rules[].host`
- `spec.tls[].hosts[]`
- namespace and object identity
- source file provenance

It should warn clearly when:

- TLS coverage is ambiguous
- the manifest implies HTTP routing but not clearly auditable TLS exposure
- multiple objects collapse to one imported endpoint

Important boundary:

- this is not generic Kubernetes support
- this is not `Service` import
- this is not Gateway API or controller CRD support

## Relationship to the current model

The adapter layer should sit on top of the current generic imported-inventory
substrate:

- parse platform export
- map into canonical imported inventory
- compile into current remote execution scope
- reuse current discovery and audit flow
- reuse current diff, prioritisation and workflow layers

That is the point of doing adapters after the generic layer, not before it.

## Important boundaries

This milestone should not become:

- live cloud or CMDB connectors
- a second generic inventory model
- a dashboard
- a database
- policy-as-code
- another deep scanner milestone

Surveyor should keep:

- one canonical JSON output
- one derived Markdown output
- one remote command family

## Relationship to later work

The cleaner sequence after `v0.8.0` is:

- `v0.9.0` — stable platform-specific import adapters
- `v0.10.0` — contract hardening and feedback release
- `v1.0.0` — first stable narrow Surveyor contract

That keeps the first adapter set stable and defensible before broader or less
stable adapters are considered.
