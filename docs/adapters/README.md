<div align="center">
  <img src="../.github/banner.svg" alt="BANNER" width="720">
</div>

# Import Adapters

This document defines the current `v0.9.0` adapter layer.

Surveyor already had a generic imported-inventory path through
`--inventory-file`. The current adapter layer extends that path with selected
platform-native inputs while still mapping everything into the same canonical
imported-inventory model used by the generic YAML, JSON and CSV forms.

## What an Adapter Is

An adapter is a parser and mapper for an external product's configuration or
resource format.

Its job is to:

- understand the source format using the product's own documented semantics
- map the source into Surveyor's canonical imported-inventory model
- preserve provenance and warnings
- feed the existing `discover remote` and `audit remote` workflow

## What an Adapter Is Not

An adapter is not:

- a second remote scope model
- a second output format
- a live connector
- proof that an imported target is reachable or externally exposed
- a claim that platform intent equals verified TLS posture

## Current Supported Adapters

The current adapter set is:

- `caddy`
- `kubernetes-ingress-v1`

Current source forms:

- `caddy`
  - Caddy JSON
  - Caddyfile
- `kubernetes-ingress-v1`
  - Kubernetes Ingress v1 manifests in YAML or JSON

CLI surface:

- `--adapter caddy`
- `--adapter kubernetes-ingress-v1`
- `--adapter-bin PATH` when the selected adapter needs an external executable

Current Caddyfile convenience:

- `Caddyfile` and `*.caddyfile` auto-detect the `caddy` adapter when the file
  name is unambiguous

## Design Rule

The external format must not become the internal model.

The correct flow is:

external format
-> adapter parser
-> canonical imported inventory
-> existing Surveyor discovery, audit, diff and prioritisation flow

That is why adapter implementations should be grounded in official product
documentation while Surveyor's own documentation stays focused on the canonical
imported-inventory model and its downstream behaviour.

## Provenance and Compatibility

Every adapter-derived target should preserve enough source context for a human
to trace it back to its origin.

At minimum that means:

- source platform
- source file
- source object or record identity where practical
- source format
- adapter warnings

Compatibility rules belong to Surveyor's canonical model, not the external
product shape. Adapters should conform to the model rather than teaching the
rest of Surveyor product-specific semantics.

## Current Limits

Current limits remain deliberate:

- no live cloud or CMDB connectors
- no generic Kubernetes parser
- no second import command family
- no vendor-shaped output contract

Broader or less stable adapter work belongs later, after the current adapter
surface has been hardened.
