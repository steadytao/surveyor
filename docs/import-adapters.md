# Import Adapters

This document defines the planned `v0.9.0` adapter layer.

It does not describe current shipped behaviour.

Surveyor already has a generic imported-inventory path through
`--inventory-file`. The next layer should let Surveyor ingest selected
platform-native inputs while still mapping everything into the same canonical
imported-inventory model used by the current generic YAML, JSON and CSV forms.

## What an adapter is

An adapter is a parser and mapper for an external product's configuration or
resource format.

Its job is to:

- understand the source format using the product's own documented semantics
- map the source into Surveyor's canonical imported-inventory model
- preserve provenance and warnings
- feed the existing `discover remote` and `audit remote` workflow

## What an adapter is not

An adapter is not:

- a second remote scope model
- a second output format
- a live connector
- proof that an imported target is reachable or externally exposed
- a claim that platform intent equals verified TLS posture

## First supported sources

`v0.9.0` should start with two source families:

- Caddy JSON
- Kubernetes Ingress v1 manifests

Those are the right first sources because they are stable, externally defined
and map cleanly enough into Surveyor's remote inventory model.

Follow-on input surfaces may arrive later only if they fit the same contract
without weakening it. Examples include:

- Caddyfile, as translated Caddy input rather than the canonical Caddy source
- broader Kubernetes-derived hints such as Service and Secret references

## Design rule

The external format must not become the internal model.

The correct flow is:

external format
-> adapter parser
-> canonical imported inventory
-> existing Surveyor discovery, audit, diff and prioritisation flow

That is why adapter implementations should be grounded in official product
documentation while Surveyor's own documentation stays focused on the canonical
imported-inventory model and its downstream behaviour.

## Provenance and compatibility

Every adapter-derived target should preserve enough source context for a human
to trace it back to its origin.

At minimum that means:

- source platform
- source file
- source object or record identity where practical
- adapter warnings
- mapping-relevant metadata

Compatibility rules belong to Surveyor's canonical model, not the external
product shape. Adapters should conform to the model rather than teaching the
rest of Surveyor product-specific semantics.
