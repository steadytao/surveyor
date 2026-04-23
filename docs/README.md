<div align="center">
  <img src="../.github/banner.svg" alt="BANNER" width="720">
</div>

# Surveyor Documentation

This directory is a map of the Surveyor docs set.

For the product overview, canonical command surface and current contract
summary, start with [../README.md](../README.md).

## Using Surveyor

- [commands/README.md](commands/README.md), command docs index
- [commands/discovery.md](commands/discovery.md), `surveyor discover` command semantics, output shape and examples
- [commands/audit.md](commands/audit.md), `surveyor audit` command semantics, output shape and examples
- [commands/remote-scope.md](commands/remote-scope.md), declared remote scope under `discover remote` and `audit remote`
- [commands/remote-inventory.md](commands/remote-inventory.md), remote discovery and audit behaviour over explicit remote scope
- [contracts/inventory-inputs.md](contracts/inventory-inputs.md), generic structured inventory input contract
- [reference/safety.md](reference/safety.md), scope, probing and output-safety boundaries

## Contracts and Analysis

- [contracts/README.md](contracts/README.md), contract docs index
- [contracts/output-schema.md](contracts/output-schema.md), canonical JSON schema and stability notes
- [contracts/baselines.md](contracts/baselines.md), baseline header model and compatibility rules
- [contracts/diffing.md](contracts/diffing.md), supported diff inputs, report shape and workflow controls
- [contracts/prioritisation.md](contracts/prioritisation.md), prioritisation profiles, item model and workflow grouping
- [contracts/policy-workflows.md](contracts/policy-workflows.md), workflow grouping, filtering, grouped summaries and workflow findings
- [contracts/classification.md](contracts/classification.md), conservative classification buckets and recognised algorithm sets

## Import Adapters

- [adapters/README.md](adapters/README.md), top-level adapter boundary and supported adapter set
- [adapters/contract.md](adapters/contract.md), adapter expectations, provenance and warning rules
- [adapters/caddy.md](adapters/caddy.md), Caddy JSON and Caddyfile support details
- [adapters/kubernetes.md](adapters/kubernetes.md), Kubernetes Ingress v1 support details

## Architecture, Decisions and References

- [architecture/README.md](architecture/README.md), package responsibilities, data flow and architectural boundaries
- [architecture/decisions/README.md](architecture/decisions/README.md), accepted project and architecture decisions
- [reference/README.md](reference/README.md), reference docs index
- [reference/references.md](reference/references.md), external standards and migration references

## Release Surface

- [releases/README.md](releases/README.md), release docs index
- [releases/checklist.md](releases/checklist.md), release readiness bar
- [releases/](releases/), checked-in release notes for published versions
