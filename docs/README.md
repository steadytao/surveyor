<div align="center">
  <img src="../.github/banner.svg" alt="BANNER" width="720">
</div>

# Surveyor Documentation

This directory is a map of the Surveyor docs set.

For the product overview, canonical command surface and current contract
summary, start with [../README.md](../README.md).

## Using Surveyor

- [discovery.md](discovery.md), `surveyor discover` command semantics, output shape and examples
- [audit.md](audit.md), `surveyor audit` command semantics, output shape and examples
- [remote-scope.md](remote-scope.md), declared remote scope under `discover remote` and `audit remote`
- [remote-inventory.md](remote-inventory.md), remote discovery and audit behaviour over explicit remote scope
- [inventory-inputs.md](inventory-inputs.md), generic structured inventory input contract
- [safety.md](safety.md), scope, probing and output-safety boundaries

## Contracts And Analysis

- [output-schema.md](output-schema.md), canonical JSON schema and stability notes
- [baselines.md](baselines.md), baseline header model and compatibility rules
- [diffing.md](diffing.md), supported diff inputs, report shape and workflow controls
- [prioritisation.md](prioritisation.md), prioritisation profiles, item model and workflow grouping
- [policy-workflows.md](policy-workflows.md), workflow grouping, filtering, grouped summaries and workflow findings
- [classification.md](classification.md), conservative classification buckets and recognised algorithm sets

## Import Adapters

- [import-adapters.md](import-adapters.md), top-level adapter boundary and supported adapter set
- [adapter-contract.md](adapter-contract.md), adapter expectations, provenance and warning rules
- [adapter-caddy.md](adapter-caddy.md), Caddy JSON and Caddyfile support details
- [adapter-kubernetes.md](adapter-kubernetes.md), Kubernetes Ingress v1 support details

## Architecture And References

- [architecture.md](architecture.md), package responsibilities, data flow and architectural boundaries
- [references.md](references.md), external standards and migration references

## Release Surface

- [release-checklist.md](release-checklist.md), release readiness bar
- [releases/](releases/), checked-in release notes for published versions
