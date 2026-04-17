<div align="center">
  <img src="../.github/banner.svg" alt="BANNER" width="720">
</div>

# Adapter Contract

This document defines the current adapter boundary for `v0.9.0`.

## Contract goal

Adapters parse a supported external source, emit canonical imported inventory
plus provenance and warnings, then hand that output to the existing remote
workflow.

## Interface expectations

An adapter defines:

- adapter name
- supported source forms
- parse and validation rules
- mapping rules into canonical imported inventory
- provenance requirements
- warning and error rules
- duplicate and conflict behaviour

Adapter-specific execution inputs, such as an external helper executable path,
remain outside the canonical imported-inventory model.

## Required canonical output

Adapter output must provide enough information to produce canonical imported
targets with:

- host or address
- relevant ports when they can be derived honestly
- provenance
- adapter warnings

If the external source does not support a clean mapping, the adapter should
emit a warning or fail clearly rather than inventing certainty.

## Optional metadata

Where the source provides it cleanly, adapters may attach metadata such as:

- name
- owner or team
- environment
- tags
- notes
- source object identity
- TLS-related hints

Optional metadata must not be required for a valid import.

## Warnings and errors

Warnings are for partially useful input that still maps into the canonical
model, but with caveats.

Errors are for input that cannot be mapped honestly or safely.

Warnings should be explicit when:

- host or port mapping is ambiguous
- controller-specific behaviour materially affects meaning
- multiple source objects collapse to one imported endpoint
- the source implies routing intent but not verified TLS exposure

## Provenance requirements

At minimum, provenance should preserve:

- source platform
- source file
- source object or record identity where practical
- source format

Adapters may add further context, but they should not depend on downstream
code understanding product-specific structures.

## Deduplication expectations

Deduplication still happens against Surveyor's canonical imported-target model.

That means:

- identity rules stay canonical
- duplicate collapse stays deterministic
- conflicts remain explicit
- adapter-specific detail does not redefine target identity

## Command integration

Adapters extend the existing `--inventory-file` path.

Current command integration:

- `surveyor discover remote`
- `surveyor audit remote`
- `--adapter NAME` for explicit adapter selection
- `--adapter-bin PATH` for explicit external executable selection when needed

They do not introduce a second import command family.
