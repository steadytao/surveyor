# Adapter: Caddy

This document defines the planned `v0.9.0` Caddy adapter.

It does not describe current shipped behaviour.

## External references

Implementation should be grounded in Caddy's official documentation:

- Caddy JSON config, as the native config form
- Caddy API, for operational context
- Caddyfile docs and concepts, when translated input is supported later
- config adapter docs, for how non-JSON input maps back into Caddy JSON

Surveyor should understand those semantics, but it should still map them into
Surveyor's own canonical imported-inventory model.

## First supported source

The first Caddy source should be Caddy JSON.

That is the correct anchor because Caddy documents JSON as its native config
language, while the Caddyfile is a config adapter and is less expressive than
native JSON.

## Later source

Caddyfile support can arrive later, but only as translated Caddy input. It
should not become the canonical reference for the adapter.

## What Surveyor should extract

The Caddy adapter should extract conservatively:

- declared hostnames
- listener addresses and relevant ports
- site, server or route identity where useful
- source file provenance
- enough record identity to trace a mapped target back to a Caddy config block

## What Surveyor should not overclaim

The adapter should not claim:

- verified reachability
- confirmed public exposure
- final certificate state
- effective runtime behaviour beyond what the config expresses clearly

Surveyor still needs to run its own discovery and audit flow after import.

## Warning cases

Warnings should be explicit when:

- host or port mapping is ambiguous
- configuration is internal-only or not clearly auditable remotely
- multiple config blocks collapse to one imported endpoint
- TLS intent cannot be mapped cleanly to a concrete target
