# Adapter: Caddy

This document defines the current `v0.9.0` Caddy adapter.

## External references

Implementation is grounded in Caddy's official documentation:

- Caddy JSON config, as the native config form
- Caddy API, for operational context
- Caddyfile docs and concepts
- config adapter docs, for how Caddyfile input maps back into Caddy JSON

Surveyor understands those semantics at the adapter boundary, but still maps
them into Surveyor's canonical imported-inventory model.

## Current supported source forms

The current `caddy` adapter supports:

- Caddy JSON
- Caddyfile

Important boundary:

- Caddy JSON remains the canonical Caddy source
- Caddyfile is supported as translated Caddy input, not as a second internal
  Surveyor model

## Current command surface

Examples:

```bash
surveyor discover remote --inventory-file examples/caddy.json --adapter caddy
surveyor audit remote --inventory-file Caddyfile
surveyor audit remote --inventory-file site.conf --adapter caddy
surveyor audit remote --inventory-file Caddyfile --adapter-bin /path/to/caddy
```

Current Caddyfile convenience:

- `Caddyfile` and `*.caddyfile` auto-detect the `caddy` adapter
- non-standard names such as `site.conf` require explicit `--adapter caddy`

## External executable boundary

Caddy JSON support is in-process.

Caddyfile support is implemented by invoking:

```text
caddy adapt --adapter caddyfile
```

Binary resolution order:

- `--adapter-bin`
- `SURVEYOR_CADDY_BIN`
- `PATH`
- common install locations

That keeps full Caddyfile semantics available without embedding Caddy's module
graph into the main Surveyor binary.

## What Surveyor extracts

The Caddy adapter extracts conservatively:

- declared hostnames
- listener addresses and relevant ports
- site, server or route identity where useful
- source file provenance
- enough record identity to trace a mapped target back to a Caddy config block

## What Surveyor should not overclaim

The adapter does not claim:

- verified reachability
- confirmed public exposure
- final certificate state
- effective runtime behaviour beyond what the config expresses clearly

Surveyor still needs to run its own discovery and audit flow after import.

## Current warning cases

Warnings are explicit when:

- non-TCP listeners are ignored
- listener ports cannot be mapped cleanly
- wildcard or placeholder hosts are ignored
- Caddyfile adaptation emits warnings
- multiple config blocks collapse to one imported endpoint
