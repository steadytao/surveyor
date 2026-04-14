# Architecture

Surveyor is intentionally small at this stage.

The current codebase is organised around one narrow flow:

1. accept explicit TLS targets from config or direct CLI input
2. collect raw TLS and X.509 observations
3. classify the observed posture conservatively
4. derive canonical JSON and human-readable Markdown from the same result model

That separation matters. Surveyor should not blur raw observation, interpretation and reporting into one package.

## Package responsibilities

### `cmd/surveyor`

Owns the thin executable wrapper.

Current responsibilities:
- expose `surveyor scan tls`
- accept either config-driven targets or explicit `--targets` input
- run the TLS inventory flow end to end
- write Markdown and JSON outputs

This layer should stay thin. It should orchestrate existing packages, not reimplement their logic.

### `internal/config`

Owns the input contract.

Current responsibilities:
- parse YAML configuration
- validate required fields
- normalise target data into one in-memory representation

Current target model:
- required: `host`, `port`
- optional: `name`, `tags`

This package should stay strict. It is better for config files to be explicit than clever.

### `internal/core`

Owns the canonical result model shared across the rest of the project.

Current responsibilities:
- define severities
- define findings
- define certificate references
- define per-target results
- define report summaries and top-level reports

`internal/core` should not become a dumping ground for scanner logic or renderer-specific behaviour.

### `internal/scanners/tlsinventory`

Owns collection and first-pass classification for the TLS inventory slice.

Current responsibilities:
- establish a standard TLS connection to an explicit target
- record transport facts such as reachability, negotiated TLS version and cipher suite
- extract presented certificate-chain metadata
- classify the result into conservative migration-posture buckets

Important current design choices:
- certificate verification is deliberately disabled during collection so the scanner can observe what the service presents even when trust or hostname validation would fail
- SNI is only set for non-IP hosts
- classification is based on observed evidence only

This package should remain focused on TLS inventory. It should not grow into a generic protocol framework.

### `internal/outputs`

Owns report assembly and rendering.

Current responsibilities:
- build a top-level report from target results
- derive summary counts
- render canonical JSON
- render Markdown from the same canonical model

JSON is the source of truth. Markdown is derived output.

## Data flow

The current data flow is:

```text
CLI arguments
  -> cmd/surveyor
  -> internal/config or direct target parsing
  -> []config.Target
  -> internal/scanners/tlsinventory
  -> []core.TargetResult
  -> internal/outputs.BuildReport
  -> core.Report
  -> JSON / Markdown rendering
```

That flow is intentionally linear. It keeps the boundaries easy to reason about and easy to test.

## What must remain true

The following invariants must remain true as the project grows:
- config parsing stays separate from scanning
- collection records observed facts before interpretation
- classification does not invent evidence that was not observed
- JSON remains canonical
- Markdown does not contain facts absent from the canonical report model
- ambiguous observations fall back to manual review rather than overclaiming certainty

## What is not implemented yet

The current architecture does not yet include:
- trust-store validation
- hostname validation semantics
- STARTTLS or multi-protocol probing
- discovery across ranges or cloud inventories
- policy engines
- stateful storage or diffing

Those are separate steps and should only be added once the current TLS path remains coherent.
