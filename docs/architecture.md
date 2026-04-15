# Architecture

Surveyor is intentionally small at this stage.

The current codebase is organised around one narrow flow:

1. enumerate local endpoints for discovery, or accept explicit TLS targets from config or direct CLI input
2. collect observed endpoint facts or raw TLS and X.509 observations
3. attach conservative hints or classify the observed posture conservatively
4. derive canonical JSON and human-readable Markdown from the same result model

That separation matters. Surveyor should not blur raw observation, interpretation and reporting into one package.

## Package responsibilities

### `cmd/surveyor`

Owns the thin executable wrapper.

Current responsibilities:

- expose `surveyor discover local`
- expose `surveyor scan tls`
- run the discovery flow end to end
- accept either config-driven targets or explicit `--targets` input
- run the TLS inventory flow end to end
- write Markdown and JSON outputs

This layer should stay thin. It should orchestrate existing packages, not reimplement their logic.

Planned next responsibility:

- expose `surveyor audit local`
- orchestrate discovery and supported scanner handoff without embedding scanner logic in the CLI layer

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

### `internal/discovery`

Owns local discovery and endpoint enrichment.

Current responsibilities:

- enumerate local TCP listening endpoints and UDP bound endpoints
- attach best-effort process metadata where available
- attach conservative protocol hints based on observed facts

This package should stay observational. It should not perform active probing or scanner-specific verification.

### `internal/audit`

Planned responsibility:

- orchestrate local discovery into supported scanner execution
- record selection decisions and skip reasons
- preserve the distinction between discovered facts, hints and verified scan results

This layer should coordinate existing components rather than reimplement discovery or scanner internals.

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

- build top-level reports from target results and discovery results
- derive summary counts
- render canonical JSON
- render Markdown from the same canonical model

JSON is the source of truth. Markdown is derived output.

## Data flow

The current TLS data flow is:

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

The current discovery flow is:

```text
CLI arguments
  -> cmd/surveyor
  -> internal/discovery
  -> []core.DiscoveredEndpoint
  -> internal/outputs.BuildDiscoveryReport
  -> core.DiscoveryReport
  -> JSON / Markdown rendering
```

The planned local audit flow is:

```text
CLI arguments
  -> cmd/surveyor
  -> internal/discovery
  -> []core.DiscoveredEndpoint
  -> internal/audit selection logic
  -> supported scanner handoff
  -> []core.AuditResult
  -> internal/outputs.BuildAuditReport
  -> core.AuditReport
  -> JSON / Markdown rendering
```

## What must remain true

The following invariants must remain true as the project grows:

- config parsing stays separate from scanning
- collection records observed facts before interpretation
- classification does not invent evidence that was not observed
- JSON remains canonical
- Markdown does not contain facts absent from the canonical report model
- ambiguous observations fall back to manual review rather than overclaiming certainty

## What is not implemented yet

The current architecture still does not include:

- trust-store validation
- hostname validation semantics
- discovery-to-scan orchestration
- STARTTLS or multi-protocol probing
- discovery across ranges or cloud inventories
- policy engines
- stateful storage or diffing

Those are separate steps and should only be added once the current TLS path remains coherent.

## Current architectural boundary

The current discovery layer around `surveyor discover local` sits beside scanner-specific execution, not inside it.

Its job is to:

- enumerate candidate local endpoints
- describe them in a stable canonical model
- attach conservative protocol hints
- stay distinct from scanner-specific verification

That boundary should remain intact. Future audit flows should coordinate discovery, selection and verified scanning without collapsing them into one indistinguishable result type.
