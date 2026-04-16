# Architecture

Surveyor is intentionally small at this stage.

The current codebase is organised around one narrow family of flows:

1. enumerate local endpoints, enumerate explicitly declared remote scope, or accept explicit TLS targets from config or direct CLI input
2. collect observed endpoint facts or raw TLS and X.509 observations
3. attach conservative hints or classify the observed posture conservatively
4. derive canonical JSON and human-readable Markdown from the same result model

That separation matters. Surveyor should not blur raw observation, interpretation and reporting into one package.

## Package responsibilities

### `cmd/surveyor`

Owns the thin executable wrapper.

Current responsibilities:

- expose `surveyor audit local`
- expose `surveyor audit remote`
- preserve `surveyor audit subnet` as a CIDR-only compatibility alias from `v0.4.x`
- expose `surveyor discover local`
- expose `surveyor discover remote`
- preserve `surveyor discover subnet` as a CIDR-only compatibility alias from `v0.4.x`
- expose `surveyor scan tls`
- run the audit flow end to end
- run the discovery flow end to end
- accept either config-driven targets or explicit `--targets` input
- validate remote scope and dry-run plans
- run the TLS inventory flow end to end
- write Markdown and JSON outputs

This layer should stay thin. It should orchestrate existing packages, not reimplement their logic.

### `internal/config`

Owns the input contract.

Current responsibilities:

- parse YAML configuration
- validate required fields
- normalise target data into one in-memory representation
- parse and validate remote scope
- enforce remote pace and safety controls such as host caps, concurrency and timeout defaults

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

Owns discovery and endpoint enrichment.

Current responsibilities:

- enumerate local TCP listening endpoints and UDP bound endpoints
- enumerate explicitly declared remote TCP scope with bounded reachability probing
- attach best-effort process metadata where available
- attach conservative protocol hints based on observed facts

This package should stay discovery-scoped. It should not perform scanner-specific verification. For local scope that means purely observational listener inspection; for remote scope that means bounded reachability probing within explicitly declared scope.

### `internal/audit`

Current responsibilities:

- orchestrate local and remote discovery into supported scanner execution
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

- build top-level reports from target results, discovery results and audit results
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

The current remote discovery flow is:

```text
CLI arguments
  -> cmd/surveyor
  -> internal/config.ParseRemoteScope
  -> internal/discovery.RemoteEnumerator
  -> []core.DiscoveredEndpoint
  -> internal/outputs.BuildDiscoveryReport
  -> core.DiscoveryReport
  -> JSON / Markdown rendering
```

The current local audit flow is:

```text
CLI arguments
  -> cmd/surveyor
  -> internal/audit.LocalRunner
  -> internal/discovery
  -> []core.DiscoveredEndpoint
  -> internal/audit selection logic
  -> supported TLS scanner handoff
  -> []core.AuditResult
  -> internal/outputs.BuildAuditReport
  -> core.AuditReport
  -> JSON / Markdown rendering
```

The runner reuses the same target validation and TLS scanner path as explicit
`surveyor scan tls` execution. Local audit should be orchestration, not a
parallel scanner implementation.

The current remote audit flow is:

```text
CLI arguments
  -> cmd/surveyor
  -> internal/config.ParseRemoteScope
  -> internal/audit.RemoteRunner
  -> internal/discovery.RemoteEnumerator
  -> []core.DiscoveredEndpoint
  -> internal/audit selection logic
  -> supported TLS scanner handoff
  -> []core.AuditResult
  -> internal/outputs.BuildAuditReport
  -> core.AuditReport
  -> JSON / Markdown rendering
```

Remote audit reuses the same selection and TLS scanner handoff path as local
audit. The difference is the discovery source and scope contract, not a second
TLS implementation.

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
- STARTTLS or multi-protocol probing
- remote scope inputs beyond the current explicit CIDR path and simple file-backed host path
- organisation-wide or cloud inventory discovery
- policy engines
- stateful storage or diffing

Those are separate steps and should only be added once the current TLS path remains coherent.

Scoped remote inventory with canonical `remote` commands is now part of the current repository surface. See [docs/remote-inventory.md](remote-inventory.md) and [docs/remote-scope.md](remote-scope.md) for the current boundary.

## Current architectural boundary

The current discovery layer around `surveyor discover local`, `surveyor discover remote` and the `surveyor discover subnet` compatibility alias sits beside scanner-specific execution, not inside it.

Its job is to:

- enumerate candidate local or remote endpoints within declared scope
- describe them in a stable canonical model
- attach conservative protocol hints
- stay distinct from scanner-specific verification

That boundary should remain intact. The current audit flows coordinate discovery, selection and verified scanning without collapsing them into one indistinguishable result type.

## Current remote scope model

The current remote model is:

- canonical `discover remote` and `audit remote` commands
- support for both `--cidr` and `--targets-file`
- `discover subnet` and `audit subnet` retained as CIDR-only compatibility aliases during `v0.5.x`

That widens the remote scope model without weakening the existing discovery, hinting, selection and verified-scanning boundaries.
