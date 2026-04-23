<div align="center">
  <img src="../.github/banner.svg" alt="BANNER" width="720">
</div>

# Architecture

Surveyor is intentionally small at this stage.

Material architecture and project-boundary decisions are also recorded in the ADR set under [decisions/](decisions/README.md).

The current codebase is organised around one narrow family of flows:

1. enumerate local endpoints, enumerate explicitly declared remote scope, or accept explicit TLS targets from config or direct CLI input
2. collect observed endpoint facts or raw TLS and X.509 observations
3. attach conservative hints or classify the observed posture conservatively
4. derive canonical JSON and human-readable Markdown from the same result model

That separation matters. Surveyor should not blur raw observation, interpretation and reporting into one package.

## Package Responsibilities

### `cmd/surveyor`

Owns the thin executable wrapper.

Current responsibilities:

- expose `surveyor diff`
- expose `surveyor prioritize`
- support `surveyor prioritise` as a CLI alias
- expose `surveyor audit local`
- expose `surveyor audit remote`
- preserve `surveyor audit subnet` as a CIDR-only compatibility alias from `v0.4.x`
- expose `surveyor discover local`
- expose `surveyor discover remote`
- preserve `surveyor discover subnet` as a CIDR-only compatibility alias from `v0.4.x`
- expose `surveyor scan tls`
- run the audit flow end to end
- run the discovery flow end to end
- run the diff flow end to end
- run the prioritisation flow end to end
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

### `internal/inventory`

Owns structured imported-inventory parsing and normalisation.

Current responsibilities:

- parse YAML, JSON and constrained CSV inventory files
- validate the narrow manifest schema
- normalise hosts, ports and tags deterministically
- preserve source provenance
- collapse exact duplicates and reject conflicting duplicate metadata

This package should stay import-focused. It should normalise approved external inventory into one stable internal shape rather than grow vendor-specific adapter logic into the core.

The current adapter layer sits above this package, not inside its generic
normalisation core. `internal/inventory` remains the canonical generic
normalisation boundary while current adapter implementations add product-aware
parsing on top of it.

### `internal/core`

Owns the canonical result model shared across the rest of the project.

Current responsibilities:

- define severities
- define findings
- define certificate references
- define per-target results
- define report summaries and top-level reports

`internal/core` should not become a dumping ground for scanner logic or renderer-specific behaviour.

### `internal/baseline`

Owns baseline parsing and comparison preconditions.

Current responsibilities:

- parse canonical Surveyor report headers from saved JSON
- validate required baseline-compatible metadata
- enforce supported comparison boundaries
- generate stable identity keys for TLS, discovery and audit entities

This package should stay comparison-focused. It should validate whether reports can be compared before the diff engine starts interpreting them.

### `internal/diff`

Owns canonical report comparison.

Current responsibilities:

- compare compatible saved reports
- assemble canonical diff reports
- categorise supported change types
- keep change ordering deterministic

This package should stay narrow. It should explain supported change, not become a policy or prioritisation engine.

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
- build top-level diff and prioritisation reports for output tests and examples
- derive summary counts
- render canonical JSON
- render Markdown from the same canonical model

JSON is the source of truth. Markdown is derived output.

### `internal/prioritize`

Owns current-report ranking and workflow-oriented interpretation over current reports.

Current responsibilities:

- rank current TLS and audit reports
- apply the `migration-readiness` and `change-risk` profiles
- refine inventory-backed audit ranking with owner, environment and tag context
- emit deterministic prioritisation items, workflow findings and optional grouped summaries

This package should stay a lightweight decision-support layer. It should rank current evidence, not pretend to be a full policy engine.

## Data Flow

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

The current diff flow is:

```text
saved canonical JSON reports
  -> cmd/surveyor
  -> internal/baseline
  -> internal/diff
  -> diff.Report
  -> JSON / Markdown rendering
```

That boundary matters. Compatibility validation belongs in `internal/baseline`;
change interpretation belongs in `internal/diff`.

The current prioritisation flow is:

```text
saved canonical JSON report
  -> cmd/surveyor
  -> internal/prioritize
  -> prioritize.Report
  -> JSON / Markdown rendering
```

The first prioritisation release operates on current reports, not diff reports.
That keeps ranking logic narrower and easier to defend.

## What Must Remain True

The following invariants must remain true as the project grows:

- config parsing stays separate from scanning
- collection records observed facts before interpretation
- classification does not invent evidence that was not observed
- JSON remains canonical
- Markdown does not contain facts absent from the canonical report model
- ambiguous observations fall back to manual review rather than overclaiming certainty

## What Is Not Implemented Yet

The current architecture still does not include:

- trust-store validation
- hostname validation semantics
- STARTTLS or multi-protocol probing
- organisation-wide or cloud inventory discovery
- discovery-only diffing
- diff-input prioritisation
- policy engines
- stateful storage

Those are separate steps and should only be added once the current TLS path remains coherent.

Scoped remote inventory with canonical `remote` commands is now part of the current repository surface. See [../commands/remote-inventory.md](../commands/remote-inventory.md) and [../commands/remote-scope.md](../commands/remote-scope.md) for the current boundary.

## Current Architectural Boundary

The current discovery layer around `surveyor discover local`, `surveyor discover remote` and the `surveyor discover subnet` compatibility alias sits beside scanner-specific execution, not inside it.

Its job is to:

- enumerate candidate local or remote endpoints within declared scope
- describe them in a stable canonical model
- attach conservative protocol hints
- stay distinct from scanner-specific verification

That boundary should remain intact. The current audit flows coordinate discovery, selection and verified scanning without collapsing them into one indistinguishable result type.

## Current Remote Scope Model

The current remote model is:

- canonical `discover remote` and `audit remote` commands
- support for `--cidr`, `--targets-file` and `--inventory-file`
- `discover subnet` and `audit subnet` retained as CIDR-only compatibility aliases from `v0.4.x`

That widens the remote scope model without weakening the existing discovery, hinting, selection and verified-scanning boundaries.

Structured imported inventory now sits on top of the same remote model rather than introducing a second remote command family. See [../contracts/inventory-inputs.md](../contracts/inventory-inputs.md) for the current contract.

The current adapter layer extends the same `inventory_file` path with explicit
adapter selection rather than introducing a parallel import-specific command
family. See [../adapters/README.md](../adapters/README.md) and
[../adapters/contract.md](../adapters/contract.md) for the current contract.

## Current Analysis Layer

The current analysis layer sits on top of the canonical JSON reports:

- baseline-compatible metadata on current report shapes
- compatibility validation for supported comparisons
- `surveyor diff`
- `surveyor prioritize`
- `surveyor prioritise` as a CLI alias
- inventory-aware workflow grouping and filtering for audit analysis
- grouped summaries in diff and prioritisation output
- workflow findings in prioritisation output for weak imported metadata

Current limits remain deliberate:

- diffing is currently supported for `tls_scan` and `audit` only
- prioritisation is currently supported for current `tls_scan` and `audit` reports only
- workflow grouping and filtering apply only to inventory-backed audit input or audit comparisons
- TLS input rejects workflow controls
- discovery-only diffing is still deferred
- diff-input prioritisation is still deferred

That workflow layer remains output- and interpretation-focused. It does not rewrite the underlying technical diff model or collapse observed facts into policy claims.

The current `v0.9.0` adapter layer is import-focused:

- explicit adapter selection
- stable adapter provenance and warnings
- Caddy JSON and Caddyfile support through the `caddy` adapter
- Kubernetes Ingress v1 manifests through the `kubernetes-ingress-v1` adapter

Current limits remain deliberate:

- no live connectors
- no generic Kubernetes parser
- no weakened generic imported-inventory boundary

See:

- [../contracts/baselines.md](../contracts/baselines.md)
- [../contracts/diffing.md](../contracts/diffing.md)
- [../contracts/prioritisation.md](../contracts/prioritisation.md)
- [../contracts/policy-workflows.md](../contracts/policy-workflows.md)
- [../adapters/README.md](../adapters/README.md)
- [../adapters/contract.md](../adapters/contract.md)
- [../adapters/caddy.md](../adapters/caddy.md)
- [../adapters/kubernetes.md](../adapters/kubernetes.md)
