# Audit

Audit is the current orchestration layer built on top of the discovery foundation.

It exists to answer a different question from `surveyor discover local`:

given the endpoints this machine is exposing locally, which of them should Surveyor hand off to a supported scanner, what was actually verified, and what was skipped?

## Why audit exists

Surveyor now has two separate implemented primitives:

- `surveyor discover local`
- `surveyor scan tls`

That is enough to collect local endpoint facts and to run verified TLS inventory against explicit targets.

Surveyor now has the workflow that joins them together:

- run local discovery first
- decide which discovered endpoints are worth TLS scanning
- hand the supported subset into the existing TLS scanner
- emit one combined report

That is the purpose of `audit local`.

## Command

The audit command is:

```bash
surveyor audit local
```

This command turns the current discovery and TLS slices into one usable local audit workflow.

## Command semantics

The semantics of `surveyor audit local` are:

- run local discovery first
- preserve discovered endpoint facts and protocol hints
- select supported scanners conservatively
- hand selected endpoints into existing scanner implementations
- record verified scan results separately from discovery results
- record skipped endpoints and the reason they were skipped
- emit canonical JSON and derived Markdown

This command should follow the same output conventions as the existing CLI:

- `-o, --output` for Markdown output
- `-j, --json` for JSON output
- Markdown to stdout when no output path is given

## Scope

The current audit flow covers:

- local-only execution
- discovery-first orchestration
- conservative TLS-candidate selection
- automatic handoff only to the existing TLS scanner
- one combined report covering both discovery and verified scan results
- explicit skip reasons for unscanned endpoints

The current audit flow does not cover:

- remote discovery
- subnet or range scanning
- non-TLS deep scanners
- aggressive probing
- broad vulnerability-scanner behaviour
- enterprise-wide orchestration

## Facts, hints, selections and scans

Audit must keep five things separate:

1. discovered endpoint facts
2. protocol hints
3. scanner selection decisions
4. verified scan results
5. skipped endpoints and reasons

Examples:

- `transport=tcp`, `address=0.0.0.0`, `port=443` are discovered facts
- `protocol=tls` with low confidence is a hint
- `selected_scanner=tls` is a selection decision
- negotiated TLS version, cipher suite and certificate metadata are verified scan results
- `skip_reason=no supported scanner for udp endpoint` is a skip outcome

Hints are not scans, and scanner selection is not verification.

## Audit schema

Audit should follow the same output philosophy as the current TLS and discovery slices:

- JSON is canonical
- Markdown is derived from the canonical model

### Top-level report

Current top-level audit report shape:

```json
{
  "generated_at": "2026-04-16T02:00:00Z",
  "results": [],
  "summary": {}
}
```

Fields:

- `generated_at`: RFC3339 UTC timestamp for report assembly time
- `results`: one entry per discovered endpoint considered by the audit flow
- `summary`: aggregate counts derived from `results`

### Audit result

Current per-endpoint audit result shape:

```json
{
  "discovered_endpoint": {},
  "selection": {},
  "tls_result": {}
}
```

Fields:

- `discovered_endpoint`: the discovered endpoint facts and hints as produced by the discovery layer
- `selection`: the scanner decision for this endpoint, including skipped outcomes
- `tls_result`: verified TLS result when the endpoint was selected for the TLS scanner and the scan ran

### Selection

Current selection shape:

```json
{
  "status": "selected",
  "selected_scanner": "tls",
  "reason": "tls hint on tcp/443"
}
```

Fields:

- `status`: selection outcome, initially `selected` or `skipped`
- `selected_scanner`: scanner identifier when selected, initially `tls`
- `reason`: explicit explanation for the decision

Skipped example:

```json
{
  "status": "skipped",
  "reason": "no supported scanner for udp endpoint"
}
```

### Verified TLS result

When an endpoint is selected for TLS scanning, `tls_result` should embed the current canonical TLS result model rather than inventing a parallel TLS schema.

That means audit should reuse the existing target-result contract documented in [docs/output-schema.md](output-schema.md).

### Summary

Current summary shape:

```json
{
  "total_endpoints": 3,
  "tls_candidates": 1,
  "scanned_endpoints": 1,
  "skipped_endpoints": 2,
  "selection_breakdown": {
    "tls": 1
  },
  "verified_classification_breakdown": {
    "modern_tls_classical_identity": 1
  }
}
```

Fields:

- `total_endpoints`: total number of discovered endpoints considered by the audit flow
- `tls_candidates`: endpoints selected for the TLS scanner
- `scanned_endpoints`: endpoints for which a supported scanner actually ran
- `skipped_endpoints`: endpoints not scanned
- `selection_breakdown`: counts keyed by selected scanner
- `verified_classification_breakdown`: counts keyed by verified TLS classification where a TLS scan completed

## Safety model

`audit local` should stay conservative.

It should:

- rely on local discovery rather than remote probing
- only hand off to supported scanners intentionally
- preserve the difference between hinting and verification
- avoid implying that unsupported endpoints were fully assessed

The audit flow performs real scanner activity on selected endpoints, but only within the scope of the scanners it explicitly invokes.

## Relationship to future work

`audit local` is the first complete workflow in Surveyor.

After that, future work may expand into:

- additional supported scanners
- stronger candidate-selection logic
- richer combined reporting
- later, broader orchestration models

The current boundary should stay focused on local discovery chained into the existing TLS scanner.
