# Discovery

Discovery is the current foundation primitive that sits alongside the explicit-target TLS inventory slice.

It exists to answer a narrower question than `audit local`:

what endpoints is this machine exposing locally, and what conservative protocol hints can Surveyor attach before any scanner-specific verification runs?

## Why discovery exists

Surveyor already has one verified scanner path:

- `surveyor scan tls`

That path works when the operator already knows what to scan.

What Surveyor does not yet have is a discovery layer that can:

- enumerate candidate local endpoints
- describe them in a stable schema
- attach conservative protocol hints
- hand them off later to scanner-specific flows without collapsing discovery and scanning into one command

That is the purpose of discovery.

## Command

The discovery command is:

```bash
surveyor discover local
```

This command enumerates local listening or bound endpoints and emits structured output.

It is deliberately narrower than a future `audit local` command.

## Command semantics

The semantics of `surveyor discover local` are:

- enumerate local endpoints the current host is exposing
- report observed local facts
- attach conservative protocol hints where justified
- emit canonical JSON and derived Markdown
- avoid active probing or scanner-specific verification

This command should follow the same output conventions as `scan tls`:

- `-o, --output` for Markdown output
- `-j, --json` for JSON output
- Markdown to stdout when no output path is given

## Scope

Discovery currently covers:

- local-only endpoint enumeration
- TCP listening endpoints
- UDP bound endpoints
- best-effort process metadata where available
- conservative protocol hints with explicit confidence and evidence

Discovery does not cover:

- remote discovery
- arbitrary range scanning
- active probing
- automatic TLS or protocol handshakes
- broad host assessment
- vulnerability scanning
- automatic scan orchestration in the same command

## Facts, hints and scans

Discovery must keep three things separate:

1. observed endpoint facts
2. protocol hints
3. verified scan results

Examples:

- `transport=tcp`, `address=0.0.0.0`, `port=443` are observed facts
- `protocol=tls` with conservative confidence may be a hint
- negotiated TLS version, cipher suite and certificate metadata are verified scan results and belong to a scanner, not discovery

Hints are not scans.

## Discovery schema

Discovery should follow the same output philosophy as the current TLS slice:

- JSON is canonical
- Markdown is derived from the canonical model

### Top-level report

Current top-level discovery report shape:

```json
{
  "generated_at": "2026-04-15T03:00:00Z",
  "results": [],
  "summary": {}
}
```

Fields:

- `generated_at`: RFC3339 UTC timestamp for report assembly time
- `results`: one entry per discovered endpoint
- `summary`: aggregate counts derived from `results`

### Discovered endpoint

Current discovered-endpoint shape:

```json
{
  "address": "0.0.0.0",
  "port": 443,
  "transport": "tcp",
  "state": "listening",
  "pid": 1234,
  "process_name": "local-service",
  "executable": "C:\\Program Files\\Surveyor Test\\local-service.exe",
  "hints": [],
  "warnings": [],
  "errors": []
}
```

Fields:

- `address`: local bound address as observed
- `port`: local port number
- `transport`: transport name, initially `tcp` or `udp`
- `state`: observed local state, initially `listening` or `bound`
- `pid`: process identifier where available without requiring elevation
- `process_name`: best-effort process name where available
- `executable`: best-effort executable path where available and appropriate to expose
- `hints`: protocol hints derived conservatively from observed facts
- `warnings`: non-fatal discovery concerns or platform limitations
- `errors`: result-level failures where discovery for a specific endpoint could not be completed cleanly

### Hint

Planned hint shape:

```json
{
  "protocol": "tls",
  "confidence": "low",
  "evidence": [
    "transport=tcp",
    "port=443"
  ]
}
```

Fields:

- `protocol`: hinted protocol family, for example `tls`, `ssh` or `rdp`
- `confidence`: explicit qualitative confidence label
- `evidence`: observed facts supporting the hint

Confidence stays conservative. Discovery prefers understating certainty over implying protocol verification it has not performed.

### Summary

Current summary shape:

```json
{
  "total_endpoints": 2,
  "tcp_endpoints": 1,
  "udp_endpoints": 1,
  "hint_breakdown": {
    "tls": 1,
    "ssh": 1
  }
}
```

Fields:

- `total_endpoints`: total number of discovered results
- `tcp_endpoints`: count of TCP results
- `udp_endpoints`: count of UDP results
- `hint_breakdown`: count of results carrying each hinted protocol

## Platform expectations

Discovery aims to support:

- Linux
- macOS
- Windows

But the process metadata surface will not be equally strong on every platform or under every permission model.

That means:

- missing PID or process-name data must not fail discovery
- platform limitations should surface as warnings, not silent omissions where possible
- elevated access must not be required for the base discovery flow

## Safety model

Discovery should stay observational.

The discovery command should:

- inspect local listener state
- avoid active network probing
- avoid implying trust validation
- avoid implying protocol verification where only a hint exists

If future commands consume discovery output for scanner handoff, that should be a later layer and should be explicit in the CLI.

## Current examples

Representative example outputs live in:

- [examples/discovery.json](../examples/discovery.json)
- [examples/discovery.md](../examples/discovery.md)

## Relationship to future work

Discovery is the foundation for later work such as:

- a future `audit local` flow
- scanner handoff for endpoints that look TLS-like
- additional protocol-specific scanners

It is not itself the full audit layer.
