# Discovery

Discovery is the current foundation layer that sits alongside the explicit-target TLS inventory slice and beneath both audit commands.

It answers two different but related questions:

- what endpoints is this machine exposing locally
- what endpoints within explicitly declared remote scope respond at all

Discovery still stops short of verified scanner output.

## Current commands

The discovery commands are:

```bash
surveyor discover local
surveyor discover subnet --cidr 10.0.0.0/24 --ports 443,8443
```

## Why discovery exists

Surveyor already has one verified scanner path:

- `surveyor scan tls`

That path works when the operator already knows what to scan.

The discovery layer exists to:

- enumerate candidate endpoints
- describe them in a stable schema
- attach conservative protocol hints
- feed later audit flows without collapsing discovery and verified scanning into one command

## Command semantics

The semantics of `surveyor discover local` are:

- enumerate local listener state
- report observed local facts
- attach conservative protocol hints where justified
- emit canonical JSON and derived Markdown
- avoid active probing or scanner-specific verification

The semantics of `surveyor discover subnet` are:

- require explicit CIDR scope and explicit ports
- perform bounded TCP reachability probing within that declared scope
- report one observed result per attempted host:port
- attach conservative protocol hints only where justified
- emit canonical JSON and derived Markdown
- avoid verified protocol scanning

Both commands follow the same output conventions:

- `-o, --output` for Markdown output
- `-j, --json` for JSON output
- Markdown to stdout when no output path is given

## Current scope

Discovery currently covers:

- local-only listener enumeration
- explicit remote subnet discovery
- TCP listening endpoints for local discovery
- UDP bound endpoints for local discovery
- TCP reachability probing for remote discovery
- best-effort process metadata where available for local discovery
- conservative protocol hints with explicit confidence and evidence

Discovery does not cover:

- undeclared remote scope
- automatic verified protocol handshakes
- broad host assessment
- vulnerability scanning
- automatic scanner execution in the discovery command itself

## Facts, hints and scans

Discovery must keep three things separate:

1. observed endpoint facts
2. protocol hints
3. verified scan results

Examples:

- `scope_kind=local`, `host=0.0.0.0`, `transport=tcp`, `port=443` are observed facts
- `scope_kind=remote`, `host=10.0.0.10`, `state=responsive`, `port=443` are observed facts
- `protocol=tls` with conservative confidence may be a hint
- negotiated TLS version, cipher suite and certificate metadata are verified scan results and belong to a scanner, not discovery

Hints are not scans.

## Discovery schema

Discovery follows the same output philosophy as the TLS slice:

- JSON is canonical
- Markdown is derived from the canonical model

### Top-level report

Current top-level discovery report shape:

```json
{
  "generated_at": "2026-04-15T03:00:00Z",
  "scope": {
    "scope_kind": "remote",
    "cidr": "10.0.0.0/30",
    "ports": [443, 8443]
  },
  "execution": {
    "profile": "cautious",
    "max_hosts": 256,
    "max_concurrency": 8,
    "timeout": "3s"
  },
  "results": [],
  "summary": {}
}
```

Fields:

- `generated_at`: RFC3339 UTC timestamp for report assembly time
- `scope`: declared scope metadata for the report
- `execution`: execution settings that materially shaped the run, currently present for remote discovery
- `results`: one entry per observed endpoint
- `summary`: aggregate counts derived from `results`

### Report scope

Current report-scope shape:

```json
{
  "scope_kind": "remote",
  "cidr": "10.0.0.0/30",
  "ports": [443, 8443]
}
```

Fields:

- `scope_kind`: `local` or `remote`
- `cidr`: declared remote CIDR when the report covers remote scope
- `ports`: declared remote port set when the report covers remote scope

### Report execution

Current report-execution shape:

```json
{
  "profile": "cautious",
  "max_hosts": 256,
  "max_concurrency": 8,
  "timeout": "3s"
}
```

Fields:

- `profile`: effective remote pace profile
- `max_hosts`: effective expanded-host hard cap
- `max_concurrency`: effective probe concurrency cap
- `timeout`: effective per-attempt timeout

### Discovered endpoint

Current discovered-endpoint shape:

```json
{
  "scope_kind": "remote",
  "host": "10.0.0.10",
  "port": 443,
  "transport": "tcp",
  "state": "responsive",
  "hints": [],
  "warnings": [],
  "errors": []
}
```

Fields:

- `scope_kind`: whether the observation came from `local` or `remote` scope
- `host`: observed host or IP within the declared scope
- `port`: observed or attempted port within the declared scope
- `transport`: transport name, currently `tcp` or `udp`
- `state`: observed endpoint state
  - local discovery currently uses `listening` or `bound`
  - remote discovery currently uses `responsive` or `candidate`
- `pid`: process identifier where available without requiring elevation, local-only
- `process_name`: best-effort process name where available, local-only
- `executable`: best-effort executable path where available and appropriate to expose, local-only
- `hints`: protocol hints derived conservatively from observed facts
- `warnings`: non-fatal discovery concerns or platform limitations
- `errors`: result-level failures, including failed remote probe attempts

### Hint

Current hint shape:

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
  "total_endpoints": 3,
  "tcp_endpoints": 3,
  "udp_endpoints": 0,
  "hint_breakdown": {
    "tls": 2
  }
}
```

Fields:

- `total_endpoints`: total number of discovered results
- `tcp_endpoints`: count of TCP results
- `udp_endpoints`: count of UDP results
- `hint_breakdown`: count of results carrying each hinted protocol

## Local and remote boundaries

`discover local` is observational only.

It:

- inspects local listener state
- avoids active network probing
- may attach best-effort process metadata

`discover subnet` is active but still conservative.

It:

- walks only explicitly declared CIDR scope
- probes only explicitly declared ports
- records both responsive and failed attempts
- attaches hints only to responsive endpoints
- does not perform verified TLS scanning
- records the declared scope and effective remote execution settings in the report metadata

## Current examples

Representative example outputs live in:

- [examples/discovery.json](../examples/discovery.json)
- [examples/discovery.md](../examples/discovery.md)
- [examples/discovery-subnet.json](../examples/discovery-subnet.json)
- [examples/discovery-subnet.md](../examples/discovery-subnet.md)

## Relationship to audit

Discovery feeds both current audit flows.

It does not itself decide which scanners run. That is the job of the audit layer described in [docs/audit.md](audit.md).
