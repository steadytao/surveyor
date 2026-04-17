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
surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443
surveyor discover remote --targets-file approved-hosts.txt --ports 443,8443
surveyor discover remote --inventory-file inventory.yaml
surveyor discover remote --inventory-file examples/caddy.json --adapter caddy
surveyor discover remote --inventory-file Caddyfile --adapter-bin /path/to/caddy
```

`surveyor discover subnet` remains as a CIDR-only compatibility alias from `v0.4.x`.

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

The semantics of `surveyor discover remote` are:

- require explicit remote scope
- support explicit adapter-backed inventory input through `--inventory-file`
- require explicit ports for `--cidr` and `--targets-file`, or use imported per-entry ports for `--inventory-file`
- perform bounded TCP reachability probing within that declared scope
- report one observed result per attempted host:port
- attach conservative protocol hints only where justified
- preserve imported inventory annotations where remote scope came from `--inventory-file`
- emit canonical JSON and derived Markdown
- avoid verified protocol scanning

Both commands follow the same output conventions:

- `-o, --output` for Markdown output
- `-j, --json` for JSON output
- Markdown to stdout when no output path is given

## Current scope

Discovery currently covers:

- local-only listener enumeration
- explicit remote discovery
- TCP listening endpoints for local discovery
- UDP bound endpoints for local discovery
- TCP reachability probing for remote discovery
- CIDR-backed remote scope
- simple file-backed host scope
- structured inventory-backed remote scope
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
  "schema_version": "1.0",
  "tool_version": "dev",
  "report_kind": "discovery",
  "scope_kind": "remote",
  "scope_description": "remote discovery from targets file examples/approved-hosts.txt over ports 443",
  "generated_at": "2026-04-15T03:00:00Z",
  "scope": {
    "scope_kind": "remote",
    "input_kind": "targets_file",
    "targets_file": "examples/approved-hosts.txt",
    "ports": [443]
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

- `schema_version`: current baseline-compatible schema version for report comparison
- `tool_version`: emitting Surveyor build version, currently `dev` for ordinary builds and tests
- `report_kind`: semantic top-level report kind, here `discovery`
- `scope_kind`: high-level scope the report covers, here `local` or `remote`
- `scope_description`: human-readable summary of the discovery scope represented by the report
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
  "input_kind": "targets_file",
  "targets_file": "examples/approved-hosts.txt",
  "ports": [443]
}
```

Fields:

- `scope_kind`: `local` or `remote`
- `input_kind`: declared remote scope input kind when the report covers remote scope, currently `cidr`, `targets_file` or `inventory_file`
- `cidr`: declared remote CIDR when the report covers CIDR-backed remote scope
- `targets_file`: declared remote targets-file path when the report covers file-backed remote scope
- `inventory_file`: declared structured inventory-file path when the report covers inventory-backed remote scope
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

`discover remote` is active but still conservative.

It:

- walks only explicitly declared remote scope
- probes only explicitly declared ports
- records both responsive and failed attempts
- attaches hints only to responsive endpoints
- does not perform verified TLS scanning
- records the declared scope and effective remote execution settings in the report metadata

## Current examples

Representative example outputs live in:

- [examples/discovery.json](../examples/discovery.json)
- [examples/discovery.md](../examples/discovery.md)
- [examples/discovery-inventory.json](../examples/discovery-inventory.json)
- [examples/discovery-inventory.md](../examples/discovery-inventory.md)
- [examples/discovery-remote.json](../examples/discovery-remote.json)
- [examples/discovery-remote.md](../examples/discovery-remote.md)
- [examples/discovery-subnet.json](../examples/discovery-subnet.json)
- [examples/discovery-subnet.md](../examples/discovery-subnet.md)

## Relationship to audit

Discovery feeds both current audit flows.

It does not itself decide which scanners run. That is the job of the audit layer described in [docs/audit.md](audit.md).
