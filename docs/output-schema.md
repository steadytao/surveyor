# Output Schema

Surveyor's canonical output is JSON.

Markdown exists for human-readable sharing but it is derived from the same canonical model. If a fact matters, it should exist in the JSON schema first.

The same rule applies to the discovery slice described in [docs/discovery.md](discovery.md).
The same rule applies to the audit slice described in [docs/audit.md](audit.md).

## Top-level report

Current top-level report shape:

```json
{
  "generated_at": "2026-04-14T01:45:00Z",
  "results": [],
  "summary": {}
}
```

Fields:

### `generated_at`

- type: RFC3339 UTC timestamp
- meaning: when the report object was assembled

### `results`

- type: array of target results
- meaning: one entry per scanned target

### `summary`

- type: summary object
- meaning: aggregate counts derived from `results`

## Per-target result

Current per-target result shape:
```json
{
  "name": "primary-site",
  "host": "example.com",
  "port": 443,
  "address": "203.0.113.10:443",
  "scanned_at": "2026-04-14T01:00:00Z",
  "reachable": true,
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "leaf_key_algorithm": "rsa",
  "leaf_key_size": 2048,
  "leaf_signature_algorithm": "sha256-rsa",
  "certificate_chain": [],
  "classification": "modern_tls_classical_identity",
  "findings": [],
  "warnings": [],
  "errors": []
}
```

Fields:

### `name`

- type: string
- optional: yes
- meaning: human label from configuration

### `host`

- type: string
- optional: no
- meaning: configured host or IP literal

### `port`

- type: integer
- optional: no
- meaning: configured TCP port

### `address`

- type: string
- optional: yes
- meaning: remote address observed by the TLS connection

### `scanned_at`

- type: RFC3339 UTC timestamp
- optional: no
- meaning: when collection for this target ran

### `reachable`

- type: boolean
- optional: no
- meaning: whether a TLS connection completed far enough to produce a connection state

### `tls_version`

- type: string
- optional: yes
- meaning: negotiated TLS version as reported by the Go TLS stack, for example `TLS 1.2` or `TLS 1.3`

### `cipher_suite`

- type: string
- optional: yes
- meaning: negotiated cipher suite name as reported by the Go TLS stack

### `leaf_key_algorithm`

- type: string
- optional: yes
- meaning: lower-case public-key algorithm name from the leaf certificate, for example `rsa` or `ecdsa`

### `leaf_key_size`

- type: integer
- optional: yes
- meaning: inferred leaf public-key size in bits where that is available

### `leaf_signature_algorithm`

- type: string
- optional: yes
- meaning: normalised lower-case leaf certificate signature algorithm, for example `sha256-rsa`

### `certificate_chain`

- type: array of certificate references
- optional: yes
- meaning: presented peer certificates in observed order

### `classification`

- type: string
- optional: no
- meaning: Surveyor's current conservative migration-posture bucket

### `findings`

- type: array of findings
- optional: yes
- meaning: structured explanations and recommendations derived from the current evidence

### `warnings`

- type: array of strings
- optional: yes
- meaning: non-fatal collection concerns, for example incomplete certificate observation

### `errors`

- type: array of strings
- optional: yes
- meaning: collection failures or hard result-level errors

## Certificate reference

Current certificate reference shape:

```json
{
  "subject": "CN=example.com",
  "issuer": "CN=Example CA",
  "serial_number": "1",
  "not_before": "2026-04-01T00:00:00Z",
  "not_after": "2026-10-01T00:00:00Z",
  "dns_names": [
    "example.com",
    "www.example.com"
  ],
  "public_key_algorithm": "rsa",
  "public_key_size": 2048,
  "signature_algorithm": "sha256-rsa",
  "is_ca": false
}
```

Fields:
- `subject`: string form of the certificate subject
- `issuer`: string form of the certificate issuer
- `serial_number`: decimal serial string
- `not_before`: RFC3339 UTC timestamp
- `not_after`: RFC3339 UTC timestamp
- `dns_names`: SAN DNS names as presented
- `public_key_algorithm`: lower-case public-key algorithm name
- `public_key_size`: inferred key size in bits where available
- `signature_algorithm`: lower-case normalised signature algorithm name
- `is_ca`: whether the certificate is marked as a CA

## Finding

Current finding shape:

```json
{
  "code": "classical-certificate-identity",
  "severity": "medium",
  "summary": "The observed certificate identity remains classical.",
  "evidence": [
    "leaf_key_algorithm=rsa",
    "leaf_signature_algorithm=sha256-rsa"
  ],
  "recommendation": "Inventory certificate replacement and related PKI dependencies as part of migration planning."
}
```

Fields:
- `code`: stable machine-readable identifier
- `severity`: one of `info`, `low`, `medium`, `high`, `critical`
- `summary`: short human-readable statement
- `evidence`: supporting observed facts
- `recommendation`: suggested next action

## Summary object

Current summary shape:
```json
{
  "total_targets": 1,
  "reachable_targets": 1,
  "unreachable_targets": 0,
  "classification_breakdown": {
    "modern_tls_classical_identity": 1
  }
}
```

Fields:
- `total_targets`: total number of results
- `reachable_targets`: number of results with `reachable=true`
- `unreachable_targets`: number of results with `reachable=false`
- `classification_breakdown`: counts keyed by classification label

## Stability notes

The current schema is an MVP contract, not a promise of permanent immutability.

Still, changes to these field names or meanings should be treated as public contract changes. If the schema changes:
- update this document
- update the examples
- update tests
- explain the behavioural impact in the PR

## Discovery report

Current discovery report shape:

```json
{
  "generated_at": "2026-04-15T01:45:00Z",
  "scope": {
    "scope_kind": "remote",
    "input_kind": "cidr",
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

### `generated_at`

- type: RFC3339 UTC timestamp
- meaning: when the discovery report object was assembled

### `scope`

- type: report-scope object
- meaning: declared scope metadata for the discovery report

### `execution`

- type: report-execution object
- optional: yes
- meaning: execution settings that materially shaped the run, currently present for remote discovery

### `results`

- type: array of discovered endpoints
- meaning: one entry per observed endpoint in the discovery report, whether observed locally or within declared remote scope

### `summary`

- type: discovery summary object
- meaning: aggregate counts derived from `results`

## Report scope

Current report-scope shape:

```json
{
  "scope_kind": "remote",
  "input_kind": "cidr",
  "cidr": "10.0.0.0/30",
  "ports": [443, 8443]
}
```

Fields:

- `scope_kind`: whether the report covers `local` or `remote` scope
- `input_kind`: declared remote scope input kind when the report covers remote scope, currently `cidr`
- `cidr`: declared remote CIDR when the report covers remote scope
- `ports`: declared remote port set when the report covers remote scope

## Report execution

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
- `timeout`: effective per-attempt timeout, currently also used for remote TLS connection attempts during audit

## Discovered endpoint

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

### `scope_kind`

- type: string
- optional: no
- meaning: whether the endpoint was observed in `local` or `remote` scope

### `host`

- type: string
- optional: no
- meaning: observed host or IP within the declared scope; for local discovery this is the local bound address, for remote discovery this is the attempted remote host or IP

### `port`

- type: integer
- optional: no
- meaning: observed or attempted port within the declared scope

### `transport`

- type: string
- optional: no
- meaning: transport name, currently `tcp` or `udp`

### `state`

- type: string
- optional: no
- meaning: observed endpoint state
  - local discovery currently uses `listening` or `bound`
  - remote discovery currently uses `responsive` or `candidate`

### `pid`

- type: integer
- optional: yes
- meaning: process identifier where available without requiring elevation, currently local-only

### `process_name`

- type: string
- optional: yes
- meaning: best-effort process name where available, currently local-only

### `executable`

- type: string
- optional: yes
- meaning: best-effort executable path where available, currently local-only

### `hints`

- type: array of discovery hints
- optional: yes
- meaning: conservative protocol hints derived from observed facts

### `warnings`

- type: array of strings
- optional: yes
- meaning: non-fatal discovery concerns, for example unavailable process metadata

### `errors`

- type: array of strings
- optional: yes
- meaning: endpoint-level discovery failures, including failed remote probe attempts

## Discovery hint

Current discovery-hint shape:

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

Hints are not verified scan results.

## Discovery summary object

Current discovery summary shape:

```json
{
  "total_endpoints": 2,
  "tcp_endpoints": 1,
  "udp_endpoints": 1,
  "hint_breakdown": {
    "tls": 1
  }
}
```

Fields:

- `total_endpoints`: total number of discovered endpoints
- `tcp_endpoints`: number of discovered TCP endpoints
- `udp_endpoints`: number of discovered UDP endpoints
- `hint_breakdown`: counts keyed by hinted protocol label

## Audit report

Current top-level audit report shape:

```json
{
  "generated_at": "2026-04-16T02:00:00Z",
  "scope": {
    "scope_kind": "remote",
    "input_kind": "cidr",
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

### `generated_at`

- type: RFC3339 UTC timestamp
- meaning: when the audit report object was assembled

### `scope`

- type: report-scope object
- meaning: declared scope metadata for the audit report

### `execution`

- type: report-execution object
- optional: yes
- meaning: execution settings that materially shaped the run, currently present for remote audit

### `results`

- type: array of audit results
- meaning: one entry per discovered endpoint considered by the local or remote audit flow

### `summary`

- type: audit summary object
- meaning: aggregate counts derived from `results`

## Audit result

Current per-endpoint audit-result shape:

```json
{
  "discovered_endpoint": {},
  "selection": {},
  "tls_result": {}
}
```

Fields:

### `discovered_endpoint`

- type: discovered endpoint object
- meaning: observed endpoint facts and hints from the discovery layer

### `selection`

- type: selection object
- meaning: scanner decision for the endpoint, including skipped outcomes

### `tls_result`

- type: target result object
- optional: yes
- meaning: verified TLS result when the endpoint is selected for the TLS scanner and the scan runs

## Selection object

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

Hints are not verified scans, and selection is not verification.

## Audit summary object

Current audit summary shape:

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
- `scanned_endpoints`: endpoints for which a supported scanner ran
- `skipped_endpoints`: endpoints not scanned
- `selection_breakdown`: counts keyed by selected scanner
- `verified_classification_breakdown`: counts keyed by verified TLS classification where a TLS scan completed
