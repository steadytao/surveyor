# Surveyor Diff Report

- Generated: 2026-04-22T02:00:00Z
- Baseline report kind: audit
- Current report kind: audit
- Total baseline entities: 1
- Total current entities: 2
- Added entities: 1
- Removed entities: 0
- Changed entities: 1
- Unchanged entities: 0
- Scope changed: true

## Comparison

- Baseline generated: 2026-04-20T02:00:00Z
- Current generated: 2026-04-21T02:00:00Z
- Baseline scope: remote audit within CIDR 10.0.0.0/30 over ports 443
- Current scope: remote audit within CIDR 10.0.1.0/30 over ports 443

## Change Summary

- cipher_suite_changed: 1
- classification_changed: 1
- findings_changed: 1
- new_endpoint: 1
- tls_version_changed: 1
- warnings_changed: 1

## Direction Summary

- changed: 1
- improved: 3
- informational: 1
- worsened: 1

## Changes

### remote|10.0.0.10|443|tcp

- Code: new_endpoint
- Direction: informational
- Severity: info
- Summary: A new audit endpoint appeared in the current report.
- Current value:

```json
{
  "discovered_endpoint": {
    "scope_kind": "remote",
    "host": "10.0.0.10",
    "port": 443,
    "transport": "tcp",
    "state": "candidate",
    "errors": [
      "connection refused"
    ]
  },
  "selection": {
    "status": "skipped",
    "reason": "endpoint did not respond during remote discovery"
  }
}
```

#### Evidence

- scope_kind=remote
- host=10.0.0.10
- port=443
- transport=tcp

### remote|example.com|443|tcp

- Code: cipher_suite_changed
- Direction: changed
- Severity: low
- Summary: The negotiated cipher suite changed.
- Baseline value:

```json
"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```
- Current value:

```json
"TLS_AES_128_GCM_SHA256"
```

### remote|example.com|443|tcp

- Code: classification_changed
- Direction: improved
- Severity: low
- Summary: The verified TLS classification changed.
- Baseline value:

```json
"legacy_tls_exposure"
```
- Current value:

```json
"modern_tls_classical_identity"
```

### remote|example.com|443|tcp

- Code: findings_changed
- Direction: worsened
- Severity: medium
- Summary: The TLS findings changed.
- Baseline value:

```json
[
  {
    "code": "legacy-tls-version",
    "severity": "high",
    "summary": "The service negotiated a legacy TLS version."
  },
  {
    "code": "classical-certificate-identity",
    "severity": "medium",
    "summary": "The observed certificate identity remains classical."
  }
]
```
- Current value:

```json
[
  {
    "code": "classical-certificate-identity",
    "severity": "medium",
    "summary": "The observed certificate identity remains classical."
  }
]
```

### remote|example.com|443|tcp

- Code: tls_version_changed
- Direction: improved
- Severity: low
- Summary: The negotiated TLS version changed.
- Baseline value:

```json
"TLS 1.2"
```
- Current value:

```json
"TLS 1.3"
```

### remote|example.com|443|tcp

- Code: warnings_changed
- Direction: improved
- Severity: low
- Summary: Audit warnings changed.
- Baseline value:

```json
{
  "tls_result": [
    "baseline-warning"
  ]
}
```
- Current value:

```json
{}
```
