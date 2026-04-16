# Generalised Remote Scope

Generalised remote scope is now part of Surveyor's current repository surface.

This document defines the current remote scope model that sits underneath
[docs/remote-inventory.md](remote-inventory.md).

## Current command surface

Canonical remote commands:

```bash
surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o discovery.md -j discovery.json
surveyor discover remote --targets-file approved-hosts.txt --ports 443,8443 --profile cautious -o discovery.md -j discovery.json

surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o audit.md -j audit.json
surveyor audit remote --targets-file approved-hosts.txt --ports 443,8443 --profile cautious -o audit.md -j audit.json
```

Compatibility aliases during `v0.5.x`:

```bash
surveyor discover subnet ...
surveyor audit subnet ...
```

Those aliases continue to mean the CIDR-backed remote path only. They are
compatibility affordances, not the long-term design centre.

## Scope model

The current remote scope model represents:

- remote scope kind
- declared input kind
- declared source details
- effective host set
- declared ports
- effective execution controls

Current report and planning fields:

- `scope_kind: remote`
- `input_kind: cidr | targets_file`
- `cidr` when relevant
- `targets_file` when relevant
- `host_count`
- `ports`

These fields should be reflected consistently in:

- CLI execution planning
- config parsing
- discovery report metadata
- audit report metadata

## Targets-file rules

The file-backed scope grammar stays deliberately simple.

Current rules:

- one host or IP per line
- blank lines allowed
- `#` comments allowed
- no implicit ports in the file
- `--ports` remains required

Do not add host:port tuples, YAML or multiple competing file grammars in the current line.

That keeps the remote model explicit:

- the file defines scope
- `--ports` defines surface

## Safety model

Generalised remote scope keeps the current remote safety controls:

- `--profile cautious|balanced|aggressive`
- `--dry-run`
- `--max-hosts`
- `--max-concurrency`
- `--timeout`
- `--ports`

Rules:

- `--profile` sets defaults
- explicit flags override profile defaults
- profiles change pace, not scope
- scope remains explicit
- `--dry-run` performs no network I/O

For `--targets-file`, `--max-hosts` still applies after the file is parsed
and normalised.

## Discovery and audit boundaries

Generalised remote scope does not blur the existing architectural separation.

Discovery should still do:

- observed remote facts
- conservative hints

Audit should still do:

- selection
- scanner handoff
- verified TLS results

TLS remains the only deep verified scanner in the current milestone line.

## What must remain true

These rules remain true in the current implementation:

- discovery records facts before hinting
- hints stay separate from verified scans
- audit remains orchestration, not a second scanner implementation
- JSON remains canonical
- Markdown contains no facts absent from JSON
- compatibility aliases do not become the product's long-term centre of gravity
- ambiguous observations fall back to skip or manual review rather than overclaiming

## Non-goals

The current remote scope model does not include:

- a second deep scanner
- STARTTLS or multi-protocol probing
- trust-store validation
- hostname validation
- history, diffing or stateful storage
- policy engines
- cloud connectors
- undeclared or internet-wide scanning
- complex scope-file grammars

## Relationship to the current remote surface

The current remote surface is now:

- canonical `surveyor discover remote`
- canonical `surveyor audit remote`
- explicit `--cidr` or `--targets-file`
- explicit `--ports`
- `surveyor discover subnet` and `surveyor audit subnet` retained as CIDR-only compatibility aliases during `v0.5.x`

That makes remote scope first-class without weakening the existing discovery,
hinting, selection and verified-scanning boundaries.
