# Generalised Remote Scope

This document defines the planned `v0.5.0` remote-scope contract.

It does not replace the current shipped remote-inventory boundary in
[docs/remote-inventory.md](remote-inventory.md). That document remains the
source of truth for the current `v0.4.x` implementation around
`surveyor discover subnet` and `surveyor audit subnet`.

## Why this next

`v0.4.x` proved that Surveyor can:

- discover explicitly declared remote CIDR scope conservatively
- attach conservative remote hints
- select supported TLS-like candidates narrowly
- hand only that subset into the existing TLS scanner

The next missing capability is not another deep scanner. It is a more honest
remote scope model.

The current remote surface is still too subnet-shaped:

- command names are `discover subnet` and `audit subnet`
- the current scope contract is CIDR-specific
- there is no supported file-backed remote scope input

`v0.5.0` should fix that by making remote scope first-class.

## Planned command surface

Canonical remote commands:

```bash
surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o discovery.md -j discovery.json
surveyor discover remote --targets-file approved-hosts.txt --ports 443,8443 --profile cautious -o discovery.md -j discovery.json

surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o audit.md -j audit.json
surveyor audit remote --targets-file approved-hosts.txt --ports 443,8443 --profile cautious -o audit.md -j audit.json
```

Compatibility aliases for `v0.5.x`:

```bash
surveyor discover subnet ...
surveyor audit subnet ...
```

Those aliases should continue to mean the CIDR-backed remote path only. They are
compatibility affordances, not the long-term design centre.

## Scope model

The current `SubnetScope` contract should become a broader remote scope model.

That model should represent:

- remote scope kind
- declared input kind
- declared source details
- effective host set
- declared ports
- effective execution controls

Suggested report and planning fields:

- `scope_kind: remote`
- `input_kind: cidr | targets_file`
- `cidr` when relevant
- `targets_file` when relevant
- `host_count`
- `ports`

This should be reflected consistently in:

- CLI execution planning
- config parsing
- discovery report metadata
- audit report metadata

## Targets-file rules

The first file-backed scope grammar should stay deliberately simple.

Recommended rules:

- one host or IP per line
- blank lines allowed
- `#` comments allowed
- no implicit ports in the file
- `--ports` remains required

Do not add host:port tuples, YAML or multiple competing file grammars in
`v0.5.0`.

That keeps the remote model explicit:

- the file defines scope
- `--ports` defines surface

## Safety model

Generalised remote scope should keep the current remote safety controls:

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

For `--targets-file`, `--max-hosts` should still apply after the file is parsed
and normalised.

## Discovery and audit boundaries

Generalised remote scope must not blur the existing architectural separation.

Discovery should still do:

- observed remote facts
- conservative hints

Audit should still do:

- selection
- scanner handoff
- verified TLS results

TLS should remain the only deep verified scanner in this milestone.

## What must remain true

These rules should remain true through `v0.5.0`:

- discovery records facts before hinting
- hints stay separate from verified scans
- audit remains orchestration, not a second scanner implementation
- JSON remains canonical
- Markdown contains no facts absent from JSON
- compatibility aliases do not become the product's long-term centre of gravity
- ambiguous observations fall back to skip or manual review rather than overclaiming

## Non-goals

`v0.5.0` should not include:

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

The current shipped remote surface remains:

- `surveyor discover subnet`
- `surveyor audit subnet`
- explicit `--cidr`
- explicit `--ports`

This document defines the next architectural step on top of that surface. It
does not change the meaning of the current `v0.4.x` commands by itself.
