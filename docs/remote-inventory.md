# Remote Inventory

Remote inventory is now part of Surveyor's current repository surface.

It extends the local discovery and audit model across an authorised remote boundary without changing the project's core discipline:

- explicit scope first
- conservative discovery second
- conservative hints third
- narrow scanner selection fourth
- verified TLS scanning only for the supported subset
- canonical JSON first, Markdown derived from it

## Current command surface

The canonical remote commands are:

```bash
surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o discovery-remote.md -j discovery-remote.json
surveyor discover remote --targets-file approved-hosts.txt --ports 443,8443 --profile cautious -o discovery-remote.md -j discovery-remote.json

surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o audit-remote.md -j audit-remote.json
surveyor audit remote --targets-file approved-hosts.txt --ports 443,8443 --profile cautious -o audit-remote.md -j audit-remote.json
```

`surveyor discover subnet` and `surveyor audit subnet` remain as CIDR-only compatibility aliases during `v0.5.x`.

## Why this surface exists

Surveyor already proved:

- one verified deep scanner, TLS
- one local discovery foundation
- one local audit orchestration path
- one JSON-first reporting model

Remote inventory compounds that architecture instead of widening it sideways into new protocol scanners.

## Current command semantics

Current semantics for `surveyor discover remote`:
- require explicit remote CIDR scope
- or explicit file-backed host scope
- require an explicit remote port set
- stay within the declared scope only
- perform bounded TCP reachability probing
- record one result per attempted host:port
- attach conservative protocol hints only to responsive endpoints
- avoid implying verified protocol identification
- emit canonical JSON and derived Markdown

Current semantics for `surveyor audit remote`:
- run remote discovery first
- preserve observed endpoint facts and hints
- select supported scanners conservatively
- hand only the supported TLS-like subset into the existing TLS scanner
- record verified TLS results separately from discovery and selection
- record skipped endpoints with explicit reasons
- emit one combined canonical JSON report and derived Markdown

## Scope and pace are separate

Remote scope and remote pace remain separate concepts.

Scope is defined by:
- exactly one of `--cidr` or `--targets-file`
- `--ports`

Pace is defined by:
- `--profile`
- `--max-concurrency`
- `--timeout`

Profiles change pace, not scope.

## Current remote safety controls

The current remote control surface is:

- `--profile cautious|balanced|aggressive`
- `--dry-run`
- `--max-hosts`
- `--max-concurrency`
- `--timeout`
- `--ports`

Rules:

- `--profile` sets defaults
- explicit flags override profile defaults
- `--dry-run` performs no network I/O at all
- `--max-hosts` is a hard stop after scope expansion
- `--timeout` applies per probe or connection attempt
- `--ports` is required for current remote scope modes

Current defaults:
- profile default: `cautious`
- `--max-hosts` default: `256`
- `cautious`: `max-concurrency=8`, `timeout=3s`
- `balanced`: `max-concurrency=24`, `timeout=2s`
- `aggressive`: `max-concurrency=64`, `timeout=1s`

## Dry-run behaviour

`--dry-run` validates the execution plan without touching the network.

It prints:

- command mode
- resolved scope
- expanded host count
- selected ports
- effective profile
- effective host cap
- effective concurrency
- effective timeout
- supported scanner set

It does not emit canonical discovery or audit JSON. That is deliberate. The dry-run output is an execution plan, not a report of observed or verified facts.

## Discovery boundary

Remote discovery stays conservative.

It does:
- walk only the declared remote scope
- probe only the declared ports
- record responsive TCP endpoints as `state=responsive`
- record failed attempts as `state=candidate` with explicit errors
- attach conservative low-confidence hints only to responsive endpoints
- record the declared scope and effective execution settings in the report metadata

It does not:
- perform verified protocol handshakes
- widen scope implicitly
- infer protocol identity from failed attempts

## Audit boundary

Remote audit also stays narrow.

It does:
- consume the remote discovery results first
- select only remote `tcp` endpoints in `responsive` state
- require a conservative `tls` hint before TLS scanner handoff
- invoke only the existing TLS scanner
- skip everything else explicitly with a reason
- record the declared scope and effective execution settings in the report metadata

Important examples:
- a failed `443` probe remains an attempted endpoint with explicit errors
- a failed `443` probe is not a TLS candidate
- a responsive `443` or `8443` endpoint may carry a low-confidence `tls` hint
- only then can audit select it for verified TLS scanning
- verified TLS results on remote runs reflect literal IP-target connection paths, not hostname validation or full virtual-host coverage

## Facts, hints, selections and scans

Remote inventory preserves the same separation already used locally:

1. observed endpoint facts
2. protocol hints
3. selection decisions
4. verified TLS results
5. skipped endpoints and reasons

Hints are not scans.

Selection is not verification.

Markdown must not introduce facts that are absent from the canonical JSON model.

## Current examples

Representative remote example outputs live in:

- [examples/discovery-remote.json](../examples/discovery-remote.json)
- [examples/discovery-remote.md](../examples/discovery-remote.md)
- [examples/audit-remote.json](../examples/audit-remote.json)
- [examples/audit-remote.md](../examples/audit-remote.md)
- [examples/approved-hosts.txt](../examples/approved-hosts.txt)

## Non-goals

The current remote inventory surface does not include:

- non-TLS deep scanners such as RDP, SSH or SMTP
- STARTTLS or multi-protocol probing
- arbitrary internet-wide scanning
- implicit full-network sweeps
- trust-store validation
- hostname validation semantics
- policy engines
- history or diffing
- cloud connectors
- enterprise-wide orchestration beyond explicitly declared scope

## Relationship to future work

Remote inventory should now be hardened through real use before Surveyor chooses the second deep scanner or a broader orchestration model.

That keeps the project growing upward before it grows sideways.

The current remote scope model lives in [docs/remote-scope.md](remote-scope.md).
