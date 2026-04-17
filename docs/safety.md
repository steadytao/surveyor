# Safety

Surveyor is a defensive inventory and reporting tool.

That is not just branding. It should shape default behaviour, scope and future design decisions.

## Current safety model

The current implementation is intentionally narrow:

- `surveyor audit local` only hands supported TLS-like endpoints into the current TLS scanner
- `surveyor discover local` is observational only
- `surveyor discover remote` and `surveyor audit remote` require explicit declared remote scope and declared port surface
- `surveyor discover subnet` and `surveyor audit subnet` remain CIDR-only compatibility aliases from `v0.4.x`
- remote pace is bounded by profile defaults, host caps, concurrency caps and per-attempt timeouts
- `--dry-run` exists for the remote commands and performs no network I/O
- the scanner performs standard TLS client behaviour
- there is no implicit full-network sweep
- there is no protocol abuse logic
- there is no exploit or active manipulation behaviour

This keeps the current release easier to reason about and lowers the risk of surprising network behaviour.

## Explicit scope model

Surveyor supports two current scope models:

### Explicit TLS targets

The explicit TLS path requires:

- `host`
- `port`

That applies to both:

- YAML config input
- command-line `--targets`

### Explicit remote scope

The canonical remote commands require exactly one of:

- `--cidr`
- `--targets-file`
- `--inventory-file`

Port rules:

- `--ports` is required for `--cidr`
- `--ports` is required for `--targets-file`
- `--ports` overrides imported entry ports for `--inventory-file`
- if `--ports` is omitted for `--inventory-file`, imported entries must declare ports

Optional pace controls:

- `--profile`
- `--max-hosts`
- `--max-concurrency`
- `--timeout`

Safety preview:

- `--dry-run`

This means Surveyor currently supports:

- public hostnames with explicit ports, for example `google.com:443`
- internal IPs with explicit ports, for example `10.0.0.5:443`
- explicitly declared remote subnet scope such as `--cidr 10.0.0.0/24 --ports 443,8443`
- explicitly declared file-backed host scope such as `--targets-file examples/approved-hosts.txt --ports 443`
- explicitly declared structured inventory scope such as `--inventory-file examples/inventory.yaml`
- explicitly declared adapter-backed inventory scope such as `--inventory-file Caddyfile` or `--inventory-file ingress.yaml --adapter kubernetes-ingress-v1`

It does not currently support:

- host-only config entries with an implied default port
- IP-only config entries with an implied default port
- undeclared remote scope
- automatic service discovery outside the current local and remote commands
- live cloud inventory import

That strictness is deliberate. Safety improves when the tool is explicit about what it will touch.

## Local discovery boundary

`surveyor discover local` is:

- local only
- observational only
- limited to local TCP listening endpoints and UDP bound endpoints
- limited to conservative protocol hints from observed facts

It does not perform:

- active probing
- verified protocol scanning
- automatic scanner handoff in the same command

## Remote discovery boundary

`surveyor discover remote` is active, but still conservative.

It is:

- limited to explicitly declared remote scope
- limited to explicitly declared ports
- bounded by host caps, concurrency and timeout
- limited to TCP reachability probing
- explicit about both responsive and failed attempts

It does not:

- widen scope implicitly
- perform verified TLS scanning
- infer protocol identity from unreachable ports

Hints remain hints. A failed `443` attempt is still not a TLS scan result.

Remote discovery reports also carry the declared scope and effective execution settings so later readers can see what the command was actually allowed to touch.

## Local audit boundary

`audit local` is:

- local only
- discovery first
- conservative about scanner selection
- limited to automatic handoff into the existing TLS scanner
- explicit about skipped endpoints and skip reasons

## Remote audit boundary

`audit remote` is:

- limited to explicitly declared remote scope and declared port surface
- discovery first
- conservative about scanner selection
- limited to automatic handoff into the existing TLS scanner
- explicit about skipped endpoints and skip reasons

It only selects:

- remote `tcp` endpoints
- in `responsive` state
- that already carry a conservative `tls` hint

It does not:

- run non-TLS deep scanners
- perform aggressive multi-protocol probing
- imply that unsupported endpoints were fully assessed

Remote audit reports carry the declared scope and effective execution settings for the same reason.

## Collection boundaries

The current TLS scanner deliberately disables certificate verification during collection.

Why:

- the collection layer needs to record what the service actually presents
- failing early on trust or hostname validation would prevent inventory of many real-world endpoints

What this does not mean:

- Surveyor treats the endpoint as trusted
- Surveyor has validated service identity
- Surveyor has completed a compliance or trust assessment

Those are separate concerns and should only be added as explicit later work.

## IP literals and SNI

When the target host is an IP literal, Surveyor does not set `ServerName`.

Why:

- SNI is a hostname-oriented signal
- forcing an IP literal into that path would blur what was truly observed

This means IP-target results should be read as observations of that connection path, not as a complete statement about every virtual-hosted service behind the address.

## Output safety

Surveyor should prefer:

- evidence over certainty
- conservative labels over strong claims
- manual review over false confidence
- hints over overclaiming protocol certainty during discovery
- explicit skip reasons over silent omission during audit

That is why ambiguous cases still fall back to skip or manual review rather than overclaiming certainty.

## Non-goals

Surveyor is not currently intended to be:

- a generic security scanner
- an internet-wide discovery engine
- an implicit whole-network auditor
- an exploitation framework
- a binary "quantum-safe" labelling tool

If future work starts pushing the project in those directions, the change should be treated as a deliberate scope decision, not an incidental feature addition.
