# Safety

Surveyor is a defensive inventory and reporting tool.

That is not just branding. It should shape default behaviour, scope and future design decisions.

## Current safety model

The current implementation is intentionally narrow:
- `surveyor audit local` only hands supported TLS-like endpoints into the current TLS scanner
- `surveyor discover local` is observational only
- targets are explicitly provided
- local discovery is limited to local listening or bound endpoints
- connections are bounded by timeout
- the scanner performs standard TLS client behaviour
- there is no range scanning
- there is no protocol abuse logic
- there is no exploit or active manipulation behaviour

This keeps the first version easier to reason about and lowers the risk of surprising network behaviour.

## Explicit target model

The current config format requires explicit targets:
- `host`
- `port`

The current CLI also supports explicit command-line targets through `--targets`, but it keeps the same rule:
- every target must be explicit `host:port`

That means Surveyor currently supports:
- public hostnames with explicit ports, for example `google.com:443`
- internal IPs with explicit ports, for example `10.0.0.5:443`
- ad hoc command-line target lists such as `127.0.0.1:443,127.0.0.1:8443`

It does not currently support:
- host-only config entries with an implied default port
- IP-only config entries with an implied default port
- CIDR ranges
- automatic service discovery
- cloud inventory import

That strictness is deliberate. Safety improves when the tool is explicit about what it will touch.

## Local discovery boundary

The current discovery path is:

- local only
- observational only
- limited to local TCP listening endpoints and UDP bound endpoints
- limited to conservative protocol hints from observed facts

That means Surveyor currently supports:

- enumerating local listener state
- attaching best-effort process metadata where available
- attaching conservative low-confidence hints such as `tls`, `ssh` or `rdp`

It does not currently support:

- active probing during discovery
- automatic protocol verification during discovery
- automatic scan handoff from discovery
- remote discovery
- arbitrary address-range discovery

Hints are not scans. Discovery output should be read as local endpoint inventory, not as verified service identification.

## Local audit boundary

The current audit path is:

- local only
- discovery first
- conservative about scanner selection
- limited to automatic handoff into the existing TLS scanner
- explicit about skipped endpoints and skip reasons

That means Surveyor currently supports:

- combining discovered endpoint facts, hints, scanner selection and verified TLS results in one report
- scanning only the supported TLS-like subset automatically

It does not currently support:

- automatic non-TLS scanning
- remote audit
- arbitrary range audit
- aggressive probing

`audit local` is a real scan workflow, but only for the explicitly supported subset chosen by the selection layer.

## Collection boundaries

The current scanner deliberately disables certificate verification during collection.

Why:
- the collection layer needs to record what the service actually presents
- failing early on trust or hostname validation would prevent inventory of many real-world endpoints

What this does not mean:
- Surveyor treats the endpoint as trusted
- Surveyor has validated service identity
- Surveyor has completed a compliance or trust assessment

Those are separate concerns and should be implemented as explicit later work.

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

That is why the current classifier uses `manual_review_required` when the evidence is incomplete or outside the recognised rule set.

## Non-goals

Surveyor is not currently intended to be:
- a generic security scanner
- an internet-wide discovery engine
- a local host auditor that aggressively scans every discovered service
- an exploitation framework
- a binary "quantum-safe" labelling tool

If future work starts pushing the project in those directions, the change should be treated as a deliberate scope decision, not an incidental feature addition.
