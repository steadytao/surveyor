# Safety

Surveyor is a defensive inventory and reporting tool.

That is not just branding. It should shape default behaviour, scope and future design decisions.

## Current safety model

The current TLS inventory path is intentionally narrow:
- targets are explicitly provided
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

That means Surveyor currently supports:
- public hostnames with explicit ports, for example `google.com:443`
- internal IPs with explicit ports, for example `10.0.0.5:443`

It does not currently support:
- host-only config entries with an implied default port
- IP-only config entries with an implied default port
- CIDR ranges
- automatic service discovery
- cloud inventory import

That strictness is deliberate. Safety improves when the tool is explicit about what it will touch.

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

That is why the current classifier uses `manual_review_required` when the evidence is incomplete or outside the recognised rule set.

## Non-goals

Surveyor is not currently intended to be:
- a generic security scanner
- an internet-wide discovery engine
- an exploitation framework
- a binary "quantum-safe" labelling tool

If future work starts pushing the project in those directions, the change should be treated as a deliberate scope decision, not an incidental feature addition.
