# Remote Inventory

Remote inventory is the planned `v0.4.0` milestone.

It is not part of the current shipped CLI surface yet.

The goal of `v0.4.0` is to extend Surveyor's proved local model across an authorised remote boundary without changing the project's core discipline:

- explicit scope first
- conservative discovery second
- conservative hints third
- narrow scanner selection fourth
- verified TLS scanning only for the supported subset
- canonical JSON first, Markdown derived from it

## Why this milestone exists

Surveyor already has three shipped surfaces:

- `surveyor scan tls`
- `surveyor discover local`
- `surveyor audit local`

That means the project has already proved:

- one verified deep scanner, TLS
- one discovery foundation
- one audit orchestration path
- one JSON-first reporting model

The next missing capability is authorised remote scope.

The next step is not another protocol scanner. It is remote inventory built on the same separation between facts, hints, selection and verified results.

## Planned command surface

The planned remote commands are:

```bash
surveyor discover subnet --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o subnet.md -j subnet.json
surveyor audit subnet --cidr 10.0.0.0/24 --ports 443,8443 --profile cautious -o audit.md -j audit.json
```

For the MVP, `--cidr` is the primary remote scope input.

`--targets-file` may be added later, but it is not required to define the first remote release cleanly. The MVP should prove one explicit remote scope path well before adding more input forms.

## Command semantics

Planned semantics for `surveyor discover subnet`:

- require explicit remote scope
- require an explicit remote port set for CIDR mode
- stay within the declared scope only
- record observed endpoint facts before hinting
- attach conservative protocol hints only where justified
- avoid implying verified protocol identification
- emit canonical JSON and derived Markdown

Planned semantics for `surveyor audit subnet`:

- run remote discovery first
- preserve observed endpoint facts and hints
- select supported scanners conservatively
- hand only the supported TLS-like subset into the existing TLS scanner
- record verified TLS results separately from discovery and selection
- record skipped endpoints with explicit reasons
- emit one combined canonical JSON report and derived Markdown

## Scope and pace are separate

Remote scope and remote pace must stay separate concepts.

Scope is defined by:

- `--cidr`
- later, potentially `--targets-file`
- `--ports`

Pace is defined by:

- `--profile`
- `--max-concurrency`
- `--timeout`

This distinction matters.

Surveyor should not use fuzzy mode names such as `--noisy`, `--quiet` or `--silent`.

Profiles should change pace, not scope.

## Planned remote safety controls

The planned remote control surface is:

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
- `--ports` is required for CIDR mode in the MVP

Recommended defaults:

- profile default: `cautious`
- `--max-hosts` default: `256`

### `--dry-run`

`--dry-run` should print the execution plan without touching the network.

It should show:

- resolved scope summary
- host count after expansion
- selected ports
- effective profile
- effective concurrency
- effective timeout
- command mode, discover or audit
- supported scanner set that would be used

### Profile meanings

`cautious`:

- low concurrency
- conservative timeouts
- intended safe default for approved scope

`balanced`:

- moderate concurrency
- normal operational mode once scope is clearly authorised

`aggressive`:

- higher concurrency
- still within declared scope, but intended for tightly controlled environments

## Discovery and audit boundaries

Remote discovery must stay conservative.

It should:

- walk only the declared scope
- probe only the declared ports
- record observed facts and explicit failures
- avoid implying verified protocol identity

Remote audit must stay narrow.

It should:

- select only TCP candidates that carry conservative TLS evidence
- invoke only the existing TLS scanner
- skip everything else explicitly with a reason

This keeps the remote workflow explainable and aligned with the current local audit model.

## Facts, hints, selections and scans

Remote inventory must preserve the same separation already used locally:

1. observed endpoint facts
2. protocol hints
3. selection decisions
4. verified TLS results
5. skipped endpoints and reasons

Hints are not scans.

Selection is not verification.

Markdown must not introduce facts that are absent from the canonical JSON model.

## Required architecture change

The current discovery model is too local-socket-shaped for remote inventory.

`v0.4.0` should generalise the discovery model from:

- local socket inspection

to:

- observed endpoint within declared scope

That means the core model should be able to represent both local and remote observations without pretending remote endpoints are local sockets with local process metadata.

Local-only enrichments such as:

- `pid`
- `process_name`
- `executable`

must remain optional.

The model still needs to preserve:

- transport
- port
- observed state
- hints
- warnings
- errors

## Non-goals for `v0.4.0`

`v0.4.0` should not include:

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

## Definition of done

`v0.4.0` is done when all of this is true:

- `surveyor discover subnet` works against explicitly declared scope
- `surveyor audit subnet` works against explicitly declared scope
- remote discovery output clearly distinguishes facts from hints
- remote audit output clearly distinguishes facts, hints, selection, verified TLS results and skips
- remote audit invokes only the existing TLS scanner
- JSON and Markdown outputs are representative and checked in
- docs match shipped behaviour
- tests cover scope parsing, discovery, selection, audit handoff and outputs

## Relationship to future work

Remote inventory should be proved before Surveyor chooses the second deep scanner.

After `v0.4.0`, the next decision can be made from actual use:

- harden remote inventory further
- add history or policy work
- or choose the second scanner deliberately

That is the right order because it grows Surveyor upward before it grows sideways.
