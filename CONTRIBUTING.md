# Contributing to Surveyor

Thanks for taking an interest in Surveyor.

This project is meant to be technically careful and useful in practice. That matters more than volume of code, feature count, or how quickly something lands.

The short version is simple:
- keep changes focused
- prefer correctness over cleverness
- explain what changed and why
- add or update tests when behaviour changes
- avoid widening scope without a clear reason

## Before you start

If the change is small and obvious, a pull request is usually fine.

If the change is larger, changes behaviour, introduces new output fields, or affects scope, open an issue first. It is better to agree on the shape of the work before anyone disappears into implementation.

Examples of work that should normally start with an issue:
- new scanner behaviour
- output schema changes
- classification logic changes
- significant CLI changes
- substantial documentation or roadmap changes

Examples of work that usually do not need one:
- typo fixes
- small wording improvements
- tightly scoped bug fixes with an obvious cause
- minor follow-up cleanups to an active PR

## Project principles

Surveyor should stay:
- narrow in scope
- conservative in claims
- evidence-oriented
- safe by default
- easy to reason about

That means a few practical rules:
- do not turn it into a generic security scanner
- do not overstate “PQ readiness”
- do not hide uncertainty behind vague labels
- do not add abstraction before the code actually needs it
- do not treat incomplete or ambiguous observations as certainty

## Pull requests

Please keep pull requests focused enough that they can be reviewed as one coherent unit of work.

A good pull request explains:
- what changed
- why it is needed
- how it was tested
- whether it changes behaviour, output, or classification

If a change affects output or reporting, include a representative example where practical.

If a change affects classification or interpretation, explain the reasoning. Surveyor is not just collecting raw data. It is also making judgement calls, so those need to be defensible.

## Code and tests

Some strong defaults for code contributions:
- write clear, idiomatic Go
- prefer explicit control flow over clever indirection
- keep packages narrowly scoped
- avoid speculative extension points
- preserve deterministic output where possible
- add or update tests when behaviour changes

If you change public behaviour, examples or docs should usually move with it.

## Documentation changes

Documentation is part of the product, not an afterthought.

Surveyor is trying to help people make security and migration decisions. The wording therefore needs to be precise. If you change documentation, prefer direct language over marketing language and be cautious with anything that is stronger than the evidence supports.

## Security issues

Do not use public issues or pull requests to report vulnerabilities in Surveyor itself.

See [SECURITY.md](SECURITY.md) for the reporting process.

## Conduct

Be professional, be respectful, and assume good faith.

Blunt technical disagreement is fine. Hand-waving, posturing, and low-signal noise are not helpful.
