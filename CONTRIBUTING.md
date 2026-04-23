<div align="center">
  <img src="./.github/banner.svg" alt="BANNER" width="720">
</div>

# Contributing to Surveyor

Thanks for taking an interest in Surveyor.

This project is meant to be technically careful and useful in practice. That matters more than volume of code, feature count, or how quickly something lands.

The short version is simple:
- keep changes focused
- prefer correctness over cleverness
- explain what changed and why
- add or update tests when behaviour changes
- sign off every commit under the DCO
- avoid widening scope without a clear reason

## Before You Start

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

If you are proposing major new functionality, the proposal should also explain:
- what new behaviour is being added
- which automated tests will be added or updated with it
- what level of coverage is expected across unit, integration, golden, fuzz, or workflow tests

## Commit Sign-Off

All commits must be signed off.

Use:
```bash
git commit -s
```

By signing off a commit, you certify the contribution under the Developer Certificate of Origin. See [`DCO.md`](DCO.md).

Pull requests containing unsigned commits should not be merged.
Repository-side enforcement should be handled through the GitHub DCO app and required status checks when that control is enabled.

## Project Principles

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

## Pull Requests

Please keep pull requests focused enough that they can be reviewed as one coherent unit of work.

A good pull request explains:
- what changed
- why it is needed
- how it was tested
- whether it changes behaviour, output, or classification

If a change affects output or reporting, include a representative example where practical.

If a change affects classification or interpretation, explain the reasoning. Surveyor is not just collecting raw data. It is also making judgement calls, so those need to be defensible.

If a pull request adds major new functionality, it should not be treated as ready unless the corresponding automated tests are included in the same change or the pull request explains exactly why that is not yet possible.

## Code and Tests

Some strong defaults for code contributions:
- write clear, idiomatic Go
- prefer explicit control flow over clever indirection
- keep packages narrowly scoped
- avoid speculative extension points
- preserve deterministic output where possible
- add or update tests when behaviour changes

Surveyor's general policy is that as major new functionality is added, automated tests for that functionality should be added to the repository as part of the same line of work. The exact mix can vary by change, but the expectation is that new functionality is covered by the strongest practical automated tests for that slice, for example unit tests, integration tests, golden tests, fuzz targets, workflow checks, or a combination of them.

Adding major functionality without adding corresponding automated tests should be treated as an exception that needs explicit justification, not the default path.

If you change public behaviour, examples or docs should usually move with it.

## File Headers and Licensing Notices

Surveyor intends to follow the OpenSSF Best Practices expectation that source files carry both a copyright statement and a licence statement.

For new source files, scripts and other copyright-affected files that support comments in a normal way, contributors should add a short header near the beginning of the file using:

```text
Copyright <year> The Surveyor Authors
SPDX-License-Identifier: Apache-2.0
```

Use the comment syntax appropriate to the file type.

This rule is intended for Surveyor-owned source files and similar project files where a notice is practical.

It does not require maintainers to rewrite:
- vendored third-party material
- generated files where the header would be unstable or misleading
- files whose format makes a normal comment header impractical

Contributors should preserve existing valid headers and should not remove or weaken per-file licensing notices casually.

## AI-Assisted Contributions

AI tools may be used to assist with research, drafting, refactoring, testing or documentation but their use must be disclosed clearly in the pull request.

The human contributor remains fully responsible for the contribution. This includes correctness, security, licensing, originality and fitness for inclusion in Surveyor.

AI systems cannot sign off commits under the DCO. Every commit must be signed off by a human author who understands the change and has the legal right to submit it.

Any pull request materially assisted by AI should be reviewed by a human maintainer before it can be merged.

## Documentation Changes

Documentation is part of the product, not an afterthought.

Surveyor is trying to help people make security and migration decisions. The wording therefore needs to be precise. If you change documentation, prefer direct language over marketing language and be cautious with anything that is stronger than the evidence supports.

## Security Issues

Do not use public issues or pull requests to report vulnerabilities in Surveyor itself.

See [SECURITY.md](SECURITY.md) for the reporting process.

## Conduct

Be professional, be respectful, and assume good faith.

Blunt technical disagreement is fine. Hand-waving, posturing, and low-signal noise are not helpful.
