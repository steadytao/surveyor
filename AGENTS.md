# AGENTS.md

**Human readers:** this file is primarily for coding agents, not for you. It exists because many AI agents are poor at consistently following instructions spread across a full repository. See the canonical project documents for the authoritative policy.

This file provides agent-focused instructions for work in Surveyor.

## Mission

Surveyor is a TLS-first cryptographic inventory and migration-readiness tool.

It exists to produce defensible transport-facing observations, conservative classification and clear next-action outputs. It is not a generic vulnerability scanner, a dashboard platform or a vague "PQ score" generator.

## Canonical Authority

Agents must treat the following as authoritative:
- [`README.md`](README.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`SECURITY.md`](SECURITY.md)
- [`DCO.md`](DCO.md)
- [`GOVERNANCE.md`](GOVERNANCE.md)
- [`MAINTAINERS.md`](MAINTAINERS.md)
- [`SUPPORT.md`](SUPPORT.md)
- [`docs/README.md`](docs/README.md)
- [`docs/architecture/README.md`](docs/architecture/README.md)
- [`docs/architecture/decisions/README.md`](docs/architecture/decisions/README.md)
- [`docs/reference/safety.md`](docs/reference/safety.md)
- [`docs/releases/checklist.md`](docs/releases/checklist.md)

If this file appears to conflict with those documents, follow the canonical documents.

## Scope and Product Discipline

Surveyor is intentionally narrow.

Agents must not:
- turn it into a generic security scanner
- overstate "PQ readiness"
- blur raw observation, interpretation and reporting into one opaque layer
- widen remote scope implicitly
- present incomplete evidence as certainty

Changes that materially affect scope, output semantics, classification or safety boundaries should be treated as deliberate product decisions, not incidental edits.

## Governance and Decision-Making

Surveyor is maintainer-led.

Agents must not imply:
- consensus governance that does not exist
- merge or release authority for contributors who do not have it
- stronger support commitments than the documented support posture

## AI-Specific Contribution Rules

AI systems may assist with drafting, refactoring, testing, workflow work and documentation, but they are not the legal contributor.

Agents must not:
- add `Signed-off-by:` lines on behalf of a human
- claim to satisfy the DCO themselves
- imply that AI review is equivalent to human review
- hide material AI assistance from pull request documentation

All commit sign-off remains a human responsibility under [`DCO.md`](DCO.md).

## Security and Disclosure

Security vulnerabilities must not be reported in public issues.

Follow [`SECURITY.md`](SECURITY.md). Agents must not replace the documented private reporting paths with public issue guidance.

Do not casually weaken or broaden the security policy. If a change affects trust assumptions, reporting expectations, output safety or release integrity, update the relevant documents together.

## Documentation and Policy Changes

When changing behaviour, output semantics, contribution process, workflow controls or security posture:
- update the relevant documentation in the same line of work
- keep language precise and evidence-based
- avoid claiming stronger guarantees than the implementation supports

When editing docs or outputs, preserve Surveyor's conservative language. It should describe observations, limits and classification defensibly.

When creating new Surveyor-owned source files, scripts or other copyright-affected files that support normal comments:
- add a copyright notice near the top of the file
- add `SPDX-License-Identifier: Apache-2.0`
- preserve valid existing file headers unless there is a real reason to normalise them

## Workflow and Repository Automation

Surveyor uses CI to enforce build, test, static analysis, vulnerability analysis, workflow validation and release-surface checks.

When editing workflows:
- keep third-party actions pinned by full SHA
- preserve hardened runner settings unless there is a deliberate reason to change them
- keep CI behaviour explicit and reviewable

If a main CI workflow exists, child `ci-*` workflows should be reusable and called from it rather than auto-triggering independently.

## Verification Expectations

Agents should run the strongest relevant checks for the files they change.

Examples:
- workflow changes: run `actionlint`
- Python helper changes: run `python -m py_compile` and relevant tests
- shell helper changes: run `shellcheck`
- Go changes: run at least targeted `go test`, and broader checks where practical
- header policy changes: run the file-header checker

Current useful commands include:

```bash
actionlint -color .github/workflows/*.yml
python -m py_compile .github/scripts/ci/check_action_pins.py .github/scripts/ci/check_file_headers.py .github/scripts/goreportcard/report_payload.py .github/scripts/goreportcard/enforce_zero_issues.py .github/scripts/goreportcard/tests/test_report_payload.py
python .github/scripts/ci/check_file_headers.py
shellcheck .github/scripts/goreportcard/*.sh
go test ./...
```
