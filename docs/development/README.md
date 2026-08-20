# OAC development records

This index separates maintainer-facing engineering state from the public project overview. These
records are intentionally detailed: they track exact commits, test environments, work-package
status, historical baselines, and architecture decisions. They should not be read as general
product guarantees.

## Current engineering state

| Record | Purpose |
|---|---|
| [`../../PROGRESS.md`](../../PROGRESS.md) | Current work-package status, exact validation evidence, and remaining gates |
| [`../TEST_MATRIX.md`](../TEST_MATRIX.md) | Local, CI, protocol, service, VM, compatibility, and acceptance coverage |
| [`../../DECISIONS.md`](../../DECISIONS.md) | Accepted architecture and validation decisions |
| [`../hardening-plan.md`](../hardening-plan.md) | Target architecture and remaining work packages; roadmap text is not implementation evidence |

## Historical and operational records

| Record | Purpose |
|---|---|
| [`../BASELINE.md`](../BASELINE.md) | Frozen pre-hardening source and evidence snapshot |
| [`../test-signing.md`](../test-signing.md) | Disposable-VM packaging, signing, containment, and cleanup procedure |
| [`../RELEASE.md`](../RELEASE.md) | Release candidate, signing/certification, symbol, rotation, and update procedure |
| [`../OPERATIONS.md`](../OPERATIONS.md) | Deployment, rollback, outage, compromise, and incident runbooks |
| [`../../AGENTS.md`](../../AGENTS.md) | Repository invariants and workflow instructions for coding agents and maintainers |
| [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) | Toolchain, validation, and pull-request requirements |

## Documentation rules

- Keep the root [`README.md`](../../README.md) concise and audience-facing.
- Put exact campaign hashes, frozen history, work-package bookkeeping, and pending engineering gates
  in the records linked above.
- Keep current implementation, planned behavior, and historical evidence clearly labeled.
- Bind compatibility and runtime claims to the exact source, Windows build, and security
  configuration that produced the evidence.
- Never publish signing keys, raw hardware identifiers, private reports, VM images, dumps, or other
  sensitive test artifacts.
