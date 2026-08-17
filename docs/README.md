# OAC documentation

The root `README.md` and source describe the current implementation. Documents in this directory
have an explicit role; a research note or plan is not runtime capability or test evidence.

| Document | Status | Purpose |
|---|---|---|
| [`../README.md`](../README.md) | Current overview | Implemented capabilities, limitations, build/run instructions, and recorded validation |
| [`BASELINE.md`](BASELINE.md) | Frozen snapshot | Starting revision, toolchain, build evidence, test boundary, and carried risks before v5 work |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Current source and planned | Status-only service path, lab scanner, per-file lifetime, tombstone, and next architecture steps |
| [`SECURITY_MODEL.md`](SECURITY_MODEL.md) | Current source and planned | Assets, current trust boundaries, evidence state, invariants, and unsupported guarantees |
| [`PROTOCOL.md`](PROTOCOL.md) | v5 production control; v4 lab-only | Implemented messages, strict validation, session authority, event schema, and missing transports |
| [`TEST_MATRIX.md`](TEST_MATRIX.md) | Evidence matrix | Host, protocol, service, VM, compatibility, and work-package acceptance coverage |
| [`test-signing.md`](test-signing.md) | Current lab procedure | Create, validate, install, test, and remove a self-signed package in a disposable VM |
| [`driver-load-review.md`](driver-load-review.md) | Exact-image research note | Safe-copy IDALib evidence about the normal Windows driver-load path and its design consequences |
| [`hwid-review.md`](hwid-review.md) | Exact-image research note | Safe-copy driver research that informed supported, privacy-preserving identity collection |
| [`hardening-plan.md`](hardening-plan.md) | Proposed plan | Complete target beyond the current partial foundation; a roadmap is not implementation evidence |
| [`../PROGRESS.md`](../PROGRESS.md) | Active work record | Work-package status, exact evidence, and unresolved gates |
| [`../DECISIONS.md`](../DECISIONS.md) | Decision log | Accepted architecture and validation decisions |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Contributor guide | Toolchain, validation expectations, and review workflow |
| [`../SECURITY.md`](../SECURITY.md) | Security policy | Private reporting, sensitive-data handling, and scope boundaries |

When a document and code disagree about current behavior, verify the code and shared protocol, then
correct the documentation in the same change. Compatibility statements must identify the exact
Windows build and security configuration that produced the evidence.
