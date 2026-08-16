# OAC documentation

The root `README.md` and source describe the current implementation. Documents in this directory
have an explicit role; a research note or plan is not runtime capability or test evidence.

| Document | Status | Purpose |
|---|---|---|
| [`../README.md`](../README.md) | Current overview | Implemented capabilities, limitations, build/run instructions, and recorded validation |
| [`test-signing.md`](test-signing.md) | Current lab procedure | Create, validate, install, test, and remove a self-signed package in a disposable VM |
| [`driver-load-review.md`](driver-load-review.md) | Exact-image research note | Safe-copy IDALib evidence about the normal Windows driver-load path and its design consequences |
| [`hwid-review.md`](hwid-review.md) | Exact-image research note | Safe-copy driver research that informed supported, privacy-preserving identity collection |
| [`hardening-plan.md`](hardening-plan.md) | Proposed plan | Target service, protocol v5, policy, telemetry, backend, and release architecture; not implemented behavior |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Contributor guide | Toolchain, validation expectations, and review workflow |
| [`../SECURITY.md`](../SECURITY.md) | Security policy | Private reporting, sensitive-data handling, and scope boundaries |

When a document and code disagree about current behavior, verify the code and shared protocol, then
correct the documentation in the same change. Compatibility statements must identify the exact
Windows build and security configuration that produced the evidence.
