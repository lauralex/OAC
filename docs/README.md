# OAC documentation

The root [README](../README.md) is the public project introduction. This directory separates
technical references for users and evaluators from maintainer-facing engineering records.

Source code and shared protocol headers remain authoritative for implemented behavior. Plans and
research notes provide context, not proof that a capability is available or accepted.

## User and evaluator documentation

| Document | Purpose |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Component boundaries, production launch flow, session lifetime, and planned architecture |
| [`SECURITY_MODEL.md`](SECURITY_MODEL.md) | Assets, adversaries, trust boundaries, failure behavior, and unsupported guarantees |
| [`PROTOCOL.md`](PROTOCOL.md) | Production and diagnostic wire contracts, validation, authority, and state transitions |
| [`GAME_INTEGRATION.md`](GAME_INTEGRATION.md) | Authoritative game events, replay state, movement rules, risk decisions, and deployment boundary |
| [`CAPABILITIES.md`](CAPABILITIES.md) | Production-control scope, detailed lab scanner matrix, evidence semantics, and limitations |
| [`driver-load-review.md`](driver-load-review.md) | Exact-image research into the normal Windows driver-load path and its design consequences |
| [`hwid-review.md`](hwid-review.md) | Hardware-identity source review, privacy rules, and stability constraints |
| [`../SECURITY.md`](../SECURITY.md) | Private vulnerability reporting and sensitive-data handling |

## Contributor documentation

| Document | Purpose |
|---|---|
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Development environment, change-specific validation, and pull-request requirements |
| [`test-signing.md`](test-signing.md) | Safe disposable-VM package, signing, installation, validation, and cleanup workflow |
| [`development/README.md`](development/README.md) | Progress, test evidence, decisions, baseline, roadmap, and other maintainer records |

When documentation and code disagree, verify the code and shared protocol first, then correct the
documentation in the same change. Compatibility statements must identify the exact Windows build
and security configuration that produced their evidence.
