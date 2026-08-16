# OAC engineering decisions

This log records consequential decisions adopted by the hardening work. Proposed details that are
not accepted here remain proposals in `docs/hardening-plan.md`.

## ADR-001: Preserve a factual implementation baseline

- **Status:** Accepted
- **Date:** 2026-08-16
- **Decision:** Freeze `075ad2109f84cce90727f8ba65f87b807500e6b7` as the WP-00 baseline and
  retain `90dfdfaa9178cbc0274394d1aec77b40ef643762` as the reviewed source baseline. Record that the
  delta contains scaffolding only.
- **Consequence:** Later claims must name the revision and evidence that changed the baseline.
  Historical README validation is labeled historical instead of silently reused as a fresh run.

## ADR-002: Keep the driver demand-start and defensive

- **Status:** Accepted
- **Date:** 2026-08-16
- **Decision:** Keep `StartType=3` and use documented Windows interfaces. Do not add mapper/BYOVD
  loading, Code Integrity or PatchGuard patching, hiding, undocumented loader hooks, or boot-start
  persistence.
- **Consequence:** A public load-image callback is treated as observation, not a pre-map veto.
  Unsupported or unavailable evidence degrades explicitly.

## ADR-003: Separate current, tested, planned, and unsupported behavior

- **Status:** Accepted
- **Date:** 2026-08-16
- **Decision:** Architecture and security documents label evidence state explicitly. Source and the
  shared protocol remain authoritative for implemented behavior; the hardening plan is a target.
- **Consequence:** WP-01 through WP-03 may be described as implemented in source while their work
  packages remain incomplete until the named host and disposable-VM acceptance tests pass.

## ADR-004: Use protocol v5 for production control

- **Status:** Accepted; foundation implemented, acceptance pending
- **Date:** 2026-08-16
- **Decision:** Preserve v4 only as an explicit `LabMode=1` diagnostic path. Production authority
  uses the restricted service, exact v5 negotiation, and a per-file-object session.
- **Consequence:** The launcher receives no driver handle, `OAC-Client` refuses production mode,
  and required service/session validation cannot fall back to v4.

## ADR-005: Split host-safe and kernel-runtime validation

- **Status:** Accepted
- **Date:** 2026-08-16
- **Decision:** Run pure unit tests in CI for Debug and Release. Keep driver loading, test signing,
  protocol integration, crash testing, and Driver Verifier in isolated disposable VMs.
- **Consequence:** The workflow builds and runs the pure protocol unit executable in both
  configurations. A green hosted `build` check is still not runtime-driver evidence, and public
  unsigned Release artifacts exclude PDBs.

## ADR-006: Define provenance before adding v5 transport

- **Status:** Accepted; schema implemented, transport planned
- **Date:** 2026-08-16
- **Decision:** The v5 event record uses stable rule/event IDs and preserves session, generation,
  kernel sequence/time, scan, occurrence, and optional service-ingestion provenance. Display text is
  optional payload and has no policy meaning.
- **Consequence:** The schema and hostile payload validation can be tested before WP-06 transport.
  Defining the record does not advertise typed event delivery or establish policy enforcement.

## ADR-007: Retain a live-target tombstone after cleanup

- **Status:** Accepted; source implemented, target-live acceptance pending
- **Date:** 2026-08-16
- **Decision:** Cleanup closes authority and drains rundown, but a session that still references a
  live target remains installed as an unusable tombstone until target exit.
- **Consequence:** A replacement controller cannot claim the device while stale target protection
  survives. Production cannot exercise this path until launch-ticket target binding exists; the v4
  lab path and a dedicated VM case must validate it in the meantime.

## ADR-008: Keep the first production service surface status-only

- **Status:** Accepted; source implemented, VM acceptance pending
- **Date:** 2026-08-16
- **Decision:** The restricted service owns one persistent v5 session and exposes only identity-
  checked hello/status IPC to the standard-user launcher.
- **Consequence:** This phase can validate service, device, IPC, and session authority without
  pretending that launch tickets, target liveness, manifests, policy, telemetry, or backend leases
  exist.

## ADR-009: Defer forced integrity on user-mode test binaries

- **Status:** Accepted
- **Date:** 2026-08-16
- **Decision:** Retain `/INTEGRITYCHECK` on the x64 driver. Do not set the forced-integrity PE flag
  on unsigned CI executables or on user-mode binaries signed by the disposable VM's self-signed
  test certificate. Enable it for production user-mode components with the supported production
  signing pipeline.
- **Consequence:** Local units and the isolated test package remain loadable. Production packaging
  must add and validate forced integrity together with authorized release signing; a test
  certificate is not treated as equivalent production trust.
