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

## ADR-004: Use the production protocol for privileged control

- **Status:** Accepted; foundation implemented and VM tested
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

## ADR-006: Define provenance before adding production transport

- **Status:** Accepted; schema and local transport implemented
- **Date:** 2026-08-16
- **Decision:** The v5 event record uses stable rule/event IDs and preserves session, generation,
  kernel sequence/time, scan, occurrence, and optional service-ingestion provenance. Display text is
  optional payload and has no policy meaning.
- **Consequence:** The transport preserves source identity instead of translating kernel findings
  into a weaker local record. Delivery does not itself establish policy enforcement or backend
  authenticity.

## ADR-007: Retain a live-target tombstone after cleanup

- **Status:** Accepted; source implemented and target-live path VM tested
- **Date:** 2026-08-16
- **Decision:** Cleanup closes authority and drains rundown, but a session that still references a
  live target remains installed as an unusable tombstone until target exit.
- **Consequence:** A replacement controller cannot claim the device while stale target protection
  survives. The production service transaction and the dedicated target-live case passed at
  implementation commit `bbf8f06bd9383be2d9de079a95b67d87848c280c` on Windows 11 build 26100.

## ADR-008: Keep the first production service surface narrow

- **Status:** Accepted; source implemented and VM tested
- **Date:** 2026-08-16
- **Decision:** The restricted service owns one persistent production session and exposes
  identity-checked hello/status plus one serialized executable launch to the standard-user launcher.
  Launch resolution and process creation use the authenticated caller identity; the service arms the
  kernel ticket, creates the process suspended, confirms the exact handle, and resumes it.
- **Consequence:** The production surface has no diagnostic scans, arbitrary arguments, policy or
  manifest transfer, evidence upload, or backend protocol. One target is allowed per service session;
  signed executable authorization remains a separate work package.

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

## ADR-010: Let the Windows job own target-tree lifetime

- **Status:** Accepted; source implemented and VM tested
- **Date:** 2026-08-18
- **Decision:** Create one unnamed service-owned job with exactly
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, assign and verify the confirmed target while it is still
  suspended, then resume it. Graceful stop explicitly revokes the driver session before closing the
  job. Unexpected service exit relies on ordinary Windows handle teardown. Record the first driver
  session-loss cause in a monotonic status latch. Do not add a completion port, watcher thread,
  process registry, or polling-based lifetime authority for this milestone.
- **Consequence:** The operating system terminates the target tree when the service loses ownership,
  children inherit the same containment boundary, and a replacement service can observe prior
  session loss. The crash and graceful-stop paths passed at implementation commit
  `a30ef78819b865786f6f4e104b7a54f48678da7f` on Windows 11 build 26100. Bounded scheduling,
  centralized policy, and authenticated backend leases remain separate work packages; the local
  lease-state helper is a policy seam, not a simulated backend.

## ADR-011: Separate alerts, events, and snapshots by delivery semantics

- **Status:** Accepted; source implemented, VM acceptance pending
- **Date:** 2026-08-18
- **Decision:** Retain high/critical records in a fixed acknowledgement queue, keep lower-priority
  operational events in an independent overwrite queue with explicit gaps, and move inventories to
  frozen cursor-paged snapshots. Callback producers only publish one fixed record under a spin
  lock. Production alert loss is terminal; diagnostic overflow remains observable without changing
  lab authority. Keep authenticated persistence and server acknowledgement out of this local
  transport milestone.
- **Consequence:** Inventory pressure cannot silently destroy queued alerts, readers can reconcile
  exact loss, and expensive snapshot capture remains outside callbacks. The service uses one small
  bounded alert poll/handoff path and fails closed on loss instead of introducing the later worker
  scheduler or pretending that in-memory delivery is backend evidence.
