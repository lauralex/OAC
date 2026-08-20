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

- **Status:** Accepted; schema and local transport VM tested
- **Date:** 2026-08-16
- **Decision:** The v5 event record uses stable rule/event IDs and preserves session, generation,
  kernel sequence/time, scan, occurrence, and optional service-ingestion provenance. Display text is
  optional payload and has no policy meaning.
- **Consequence:** The transport preserves source identity instead of translating kernel findings
  into a weaker local record. Delivery does not itself establish policy enforcement or backend
  authenticity. Its hostile input, concurrency, overflow, acknowledgement, and snapshot cases
  passed at acceptance commit `ae1102b35be6b09f4524cea820315530130a5e9d` on Windows 11 build
  26100 under standard Driver Verifier.

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
  `a30ef78819b865786f6f4e104b7a54f48678da7f` on Windows 11 build 26100. Bounded scheduling and
  signed policy were delivered by later decisions; authenticated backend leases remain separate,
  and the local lease-state helper is a backend seam rather than a simulated backend.

## ADR-011: Separate alerts, events, and snapshots by delivery semantics

- **Status:** Accepted; source implemented and VM tested
- **Date:** 2026-08-18
- **Decision:** Retain high/critical records in a fixed acknowledgement queue, keep lower-priority
  operational events in an independent overwrite queue with explicit gaps, and move inventories to
  frozen cursor-paged snapshots. Callback producers only publish one fixed record under a spin
  lock. Production alert loss is terminal; diagnostic overflow remains observable without changing
  lab authority. Keep authenticated persistence and server acknowledgement out of this local
  transport milestone.
- **Consequence:** Inventory pressure cannot silently destroy queued alerts, readers can reconcile
  exact loss, and expensive snapshot capture remains outside callbacks. The service uses one small
  bounded evidence poll/handoff path and fails closed on retained-alert loss instead of pretending
  that in-memory delivery is backend evidence. The complete local and
  disposable-VM/Driver Verifier acceptance passed at commit
  `ae1102b35be6b09f4524cea820315530130a5e9d` on Windows 11 build 26100.

## ADR-012: Keep target inspection off the service health loop

- **Status:** Accepted; source implemented and VM tested
- **Date:** 2026-08-19
- **Decision:** Keep alert acknowledgement and liveness monitoring on the service's 250 ms health
  loop. Queue target inspection into one worker with a single coalescing slot, explicit cancellation,
  continuation state, and fixed per-slice time, memory-region, byte, and thread budgets. Open target
  threads only under the authenticated target-owner identity, immediately restore the restricted
  service identity, and use one shared RAII suspension guard in both service and diagnostic scanners.
- **Consequence:** Slow or repeated inspection cannot create an unbounded work backlog or directly
  block alert acknowledgement. Status exposes strict health, queue, coverage, CPU, storage, and
  suspension metrics. Collection remains separate from WP-08 policy decisions. Commit
  `18aac02d291d9acfcb077fda67c17799a0382391` passed the complete restricted-service and Driver
  Verifier campaign on Windows 11 build 26100: 35 slices and seven sweeps completed without failure
  or cancellation while maximum health-loop delay remained 297 ms.

## ADR-013: Evaluate policy in the service from typed observations

- **Status:** Accepted; source implemented and VM tested
- **Date:** 2026-08-19
- **Decision:** Kernel producers publish typed observations with unevaluated policy state. A shared
  C-compatible catalog binds each stable rule to its event type, category, observation range, and
  required provenance, then maps it through Observe, Enforce, or Strict mode to a separate action
  and five-level policy confidence. The restricted service polls both evidence channels and applies
  the authenticated rule set and deployment mode described by ADR-015. Display payload text and
  signer subject strings are not policy inputs.
  Signer decisions use explicit source, chain, revocation, timestamp, approval, and thumbprint
  fields; the active service uses `unavailable` until authenticated manifest/policy work supplies
  them.
- **Consequence:** Collection no longer assigns policy violations. Source confidence and provenance
  survive evaluation, while actionable local copies retain their exact policy decision. The service
  can terminate its runtime so ordinary cleanup revokes the driver session and target job. It also
  implements the deny-launch action needed by later manifest and signed-policy work, although no
  current rule selects it. Lower-priority records can still be overwritten with explicit gap
  accounting; durable upload and server review remain separate work packages. Commit
  `535730c6828f723c2e42a4721db885fab94505aa` passed the complete Windows 11 build 26100
  disposable-VM and standard Driver Verifier campaign with the policy-enabled service path.

## ADR-014: Authorize one exact game build before launch

- **Status:** Accepted and runtime tested
- **Date:** 2026-08-19
- **Decision:** Use one fixed 512-byte canonical binary manifest with a detached SHA-256/RSA CMS
  signature. Require its signer to be both the exact strong-RSA Authenticode signer of the locked,
  Windows-trusted executable and the certificate SHA-256 explicitly provisioned by protected
  deployment state. Validate the exact executable leaf name, size, SHA-256, component compatibility,
  and bounded validity period before arming the driver. Record a protected per-game sequence and
  manifest/build high-water value; reject lower sequences and same-sequence equivocation. Carry the
  verified manifest digest through driver session status. Keep all certificate, filesystem,
  registry, and hashing work in the restricted service.
- **Consequence:** A valid Windows signature alone cannot self-authorize a build, copied or modified
  manifest bytes cannot authorize a launch, and service restart does not erase rollback state. The
  current schema authorizes only the main executable. Manifest-key rotation/revocation, approved
  modules and middleware, and backend admission remain later work. The
  disposable-VM test package uses its ephemeral test signer only through the isolated installer's
  exact protected pin; it is not a production signing design. Commit
  `535730c6828f723c2e42a4721db885fab94505aa` passed accepted-launch and
  modified/wrong-build/expired/rollback rejection cases in the complete Windows 11 build 26100
  disposable-VM and standard Driver Verifier campaign.

## ADR-015: Authenticate policy and preserve update history

- **Status:** Accepted; source and runtime tested
- **Date:** 2026-08-20
- **Decision:** Use one fixed 1024-byte canonical policy record with a detached SHA-256/RSA CMS
  signature and an independent protected signer pin. Bind its rule set and deployment mode to an
  exact game, build, and channel, bounded validity period, and minimum component revisions. Store a
  fixed per-game/channel record containing the current policy digest, sequence and version plus the
  historic version high-water mark. Reject replay and same-sequence equivocation. Permit rollback
  only when a newly signed record names the exact current version and digest, without lowering the
  historic high-water mark. Commit an accepted emergency revocation before refusing service startup.
- **Consequence:** Local file replacement cannot silently select unsigned rules, service restart
  cannot erase update history, and an emergency record cannot be cleared by restoring an older
  package. Policy files remain local deployment inputs; remote delivery, signer rotation metadata,
  backend admission, durable evidence acknowledgement, and game-specific module approval remain
  separate work. Driver-free validation and isolated-package fixtures cover canonical validation,
  scope, expiry, replay, equivocation, explicit rollback, and emergency revocation. Acceptance
  commit `865a9f9b5d665c1c69fcf8b39486722046d6647f` passed the signed-policy positive and negative cases
  in the complete Windows 11 build 26100 restricted-service and Driver Verifier campaign.

## ADR-016: Bind production authority to a bounded backend session

- **Status:** Accepted; implemented and VM tested
- **Date:** 2026-08-20
- **Decision:** Define one strict, transport-independent backend contract for session open, lease
  renewal, evaluated-evidence delivery, and monotonic acknowledgement. Derive a nonzero binding
  digest from the backend session identity and both open nonces, require it in the production driver
  claim, and return it through every correlated status response. Keep the service queue fixed,
  require a currently healthy lease before launch, advance retained-alert acknowledgement only
  after backend acknowledgement, and make replay, malformed correlation, lease loss or revocation,
  queue exhaustion, and acknowledgement timeout terminal service outcomes. Keep network I/O and
  authentication entirely behind a nonblocking service transport interface; provide a protected
  deterministic test double rather than embedding a reusable credential or choosing a production
  network library in this milestone.
- **Consequence:** The local control path now has explicit online-session semantics and preserves
  evidence until a correlated backend acknowledgement. Driver authority is tied to the exact
  service/backend session without moving time, policy, or network work into the kernel. The test
  backend can exercise replay and loss paths reproducibly, but it is not a deployable admission
  service or durable evidence store. Production transport, backend operations, credential lifecycle,
  retention, and remote policy delivery remain separate deployment work. Implementation commit
  `47c04005e66f1fd61ae9fe9a35260f19ee447dd1` passed driver-free validation and the complete
  Windows 11 build 26100 disposable-VM and Driver Verifier campaign, including nonce replay,
  withheld-acknowledgement and lease-loss containment, and fresh-session recovery.

## ADR-017: Keep gameplay truth server-authoritative

- **Status:** Accepted; source implemented and driver-free tested
- **Date:** 2026-08-20
- **Decision:** Define a portable canonical event interface for authoritative game servers rather
  than treating endpoint telemetry as gameplay truth. Bind each movement observation to the exact
  game, build, backend session, match, player pseudonym, replay digest, monotonic sequence, server
  tick, and replay offset. Keep one bounded detector state per complete identity scope. Reject
  replay, reordering, malformed data, foreign scope, and corrupt state without mutation. Demonstrate
  the boundary with a tick-scaled movement and reported-velocity detector whose typed behavior risk
  remains distinct from a separately supplied endpoint-risk input. Endpoint-only risk remains
  observational; Review or Reject requires a server-side behavior finding.
- **Consequence:** OAC now has a small game/server integration contract and one explainable
  behavioral detector without adding game, network, storage, or account dependencies to the local
  Windows controller. The server-authority flag records provenance but does not authenticate an
  untrusted transport. Production use still requires an authenticated game adapter, durable
  partitioned state and replay storage, signed per-build rules, additional domain detectors, and a
  reviewed adjudication process. Driver-free tests cover canonical construction, hostile records
  and rules, identity and replay rejection, gaps, exact movement bounds, corrections, coordinate
  extremes, risk combination, and saturation.
