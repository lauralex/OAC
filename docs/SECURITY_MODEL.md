# OAC security model

**Status:** WP-01 through WP-12 controls and organization accepted locally and in the disposable-VM
campaign at implementation commit `67d3f616cdb13f1ac10877d067da1b54cca5e51c` on Windows 11 build
26100. PR #18 hosted checks also passed. WP-13's portable game/server records and reference movement
detector passed local and PR #19 hosted driver-free acceptance at
`8eca1747680f7dc9ad084d1e1897f30bfec08d83`; they are not a deployed game backend. The current
WP-14 source adds an unsigned release-candidate boundary, deterministic metadata, SPDX inventory,
and symbol separation; production certification, keys, and distribution remain external.

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

This model separates source state, test evidence, planned controls, and unsupported guarantees.
[`../SECURITY.md`](../SECURITY.md) covers vulnerability reporting; this document covers assets,
trust boundaries, adversaries, and failure behavior.

## Assets

- Integrity and availability of the protected game process.
- Authority to configure and query the OAC driver.
- Kernel observations and their source sequence, time, and completeness.
- Game-build, rule, policy, and component identity.
- Authoritative match state, replay correlation, and server-side detector integrity.
- Player and hardware-identity privacy.
- Signing material, backend credentials, and revocation state.

## Current trust boundaries

| Boundary | Current behavior | Evidence state |
|---|---|---|
| Driver load | Windows Code Integrity decides whether the demand-start driver image may load | Existing control; current driver remains unsigned by default |
| Driver device | Production DACL grants SYSTEM and the exact service SID; Administrators are added only with `LabMode=1` | Named VM campaign passed service access and denied direct opens from LocalSystem, limited-user, and administrator probes |
| Service identity | The test installer sets SYSTEM owner/group and explicitly grants Administrators and Interactive query-status/start only; the restricted, session-0 LocalSystem service verifies its enabled and restricted service SID before opening the driver | Structural readback and the complete service start/status/launch path passed on Windows 11 build 26100; broader effective-right and production-deployment testing remains pending |
| Driver controller | One production session is bound to the CREATE-owner process object, service process object, exact file object, random session ID, and generation | Driver-backed lifecycle, wrong-process, cleanup, and race cases passed on the named campaign |
| Launcher IPC | Local, remote-rejecting named pipe with server/client identity cross-checks for status and one executable launch | Four standard-user status calls and two launches passed; dedicated AppContainer, remote, and impersonation-negative cases remain pending |
| Protected target | The service resolves one executable under the authenticated caller identity, creates it suspended with that token, and uses a bounded one-use ticket to bind and confirm the exact process before resume | Creation-time binding, exact-handle confirmation, and resume passed on the named campaign |
| Target-tree lifetime | The service assigns the suspended target to an unnamed kill-on-close job before resume; graceful stop explicitly revokes the driver session and service failure closes both authority handles | The named VM campaign verified parent/child termination after service crash and graceful stop, plus SCM recovery |
| Session liveness | Status carries a monotonic device-lifetime loss sequence and first observed revoke cause | The named campaign observed exact sequence `0,1,2` with `none`, `service exit`, then `requested shutdown` |
| Service scheduler | Alert and liveness work remains on the health loop; one coalescing worker incrementally samples target memory regions and threads under fixed budgets | Driver-free budget, metric, and resume tests, Clang-Tidy, and the restricted-service campaign passed; the measured health-loop delay stayed within its bound |
| User-mode handles | Object callbacks strip selected dangerous process/thread rights for a bound target | Baseline and Verifier protected-launch/scanner paths passed on the named campaign |
| Driver-load evidence | Load callback plus monotonic post-start counters | Armed renamed-driver gate and persistent-latch checks passed on the named campaign |
| Typed evidence | Separate retained-alert and overwrite-event queues preserve source identity and explicit loss; frozen kernel-module snapshots use stable paging | Hostile, concurrency, overflow, acknowledgement, and snapshot cases passed in the named baseline and Driver Verifier campaign |
| Local report | The diagnostic scanner uses a per-run unkeyed SHA-256 chain and artifact digests | Lab-only and not authenticated |
| Local policy | The service applies an authenticated typed rule set and signed Observe, Enforce, or Strict mode; driver producers cannot assign policy outcomes, and display text is excluded from the evaluator | Driver-free catalog, mode, signer-state, hostile-input, and text-independence tests plus integrated signed-policy VM execution pass |
| Game manifest | The service requires a canonical detached-signed manifest, explicitly provisioned signer pin, exact executable and Authenticode signer, bounded compatibility/expiry, and protected per-game high-water state before arming the driver | The named campaign accepted two authorized launches and rejected modified, wrong-build, expired, and rollback manifests; the driver-free suite covers the record and decision rules |
| Signed policy | A canonical detached-signed record binds rules and mode to game/build/channel scope, component compatibility, expiry, persistent update state, explicit rollback authorization, and emergency revocation | Driver-free, signed-package, restricted-service, and Driver Verifier acceptance passed at the named commit |
| Backend session | The service requires a correlated session before claiming the driver, binds a digest of the session and nonces into driver status, applies signed lease/renewal/acknowledgement bounds, and stops on replay, expiry, revocation, queue exhaustion, or acknowledgement timeout | Driver-free and Windows 11 VM/Verifier cases passed replay rejection, acknowledgement-loss and lease-loss target-tree containment, and fresh-session recovery; the included transport remains a protected test double rather than a production network service |
| Game/server behavior | Portable canonical records bind authoritative movement to game, build, backend session, match, player pseudonym, replay, sequence, and server tick; a deterministic detector enforces replay ordering, movement and velocity bounds, and typed risk | Driver-free C/C++ coverage exercises hostile records and rules, replay, identity, gaps, exact bounds, server corrections, coordinate extremes, and combined behavior/endpoint risk; no production transport or game deployment is implied |
| Release supply chain | A checked-in profile binds versions, compatibility revisions, SDK, and exact public/lab artifacts to source; the candidate carries hashes and an SPDX SBOM, embeds leaf-only PDB references, and separates private symbols | Local and hosted candidate validation can prove the unsigned boundary; only Microsoft certification, protected production signatures, final signed manifests, and platform admission can establish publication trust |
| Privacy operations | Raw hardware values stay out of reports; typed evidence, pseudonymous game records, role separation, bounded retention, access/deletion, appeal, and incident requirements are documented | Source enforces the local HWID/report boundary; a production operator and backend are still required to implement and audit the operational policy |

## Production authority

Production file creation and claim require the exact restricted service token, not Administrator
membership. Negotiation and claim occur on one persistent service handle. Every later accepted production
request must use that file from the referenced service process and match the session ID, generation,
active state, session mode, and backend binding digest. Numeric PIDs are returned only for
diagnostics and cannot authorize a request.

One active session is allowed. A different file can negotiate but cannot claim or reuse copied
session values. A duplicated handle used by another process is rejected by process-object identity.
Accepted requests hold rundown protection so cleanup can stop acquisition and wait for in-flight
work before releasing controller objects.

Diagnostic and production authorization cannot be mixed on one file. Negotiation and claim are
serialized: a production-negotiated or claimed file cannot issue privileged diagnostic operations,
while a file that claimed the unnegotiated diagnostic path cannot later negotiate production.

### Tombstone invariant

Cleanup marks the session closing and records file-cleanup revocation. If no target is referenced,
the session retires. If a target is still live, the cleaned session stays installed as an unusable
tombstone and blocks a replacement claim. Only target exit removes the last target reference and
permits retirement. This prevents a new controller from inheriting a driver whose prior target
protection state is still active.

The invariant is implemented for diagnostic binding and the production service's serialized arm,
suspended create, confirm-or-cancel, and resume transaction. Driver-backed acceptance was recorded
for implementation commit `a30ef78819b865786f6f4e104b7a54f48678da7f` on Windows 11 build 26100.

## In-scope adversaries

- Unprivileged and ordinarily elevated user-mode processes attempting inspection, injection,
  modification, suspension, termination, or handle duplication.
- A local process attempting to impersonate the launcher, pipe server, service, device-file owner,
  or an earlier session generation.
- User-mode DLL injection, manually mapped user images, debuggers, instrumentation, and suspicious
  overlay or input behavior in the lab scanner.
- Known denied or vulnerable drivers and observable driver-load changes.
- Some manually mapped kernel code when it leaves loader-independent execution or control-flow
  evidence.
- Races involving process creation, service or controller exit, PID reuse, cleanup/close, telemetry
  flooding, malformed requests, and partial failures.

An administrator capable of obtaining SYSTEM, replacing trusted binaries, taking ownership of or
changing the service configuration, or loading arbitrary kernel code is only partially observable.
The service SID and per-file session raise the control boundary but do not make a compromised local
administrator, kernel, firmware, or hypervisor trustworthy.

## Security invariants implemented in source

- The driver and service remain demand-start; `OAC/OAC.inf` keeps `StartType=3`.
- Production code does not load vulnerable drivers, patch Code Integrity or PatchGuard, hide kernel
  state, install undocumented loader hooks, or weaken host security controls.
- Kernel callbacks and IPI routines perform bounded, IRQL-appropriate work.
- Private kernel profiles are optional and exact-image gated.
- The production protocol uses fixed, C-compatible layouts with explicit `MessageType`, strict sizes, request/session
  correlation, reserved-field checks, flag masks, and bounded payload validation.
- Production device and claim authorization require the exact restricted service identity; direct
  administrator control is lab-only.
- The disposable-VM installer sets the service owner and group to SYSTEM; its exact DACL gives
  SYSTEM full control and explicitly grants Administrators and Interactive only query-status and
  start rights. Production deployment tooling must reproduce and verify this policy.
- Each file selects one protocol authority path; diagnostic and production modes cannot be combined to bypass state or
  identity checks.
- File cleanup drains in-flight requests, revokes authority, and preserves a live-target tombstone.
- A production launch ticket is random, bounded, one-use, and bound to the exact service creator and
  canonical image path; monitoring requires confirmation through an exact user-mode process handle.
- Handle filtering covers the creation-bound target immediately for ordinary user-mode requestors.
  The System process and Windows protected processes remain explicit trusted operating-system
  requestors because required process and thread initialization continues after the first resume;
  this exemption does not grant production-session authority.
- The service authenticates the pipe client, opens and resolves the executable under impersonation,
  duplicates the same identity to a primary token, and keeps the selected file locked against writes
  and deletion through process creation.
- Before arming the driver, the service validates an exact 512-byte canonical manifest and detached
  SHA-256/RSA CMS signature, the locked executable's Windows trust and strong-RSA Authenticode
  signer, the protected deployment signer pin, component compatibility, expiry, and exact leaf
  name/size/SHA-256. It rejects rollback and same-sequence equivocation using protected per-game
  high-water state, then carries the verified manifest digest in correlated driver status.
- The production controller may create exactly one child process per session; additional children
  from that service process are denied after target binding.
- The service owns one unnamed job with exactly `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, verifies target
  membership while the process is suspended, and closes the job on every stop path.
- Graceful stop requests an idempotent driver-session revoke. Cleanup and service-exit races record
  only the first loss cause, and a monotonic latch makes prior loss visible to a replacement service.
- High/critical records are retained until acknowledged. Alert overflow preserves queued records,
  records exact lost-severity provenance, and revokes production authority on the next authenticated
  session operation; callback publication remains fixed-size and nonblocking. The service preserves
  kernel provenance, adds local ingestion ordering, and drains once more before orderly shutdown.
- Lower-priority event overwrite cannot consume alert capacity, and frozen snapshot work is paged,
  identity-bound, expiring, and unavailable for new work after revocation.
- Before claiming production authority, the service establishes one authenticated backend session
  and binds its nonzero digest into the driver session. Nonces, request sequences, response
  correlation, lease sequences, and evidence acknowledgements are strictly validated. The service
  queue is fixed-size, launch requires a currently healthy lease, and replay, lease loss,
  revocation, queue exhaustion, or acknowledgement timeout terminates the service and target job.
  The kernel performs no network or blocking backend work.
- Driver producers emit observations with unevaluated policy state. The service polls both evidence
  channels and evaluates stable rule ID, event type, category, severity range, and required
  provenance through the authenticated policy's canonical rule set. Source confidence and
  provenance remain unchanged; the policy action and policy confidence are separate typed results.
  Display text is not an input.
- The game/server interface accepts only exact canonical records. Sequence, server tick, and replay
  offset are monotonic within one complete identity scope; replay, reordering, foreign scope,
  malformed input, and corrupt persistent state do not advance the detector. Server-authoritative
  movement and velocity findings remain distinct from the separately supplied endpoint-risk input,
  endpoint-only risk remains observational, and all risk arithmetic saturates at the documented
  bound.
- The signed Observe, Enforce, or Strict mode can retain warnings and review requests or stop the
  service runtime so ordinary cleanup revokes the driver session and closes the target job. The
  service also supports a deny-launch action for later game-specific rules. Manifest or policy-scope
  rejection is an independent pre-arm authorization decision.
- The health loop never performs target memory or thread inspection. One cancellation-aware worker
  keeps continuation state and enforces per-slice time, byte, region, and thread limits. It opens
  threads under the authenticated target-owner identity, reverts immediately, and uses one shared
  RAII guard so every successful suspension has an explicit resume and cleanup fallback.
- Raw hardware serials are not written to reports; removable devices do not become core anchors.
- Public candidates contain no private symbols, signing material, lab executables, reports, or raw
  evidence. Every included file is exact-name and hash allowlisted.

WP-01 through WP-12 statements combine source behavior with one exact platform acceptance run. The
current driver-backed production, service installation, lifecycle, race, job/liveness, typed
evidence, signed-policy, signed-manifest, backend-session, snapshot, and standard Driver Verifier
campaign passed on Windows 11 build 26100 with zero crash events and minidumps. That result does not
replace the broader supported-platform, effective-right, compatibility, or production-deployment
matrix. WP-13 changes only portable shared code and driver-free tests, so it does not extend the
recorded Windows runtime claim.

## Planned controls

- Manifest and policy signer rotation and revocation metadata, approved
  module/middleware/child-process scope, remote policy delivery, production authenticated network
  transport, durable evidence and replay storage, a production game adapter, broader game-specific
  detectors, production certification/signing, and backend operations.

## Evidence and enforcement

An observation, confidence assessment, policy violation, and enforcement action are distinct. A
single weak heuristic such as an overlay style, virtualization indicator, or global DR7 value is
not proof of cheating. Evidence loss, incomplete scanning, unavailable security state, or an
unsupported platform must remain explicit rather than silently becoming a clean result. Display
text has no policy meaning in the production schema.

The stable rule identities and default rule set are compiled, while the authenticated policy selects
the active thresholds, actions, and deployment mode. The signer model records signature source,
chain, revocation, timestamp, approval flags, and an exact certificate thumbprint as typed fields.
Runtime-module approval classifications remain explicitly unavailable until game-specific policy
supplies them; game-manifest authorization is a separate exact pre-launch check and does not infer
trust from an image name or display string. Lower-priority overwrite gaps remain visible transport facts;
only records actually delivered to the service can receive a local policy decision.

Load-image callbacks are observational and cannot veto a mapping before `DriverEntry`. The diagnostic
path can fail its gate after detecting the latch; the production launch transaction closes the
creation-time target-binding gap but does not replace Windows Code Integrity or authenticated
backend controls.

## Unsupported guarantees

- Universal detection after arbitrary kernel compromise.
- Reliable observation beneath a hostile hypervisor or malicious firmware.
- DMA prevention without platform/IOMMU support.
- Support for x86, ARM64, Windows XP, or every historical Windows release.
- A literal block on all process interaction or all kernel execution.
- Authentication from the current unkeyed local report chain.

Compatibility must be stated per tested Windows build, architecture, security configuration, and
game workload. The current evidence and production admission criteria are listed in
[`SUPPORT.md`](SUPPORT.md); the verified support matrix remains incomplete.

## Lab-only operations

Diagnostic direct driver control, test signing, self-signed certificates, driver installation,
Driver Verifier, private kernel profiles, `DbgUiRemoteBreakin` patching, and
`ThreadHideFromDebugger` belong only in documented diagnostic or disposable-VM paths. They are not
production trust mechanisms.
