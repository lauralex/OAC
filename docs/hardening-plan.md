# OAC production hardening plan

> [!IMPORTANT]
> This document is a planning reference, not a description of the current implementation and not
> an agent task list. Imperative language below records proposed work. Only an active, scoped
> request authorizes implementation. See the root README and source for current behavior.

> [!NOTE]
> Implementation and acceptance state are tracked in `../PROGRESS.md`. This roadmap is not updated
> in place to imply that proposed deliverables exist.

**Document status:** Proposed target architecture and roadmap
**Target repository:** `lauralex/OAC`
**Reviewed baseline:** `90dfdfaa9178cbc0274394d1aec77b40ef643762`
**Target platform:** Native x64 Windows 10, Windows 11, and corresponding supported Windows Server releases
**Primary implementation languages:** C17 kernel driver, C++20 user mode
**Initial migration target:** Protocol v5 and dedicated Windows service

---

## 1. Purpose

This specification converts the current OAC project from a broad endpoint-integrity research prototype into a professional anti-cheat foundation.

The current code contains valuable engineering:

- An unsigned-by-default, signable demand-start WDM driver.
- Process/thread handle filtering through object callbacks.
- Referenced process-object identities rather than PID-only identity.
- Bounded kernel scans and dynamic processor handling.
- Driver, module, process, handle, thread, memory, debugger, platform, service, device, and HWID observations.
- Exact-build gating for private kernel profiles.
- A legacy suspended diagnostic launch and report gate.
- A protocol test and disposable-VM/Driver-Verifier harness.
- Careful documentation of limitations.

The main weaknesses are architectural rather than a lack of detections:

- Trust is bootstrapped from the first administrative process.
- Session ownership is global and primarily process-based.
- The target is bound after creation.
- Service/client death is not tightly bound to game death.
- A single overwrite ring mixes critical alerts with inventories.
- Expensive scans block the same loop that monitors health.
- Policy is duplicated and partly driven by strings.
- Kernel provenance is not preserved through reporting.
- Game build identity and backend session authenticity are missing.
- Most detections are endpoint anomalies rather than game-specific cheating behavior.

This document defines the target architecture, invariants, protocol, work packages, tests, and release gates needed to address those issues.

---

## 2. Product positioning

Until the complete production stack exists, describe OAC as:

> A defensive Windows anti-cheat and endpoint-integrity research foundation.

Do not describe it as a complete commercial anti-cheat merely because it has a kernel driver.

A production anti-cheat is a system containing:

1. Endpoint prevention and evidence collection.
2. Authenticated launch and component identity.
3. Signed policy and secure update/revocation.
4. Server-authoritative game validation.
5. Behavioral and replay analysis.
6. Evidence ingestion, risk scoring, and adjudication.
7. Compatibility testing, privacy controls, operations, appeals, and incident response.

OAC currently implements substantial parts of item 1 and an early launcher flow. This specification adds the foundation for items 2 and 3 and the interface for later items.

---

## 3. Goals

### 3.1 Security goals

- Only the dedicated OAC service can control the driver in production mode.
- Session authority is tied to an exact driver file object and service process object.
- A target process is bound during creation, not by trusting a later PID.
- A stale PID or restarted launcher cannot inherit a previous session.
- Service/session/backend lease loss causes deterministic target revocation.
- Critical evidence is retained until acknowledged or a persistent evidence-loss failure is recorded.
- Policy cannot be changed through display text.
- Every enforcement decision is attributable to typed observations and a signed policy.
- The game executable and approved modules are authenticated against a signed manifest.
- Local reports are suitable for authenticated upload and replay rejection.
- The kernel driver remains supportable and does not behave like a rootkit.

### 3.2 Engineering goals

- Small, testable components.
- Explicit state machines.
- Versioned protocols.
- Bounded memory and execution time.
- Clear failure modes.
- Deterministic cleanup.
- Automated hostile-input, race, VM, and verifier testing.
- Compatibility and performance budgets.
- Documentation that distinguishes capability, limitation, and assumption.

### 3.3 Privacy goals

- Collect only evidence needed by policy.
- Separate stable core identity from peripherals.
- Do not upload raw hardware identifiers by default.
- Use server-keyed or session-scoped tokens when recurring-device correlation is required.
- Define retention, access, deletion, and appeal behavior before production deployment.

---

## 4. Non-goals

OAC will not:

- Defeat a hostile hypervisor that can forge every guest observation.
- Guarantee integrity after arbitrary kernel compromise.
- Replace Windows Code Integrity through undocumented kernel patching.
- Prevent DMA without platform/IOMMU support.
- Treat every anomaly as cheating.
- Ban from a single weak heuristic.
- Hide itself from the operating system or security tools.
- Load through vulnerable-driver mappers.
- Disable Secure Boot, HVCI, PatchGuard, or the vulnerable-driver blocklist.
- Use boot-start solely to gain earlier visibility.
- Depend on undocumented private offsets for core operation.
- Promise support for x86, ARM64, or historical Windows releases from the x64 implementation.

---

## 5. Threat model

### 5.1 In-scope adversaries

- Unprivileged local processes attempting to inspect, modify, suspend, inject into, terminate, or duplicate handles to the game.
- Elevated user-mode tools.
- User-mode DLL injection and manual mapping.
- Suspicious overlays and input tooling.
- Debuggers and instrumentation callbacks.
- Known vulnerable or denied drivers.
- Normal driver loads after the protected boundary.
- Some manually mapped kernel code observable through execution/control-flow artifacts.
- Tampering with the launcher or compatibility client.
- Replay or fabrication of unauthenticated local reports.
- Session takeover through PID reuse, handle reopening, or client death.
- Races around target creation and protection.
- Evidence flooding and telemetry loss.

### 5.2 Partially observable adversaries

- Signed kernel drivers that alter observations.
- Rootkits that hide from multiple but related enumeration paths.
- Hypervisors that incompletely virtualize state.
- DMA devices.
- Firmware manipulation.
- Kernel code that avoids the limited execution surfaces inspected.
- Short-lived user-mode mappings or threads between scans.

These require corroboration, platform attestation, server behavior, or external telemetry.

### 5.3 Out-of-scope guarantees

No local anti-cheat can truthfully guarantee detection when the adversary fully controls the kernel or hypervisor. Production policy must therefore combine local evidence with server-authoritative game logic and account/session risk.

---

## 6. Trust boundaries

### 6.1 Components

| Component | Privilege | Trust | Responsibilities |
|---|---:|---|---|
| OAC Driver | Kernel | High but observable/attackable | Session ownership, early target binding, handle filtering, minimal kernel events, bounded snapshots |
| OAC Service | Restricted service account or LocalSystem with service SID | Primary local authority | Driver session, manifest/policy verification, target launch, job ownership, collectors, backend lease, evidence upload |
| OAC Launcher | Standard user | Low | UI, login flow, request service launch, display status |
| Game Process | Standard game token where possible | Protected target, not controller | Game execution and optional internal integrity interface |
| Policy/Manifest Signer | Offline/controlled signing identity | High | Signs approved game builds and policy |
| Backend | Remote trusted service | High | Issues nonce/session, policy, lease, receives evidence, scores risk, revokes |
| Compatibility CLI | Administrator, test only | Lab trust | Diagnostics and migration testing; not production controller |

### 6.2 Core rule

The production launcher is never the direct kernel trust root.

The service is the sole production controller, and its authority is constrained by:

- Device ACL.
- Service identity.
- Exact file-object session.
- Process-object identity.
- Signed policy.
- Signed game manifest.
- Backend session/lease.
- One-time launch ticket.
- Job ownership.

---

## 7. Target architecture

```text
┌───────────────────────────────┐
│ OAC Launcher                  │
│ Standard user                 │
│ UI/login/status               │
└───────────────┬───────────────┘
                │ authenticated named pipe / ALPC-like documented IPC
                ▼
┌─────────────────────────────────────────────────────────┐
│ OAC Service                                             │
│ Restricted Windows service                             │
│                                                         │
│ Session Manager                                         │
│ Policy + Manifest Verifier                              │
│ Launch Manager + Job Object                             │
│ Driver Transport                                        │
│ Health/Event Loop                                       │
│ Kernel Scan Worker                                      │
│ Target Scan Worker                                      │
│ System/HWID Worker                                      │
│ Evidence Store + Backend Client                         │
└───────────────┬───────────────────────────────┬─────────┘
                │ typed IOCTL protocol v5       │ authenticated transport
                ▼                               ▼
┌────────────────────────────────┐       ┌────────────────────────────┐
│ OAC Driver                     │       │ Anti-cheat Backend         │
│                                │       │                            │
│ Per-file Session               │       │ Nonce/session/lease        │
│ Launch Ticket Table            │       │ Signed policy distribution │
│ Process Creation Binding       │       │ Evidence ingestion         │
│ Handle Callbacks               │       │ Risk and revocation        │
│ Critical Alert Channel         │       │ Audit/adjudication         │
│ Event Channel                  │       └────────────────────────────┘
│ Snapshot Manager               │
└────────────────────────────────┘
```

---

## 8. Driver session architecture

### 8.1 Session object

Introduce an internal driver session structure conceptually containing:

```c
typedef struct OAC_SESSION {
    EX_RUNDOWN_REF Rundown;
    EX_PUSH_LOCK Lock;

    OAC_SESSION_STATE State;
    OAC_SESSION_ID SessionId;
    ULONGLONG Generation;

    PFILE_OBJECT ControlFileObject;   // referenced
    PEPROCESS ServiceProcess;         // referenced
    HANDLE ServicePid;                // diagnostics only

    PEPROCESS TargetProcess;          // referenced when bound
    HANDLE TargetPid;                 // diagnostics only

    OAC_LAUNCH_TICKET* PendingTicket;
    volatile LONG64 SessionLost;
    volatile LONG64 Revoked;
    volatile LONG64 EvidenceLoss;

    OAC_ALERT_CHANNEL Alerts;
    OAC_EVENT_CHANNEL Events;
    OAC_SNAPSHOT_TABLE Snapshots;
} OAC_SESSION;
```

This is conceptual, not a required exact layout.

### 8.2 State machine

```text
Unclaimed
   │ CLAIM_SESSION
   ▼
Claimed
   │ CREATE_LAUNCH_TICKET
   ▼
LaunchPending
   │ matching process creation
   ▼
TargetBound
   │ target gate passed / START_MONITORING
   ▼
Monitoring
   │ policy failure, service loss, evidence loss, lease loss
   ▼
Revoked
   │ cleanup
   ▼
Closing
```

Invalid transitions return an explicit status and typed reason.

### 8.3 Authorization

Every privileged IOCTL must verify:

- Current file object has a valid session context.
- Session context equals the active production session.
- Current process object equals the referenced service process.
- Session state permits the request.
- Session ID/generation in the request matches.
- Request version, size, flags, reserved fields, and payload lengths are valid.
- Rundown protection can be acquired.

The process object protects against PID reuse. The file-object session protects against opening a new handle from another process after ownership was established.

### 8.4 Cleanup semantics

`IRP_MJ_CLEANUP` means the controlling handle is no longer usable and must:

- Atomically mark session lost and revoked.
- Prevent new operations.
- Emit a typed critical alert when possible.
- Clear/cancel launch tickets.
- Signal user-mode waiters where applicable.
- Preserve evidence until final close or safe expiration.
- Release target/service references only after callbacks and readers drain.

`IRP_MJ_CLOSE` releases the file-object context after cleanup and rundown complete.

---

## 9. Device and IPC security

### 9.1 Driver device

Production access should be limited to:

- `SYSTEM`.
- The OAC service SID.

Do not use a generic “administrators full control” descriptor in production.

The installer must:

- Configure the service SID.
- Apply the device security descriptor.
- Verify the resulting ACL.
- Fail closed if the expected identity cannot be established.

### 9.2 Launcher-service IPC

Use a documented Windows IPC mechanism such as a named pipe with a restrictive ACL.

The protocol must authenticate:

- Client user/session.
- Requested game/build.
- Backend login/session token reference.
- Request nonce.
- Message size and version.

The service decides whether the requesting user may start or control the session. The launcher never receives a raw privileged driver handle.

---

## 10. Launch ticket and early binding

### 10.1 Ticket contents

A launch ticket should contain:

```text
TicketId
RandomNonce
SessionId
SessionGeneration
ExpectedCreatorProcessObject
ExpectedCanonicalNtPath
ExpectedGameId
ExpectedBuildId
ExpectedFileIdentity
ExpectedManifestDigest
CreatedTimestamp
ExpiresTimestamp
State: Pending / Consumed / Cancelled / Expired
```

`ExpectedFileIdentity` should evolve toward stable volume/file identity plus cryptographic digest. Path alone is not a sufficient final identity.

### 10.2 Flow

1. Service verifies signed policy.
2. Service verifies signed game manifest.
3. Service opens and authenticates the game executable.
4. Service asks the driver to create a one-use ticket.
5. Service calls `CreateProcessW` suspended.
6. Process-creation callback receives creation information.
7. Driver matches:
   - Active service session.
   - Creator process object.
   - Expected canonical path/file identity.
   - Ticket expiration.
   - Ticket pending state.
8. Driver references and binds the new `EPROCESS`.
9. Ticket becomes consumed before the callback returns.
10. `CreateProcessW` returns to service.
11. Service confirms returned PID/process corresponds to the already-bound target.
12. Service assigns the process to the kill-on-close job.
13. Service performs target gate.
14. Service resumes the initial thread only after a clean decision.

### 10.3 Failure behavior

Any mismatch:

- Does not bind the process.
- Consumes or cancels the ticket according to replay-safe policy.
- Emits a typed event.
- Causes the service to terminate the suspended process it created.
- Releases all references.

---

## 11. Liveness and target ownership

### 11.1 Job object

The service creates a job with:

- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
- Optional process-count, child-process, and UI restrictions based on game compatibility.
- Explicit child-process allow policy.

The job handle remains owned by the service. Service death closes the handle and terminates the job.

### 11.2 Driver session liveness

The driver does not rely on periodic PID checks as the primary authority. Authority is the referenced service process plus controlling file object.

On service process exit or file cleanup:

- Mark session revoked.
- Stop accepting privileged IOCTLs.
- Retain evidence and state for bounded postmortem retrieval only if a trusted recovery path exists.
- Do not let a new arbitrary process claim the live target.

### 11.3 Backend lease

Production policy includes a short lease renewed by authenticated backend communication.

Lease states:

```text
Healthy
Degraded
Expired
Revoked
```

Network interruption policy is game-specific, but it must be explicit. The service must not silently continue forever with an expired production lease.

---

## 12. Protocol v5

### 12.1 Header

Use a common C-compatible header conceptually similar to:

```c
typedef struct OAC_MESSAGE_HEADER {
    ULONG Version;
    ULONG HeaderSize;
    ULONG MessageType;
    ULONG Flags;
    ULONGLONG TotalSize;

    OAC_SESSION_ID SessionId;
    ULONGLONG SessionGeneration;
    ULONGLONG RequestId;
} OAC_MESSAGE_HEADER;
```

All variable-length messages must validate:

- `HeaderSize`.
- `TotalSize`.
- Integer additions/multiplications.
- Offset/length ranges.
- Alignment.
- Item counts.
- Required and optional flags.
- Maximum sizes.

### 12.2 Typed observation record

```c
typedef struct OAC_OBSERVATION_RECORD {
    ULONG Version;
    ULONG Size;

    ULONGLONG Sequence;
    ULONGLONG Timestamp100ns;
    ULONGLONG ScanId;

    ULONG RuleId;
    ULONG EventType;
    ULONG ObservationSeverity;
    ULONG Confidence;

    ULONG ProcessId;
    ULONG ThreadId;
    ULONGLONG Address;
    ULONGLONG Auxiliary;

    ULONGLONG EvidenceFlags;
    ULONG PayloadType;
    ULONG PayloadLength;
} OAC_OBSERVATION_RECORD;
```

The exact layout may differ, but the concepts are mandatory.

### 12.3 Stable IDs

Define namespaces:

```text
Rule IDs:
  0x0001xxxx kernel session/liveness
  0x0002xxxx process/handle
  0x0003xxxx kernel module/driver
  0x0004xxxx kernel integrity
  0x0005xxxx target module/memory
  0x0006xxxx debugger/instrumentation
  0x0007xxxx overlay/input
  0x0008xxxx platform/virtualization
  0x0009xxxx HWID/privacy
  0x000Axxxx manifest/policy/backend

Event types:
  Observation
  PolicyViolation
  CapabilityChange
  ScanStarted
  ScanCompleted
  ScanIncomplete
  SessionStateChanged
  EvidenceLoss
  Revocation
```

### 12.4 Provenance

Preserve:

- Kernel sequence.
- Kernel timestamp.
- Ingestion timestamp.
- Service sequence.
- Scan ID.
- Session ID/generation.
- Rule ID.
- Occurrence count.
- First/last occurrence times.

Do not replace source provenance with a new local record that loses origin.

---

## 13. Telemetry architecture

### 13.1 Critical alert channel

Properties:

- Fixed-size typed records.
- Callback-safe.
- High/critical only.
- No severity-blind overwrite.
- Sequence and acknowledgement.
- Persistent overflow/evidence-loss latch.
- First-loss sequence recorded.
- Service can wait/poll efficiently.
- Bounded copy time.

When full:

- Preserve already queued alerts.
- Set evidence-loss.
- Increment lost-by-severity counters.
- Cause production policy to revoke.
- Do not flood text records.

### 13.2 Event channel

For lower-severity operational events:

- Bounded.
- Sequence gaps detectable.
- May drop according to policy, but records exact drop counters.
- Must not block critical alerts.

### 13.3 Snapshot channel

Inventories and full scans use a snapshot object:

```text
SnapshotId
SnapshotType
ScanId
CreatedTimestamp
State
TotalItems
AvailableItems
Truncated
FailureStatus
CursorGeneration
Expiration
```

Examples:

- Loaded modules.
- System handles.
- Processes and threads.
- Private trace entries.
- CPU records.
- Target memory regions.
- Services/devices in user mode.

Snapshots are paged and read by cursor. Human-readable reports are generated after typed records reach user mode.

---

## 14. Scan scheduling and performance

### 14.1 Health/event loop

Responsibilities only:

- Check target/job state.
- Read/acknowledge alerts.
- Check session status.
- Renew/check backend lease.
- Process policy revocation.
- Queue bounded work.
- Trigger immediate target revocation.

It must not:

- Hash files.
- Validate catalogs.
- Walk stacks.
- Enumerate all handles.
- Scan hundreds of megabytes.
- Serialize full reports.
- Perform blocking uploads.

### 14.2 Workers

Each worker reports:

```text
Start time
End time
CPU time
Bytes read
Items inspected
Items skipped
Timeout/cancel state
Partial result
Peak allocation
```

### 14.3 Target threads

Replace full periodic all-thread suspension with:

- Event-driven selection.
- Round-robin bounded sampling.
- Priority for new threads, unbacked start addresses, suspicious modules, or anomalous regions.
- Very short suspension budgets.
- Guaranteed resume through RAII/finally paths.
- Exclusion/coordination for known critical game threads when supported.
- Measured maximum suspension time.

### 14.4 Memory scanning

Use:

- Region metadata first.
- Incremental hash/content sampling.
- Per-cycle byte budget.
- Priority queue based on executable/private/writable/start-address correlation.
- Scan continuation state.
- Explicit coverage reporting.

---

## 15. Policy architecture

### 15.1 Separation

Collection code emits observations. It does not decide bans.

Policy engine maps observations to:

```text
NoAction
Record
Corroborate
Warn
DenyLaunch
RevokeSession
RequestServerReview
```

### 15.2 Confidence

Suggested model:

```text
Informational
Weak
Moderate
Strong
ConclusiveForLocalPolicy
```

“Conclusive” means conclusive for a defined local policy, not proof of cheating in every context.

### 15.3 Examples

| Observation | Default interpretation |
|---|---|
| Any post-start driver load | Strong violation only in strict/tournament mode; otherwise signer/build policy evaluation |
| Exact denied driver hash | Strong or critical |
| Unknown unsigned loaded driver | Strong |
| Overlay style overlap | Weak until signer/process/title/window behavior corroboration |
| Global CPU DR7 set | Weak/moderate diagnostic unless target thread or debugger evidence corroborates |
| Target thread DR7 set | Stronger target-specific evidence |
| Executable `MEM_PRIVATE` | Weak alone; stronger with PE, thread, stack, or syscall correlation |
| PE in executable unbacked memory | Strong |
| Critical evidence loss | Local production revocation |
| Service/session loss | Local production revocation |
| Missing/expired signed policy | Deny launch or revoke |
| Manifest mismatch | Deny launch |

### 15.4 Signer classification

Do not collapse all trusted signatures into a boolean.

Store:

```text
Signature present
Chain locally valid
Catalog or embedded
Signer subject/thumbprint
Microsoft signer
Approved publisher
Approved exact file
Revocation checked / not checked / unavailable
Timestamp state
Policy match
```

---

## 16. Signed game manifest

### 16.1 Manifest fields

```text
SchemaVersion
GameId
BuildId
IssuedAt
ExpiresAt
MinimumDriverVersion
MinimumServiceVersion
MinimumLauncherVersion
PolicyId
MainExecutable:
  canonical identity
  SHA-256
  approved signer constraints
Modules:
  path/name
  SHA-256 or signer/build constraints
Approved middleware
Approved overlays
Allowed child processes
Allowed JIT/runtime classes
Section-integrity rules
Backend environment
SigningKeyId
Signature
```

### 16.2 Verification

- Canonical serialization.
- Strong signature algorithm selected by project policy.
- Offline root/public key pinned in the service or Windows trust mechanism.
- Key rotation through signed key metadata.
- Expiration and rollback prevention.
- Manifest digest included in session and evidence.

---

## 17. Signed policy

### 17.1 Policy fields

```text
SchemaVersion
PolicyId
Version
GameId
BuildScope
IssuedAt
ExpiresAt
Minimum component versions
Rule catalog version
Rule actions/thresholds
Strict driver-load mode
Overlay policy
Approved signers/files
Driver deny/review policy version
Backend lease parameters
Emergency component revocations
SigningKeyId
Signature
```

### 17.2 Rollback protection

The service records the highest accepted policy version per game/channel. Lower versions require an explicitly signed rollback authorization.

---

## 18. Backend evidence model

### 18.1 Session bootstrap

1. Launcher authenticates user.
2. Service obtains or receives a backend session reference through protected IPC.
3. Backend issues:
   - Session ID.
   - Nonce.
   - Policy.
   - Lease.
4. Service verifies policy and manifest.
5. Session ID/nonce digest is bound into driver session metadata and evidence.
6. Service uploads typed events promptly.
7. Backend acknowledges highest sequence.
8. Reused/expired nonce is rejected.

### 18.2 Local evidence chain

A local SHA-256 chain remains useful for accidental corruption detection, but production authenticity requires authenticated transport and server acknowledgement.

Prefer canonical binary records over free-form report text. Text reports remain an operator view generated from typed records.

### 18.3 No embedded reusable secret

Do not place a long-lived HMAC key in the launcher/service and treat it as unextractable. Use asymmetric verification for policy/manifest and authenticated server transport/session credentials for upload.

---

## 19. Game-specific anti-cheat layer

Endpoint integrity is necessary but insufficient.

Add interfaces for the game/server to provide:

- Expected build/session ID.
- Match ID.
- Player/account ID pseudonym.
- Server tick/time.
- Movement and action invariants.
- Fire-rate/ammo/economy validation.
- Input timing summaries.
- Replay/event stream references.
- Internal integrity checkpoints.
- Protected process-tree expectations.

Server-side systems should detect:

- Impossible state transitions.
- Speed/position/teleport anomalies.
- Invalid combat timing.
- Inventory/economy manipulation.
- Aim/input statistical anomalies.
- Network protocol abuse.
- Coordinated account/device risk.

A local endpoint anomaly contributes to risk; it should not be the sole architecture.

---

## 20. Current detection subsystem disposition

| Existing subsystem | Disposition |
|---|---|
| Ob callbacks | Keep; move ownership to service session |
| Process-object identities | Keep and extend |
| Driver-load monotonic latch | Keep as observation; make strictness policy-driven |
| AuxKlib/system module cross-view | Keep as heuristic |
| System thread outside modules | Keep; typed rule and corroboration |
| CPU/IDT/MSR checks | Keep; centralize policy and fix fallback |
| Selected export baseline | Keep as heuristic; add trusted-image comparison later |
| Kernel IAT ownership | Keep; improve expected-export resolution |
| Private PiDDB/unloaded profile | Lab-only exact-build capability |
| User module cross-view | Keep |
| Executable private/mapped memory | Keep with incremental budget |
| PE/syscall/string scans | Keep with confidence distinctions |
| Target thread/stack checks | Keep, but incremental/evidence-driven |
| Overlay windows | Keep as weak policy input |
| `DbgUiRemoteBreakin` patch | Lab-only |
| `ThreadHideFromDebugger` | Lab-only |
| Loaded-driver hash policy | Keep; sign/version/update remotely |
| HWID collector | Keep separated from core enforcement; privacy policy required |
| Text report chain | Keep as operator view; typed authenticated evidence becomes primary |

---

## 21. Known defects to fix

### 21.1 Trust and lifecycle

- First administrator can claim driver.
- Exclusive device open can deny official client.
- Client exit does not deterministically kill target.
- Session can be reclaimed after client exit while target state exists.
- Target is protected after creation rather than during creation.

### 21.2 Telemetry

- 512 mixed records.
- Severity-blind overwrite.
- Synchronous scan cannot be drained while producing records.
- Verbose handles/private traces can erase evidence.
- Text-heavy records waste kernel ring capacity.

### 21.3 Policy/evidence

- Text prefix changes severity.
- Original kernel sequence/timestamp lost.
- Deduplication can hide frequency.
- CPU interpretation duplicated.
- Global DR7 too strong.
- Signature trust too coarse.
- Overlay policy too broad.

### 21.4 Detection limitations

- IAT checks do not fully verify expected export identity.
- Live export baseline can normalize preexisting compromise.
- Periodic scans miss transient activity.
- Related cross-views can be forged by kernel compromise.
- No authenticated game manifest.
- No server behavior layer.

### 21.5 CPU snapshot allocation behavior

**Status at the reviewed baseline:** The previously proposed direct-call fallback is not present.
`OacCaptureCpuSnapshot` validates output capacity before capture and invokes the callback only
through `KeIpiGenericCall`. Keep this property covered by allocation-failure and undersized-buffer
tests so a direct fallback cannot reintroduce ambiguous callback provenance.

---

## 22. Work packages

## WP-00 — Baseline, documentation, and tests

**Priority:** P0
**Outcome:** Reproducible baseline and implementation map.

Deliverables:

- Baseline build/test report.
- Architecture/security/protocol/test docs.
- Current feature map.
- Threat model.
- `PROGRESS.md`.
- `DECISIONS.md`.
- CI updated to at least run build and user-mode/protocol tests that do not require the driver.

Acceptance:

- Exact commands and outputs recorded.
- No implementation claims without evidence.
- Current tests remain buildable.

---

## WP-01 — Protocol v5 foundations

**Priority:** P0
**Outcome:** Typed, versioned, provenance-preserving protocol.

Deliverables:

- New shared protocol directory/header.
- Rule/event ID definitions.
- Session/request/scan IDs.
- Strict negotiation.
- v4 diagnostic compatibility boundary.
- Hostile-input tests.
- Protocol documentation.

Acceptance:

- No policy string parsing.
- Source timestamps/sequences preserved.
- All structures statically asserted.
- Malformed variable-length data rejected.

---

## WP-02 — Service and device identity

**Priority:** P0
**Outcome:** Dedicated production controller.

Deliverables:

- `OAC-Service`.
- Service installer.
- Restricted device ACL.
- Restricted local IPC.
- Persistent driver handle.
- Service lifecycle tests.

Acceptance:

- Unrelated admin process cannot claim driver.
- Launcher cannot directly issue privileged production IOCTLs.
- Service owns session.

---

## WP-03 — Per-file session state

**Priority:** P0
**Outcome:** Correct authority and lifecycle.

Deliverables:

- File-object context.
- Session state machine.
- Rundown/lifetime handling.
- Cleanup/close revocation.
- Session stress tests.

Acceptance:

- PID reuse safe.
- Cleanup races safe.
- No session reclamation while stale target alive.

---

## WP-04 — Launch ticket and early target binding

**Priority:** P0
**Outcome:** No post-creation protection gap.

Deliverables:

- Ticket IOCTLs.
- Creation callback matching.
- Ticket expiry/replay/cancel.
- Suspended launch confirmation.
- Race tests.

Acceptance:

- Target bound in creation callback.
- Wrong/replayed/expired ticket rejected.

---

## WP-05 — Job and liveness

**Priority:** P0
**Outcome:** Service/session loss terminates protected play.

Deliverables:

- Kill-on-close job.
- Target/child process assignment.
- Driver session-lost alert.
- Backend lease mock.
- Crash/stop tests.

Acceptance:

- Service death revokes and terminates.
- Revocation idempotent.

---

## WP-06 — Alert/event/snapshot transport

**Priority:** P0
**Outcome:** Evidence cannot be silently destroyed by inventory.

Deliverables:

- Critical alert channel.
- Lower-priority event channel.
- Snapshot manager and paging.
- Ack/cursor protocol.
- Overflow/evidence-loss tests.

Acceptance:

- Critical alert survives maximum inventory.
- Sequence gaps explicit.
- No callback blocking.

---

## WP-07 — Service scheduler and bounded scanners

**Priority:** P0
**Outcome:** Health loop remains responsive.

Deliverables:

- Independent health loop.
- Worker queues and cancellation.
- Scan budgets.
- Incremental thread/memory scanning.
- Performance metrics.

Acceptance:

- Slow scan does not delay health loop beyond budget.
- All suspended threads always resumed.

---

## WP-08 — Rule catalog and policy engine

**Priority:** P0
**Outcome:** Centralized, testable enforcement logic.

Deliverables:

- Stable rule catalog.
- Confidence and action model.
- Deployment modes.
- Signer classification.
- Regression tests.
- Removal of text-driven severity.

Acceptance:

- Same typed observation produces deterministic policy result.
- Display text changes do not affect result.

---

## WP-09 — Signed game manifest

**Priority:** P1
**Outcome:** Only approved builds launch.

Deliverables:

- Manifest schema.
- Signature verifier.
- Build/file identity checks.
- Launch integration.
- Negative tests.

Acceptance:

- Modified/wrong/expired manifest denies launch.

---

## WP-10 — Signed policy and update model

**Priority:** P1
**Outcome:** Rules are authenticated, scoped, expiring, and revocable.

Deliverables:

- Policy envelope.
- Signature and rollback protection.
- Policy cache.
- Emergency revoke.
- Tests.

Acceptance:

- Wrong signature, scope, expiry, or rollback rejected.

---

## WP-11 — Backend session abstraction

**Priority:** P1
**Outcome:** Nonce, lease, upload, and replay model.

Deliverables:

- Mock backend.
- Production transport interface.
- Evidence ack.
- Lease expiry.
- Replay tests.

Acceptance:

- Reused nonce rejected.
- Unacknowledged evidence and lease loss have explicit policy outcomes.

---

## WP-12 — Scanner modularization

**Priority:** P1
**Outcome:** Maintainable components.

Deliverables:

- Split kernel scanner.
- Shared user-mode libraries.
- Remove duplicate wrappers/policy.
- Unit tests around parsers and helpers.

Acceptance:

- No functional regression.
- Source files have coherent responsibilities.

---

## WP-13 — Game/server integration

**Priority:** P2
**Outcome:** Anti-cheat covers behavior, not only endpoint state.

Deliverables:

- Game integration SDK/interface.
- Backend event schema.
- Server-authoritative validation plan.
- Replay/risk integration.

Acceptance:

- At least one game-specific invariant and one server-side detector demonstrated in test environment.

---

## WP-14 — Production release engineering

**Priority:** P2
**Outcome:** Controlled, supportable release process.

Deliverables:

- Signing/HLK plan.
- Reproducible build metadata.
- SBOM.
- Symbol separation.
- Key rotation.
- Update/rollback.
- Support matrix.
- Privacy/retention policy.
- Operational runbooks.

---

## WP-15 — Production endpoint trust gate

**Priority:** P0
**Outcome:** Launch authorization depends on a complete, correlated endpoint scan and explicit
runtime integrity policy rather than on service identity alone.

Deliverables:

- One-use production scan configuration with explicit completeness and correlation.
- Frozen loaded-driver inventory evaluated by signature, hash, and denied family.
- Driver-load gate armed before admission completes.
- Signed-manifest runtime-module authorization.
- Typed, bounded target memory, thread, instrumentation, handle, and lifecycle observations.
- Explicit skipped, degraded, overflow, and backend-acknowledgement failure states.

Acceptance:

- Incomplete or uncorrelated scans deny admission.
- Denied or untrusted loaded drivers deny admission.
- Runtime images outside the signed policy produce typed evidence and the configured policy action.
- Target observations retain provenance, remain bounded, and cannot silently overflow.
- The exact signed package passes the full production path and standard Driver Verifier in one
  contained disposable-VM campaign.

---

## WP-16 — Production backend admission

**Priority:** P0
**Outcome:** The existing transport contract is backed by authenticated remote admission and
durable replay/evidence state.

Deliverables:

- Mutually authenticated production transport and credential lifecycle.
- Durable lease, replay, evidence, and acknowledgement storage.
- Remote policy delivery with bounded offline behavior.
- Real game/server adapter using the existing canonical event contract.

Acceptance:

- Replayed, expired, revoked, or unacknowledged sessions fail according to signed policy across
  service and backend restarts.

---

## WP-17 — Atomic launch and durable local recovery

**Priority:** P1
**Outcome:** The launch boundary closes remaining file-identity, process-job, and local evidence
durability gaps.

Deliverables:

- Assign the target job at process creation rather than after confirmation.
- Bind authorization and runtime-module decisions to stable file identity, not only a reopened path.
- Durable local evidence journal with bounded recovery and acknowledgement.
- Manifest signer rotation and revocation metadata.

Acceptance:

- No target thread can run outside the owned job, path replacement cannot change the authorized
  image, and service/backend interruption cannot silently discard accepted evidence.

---

## WP-18 — Production/diagnostic driver separation

**Priority:** P1
**Outcome:** Broad laboratory scanning is isolated from the minimal production control surface when
deployment evidence justifies the additional maintenance boundary.

Deliverables:

- Separate signed production and diagnostic packages.
- Minimal production IOCTL and callback surface.
- Independent installation, update, rollback, and compatibility tests.

Acceptance:

- Production contains no lab-only dispatch or configuration path, and both packages pass their
  independent lifecycle and Driver Verifier campaigns.

---

## 23. Test matrix

### 23.1 Authorization

| Test | Expected |
|---|---|
| Standard user opens device | Denied |
| Unrelated elevated admin opens privileged session | Denied |
| Service opens device | Success |
| Second service handle claims session | Denied or read-only diagnostic by design |
| Launcher requests valid start through IPC | Service-authorized |
| Other user/session requests control | Policy/ACL denial |

### 23.2 Lifecycle

| Test | Expected |
|---|---|
| Launcher exits | Protection continues |
| Service exits | Job terminated, driver session revoked |
| Driver handle closed | Session revoked |
| Target exits | Target reference cleared safely |
| PID reused | New process not trusted |
| Service restarts while old target alive | Cannot reclaim old live session |
| Suspend/resume | Lease and session revalidated |

### 23.3 Launch ticket

| Test | Expected |
|---|---|
| Valid ticket + expected image | Bind |
| Wrong image | Reject |
| Wrong creator | Reject |
| Expired ticket | Reject |
| Replay | Reject |
| Two simultaneous candidates | Exactly one or none; never wrong bind |
| CreateProcess fails | Ticket cancelled/expired safely |

### 23.4 Telemetry

| Test | Expected |
|---|---|
| Critical then 10,000 info items | Critical retained |
| Critical channel full | Existing alerts retained; evidence-loss latch |
| Snapshot pages | Stable cursor and counts |
| Reader disconnect | State preserved according to policy |
| Concurrent callbacks | No corruption |
| Sequence ack | Monotonic and replay-safe |

### 23.5 Performance

Measure:

- Health-loop latency.
- Alert-to-service latency.
- Revocation latency.
- CPU percent.
- Working set.
- Driver nonpaged pool.
- Scan bytes.
- Longest thread suspension.
- Frame-time p50/p95/p99 impact.
- Driver hash/signature scan duration.
- Report/upload duration.

Define budgets per supported game and machine class before production.

### 23.6 Compatibility corpus

Include:

- Discord/Steam/Xbox/NVIDIA/AMD overlays.
- OBS and common capture tools.
- Accessibility software.
- IMEs.
- Endpoint security/EDR.
- Hyper-V/VBS/HVCI.
- VirtualBox/VMware test environments.
- JIT runtimes used by the game.
- Anti-tamper/DRM middleware.
- Game launchers and patchers.
- Common hardware monitoring utilities.

Every compatibility decision is signed policy, not a hidden code exception.

---

## 24. CI and release gates

### Pull request gates

- Release and Debug x64 build.
- Unit tests.
- Protocol tests.
- Static analysis.
- Script lint.
- No new warnings.
- Documentation updated for protocol/security changes.

### Scheduled gates

- Disposable VM smoke.
- Driver Verifier.
- Launch/liveness suite.
- Telemetry stress.
- Windows build matrix.
- Performance regression.
- Clean compatibility corpus.

### Release gates

- Signed policy and manifest.
- Production driver signing path.
- Support matrix.
- Verifier/static analysis clean or documented waiver.
- Privacy and retention approval.
- Rollback package.
- Backend compatibility.
- Emergency revocation capability.
- Internal symbols retained; public package reviewed.
- Version consistency across protocol, driver INF, service, launcher, policy, and report.

---

## 25. Documentation set

Maintain:

```text
README.md
docs/ARCHITECTURE.md
docs/SECURITY_MODEL.md
docs/PROTOCOL.md
docs/RULE_CATALOG.md
docs/POLICY_FORMAT.md
docs/GAME_MANIFEST.md
docs/SERVICE_SECURITY.md
docs/DRIVER_LIFETIME.md
docs/TELEMETRY.md
docs/TEST_MATRIX.md
docs/PERFORMANCE.md
docs/PRIVACY.md
docs/PRODUCTION_SIGNING.md
docs/OPERATIONS.md
docs/INCIDENT_RESPONSE.md
PROGRESS.md
DECISIONS.md
```

Every document must distinguish:

- Implemented.
- Tested.
- Planned.
- Unsupported.
- Lab-only.
- Assumed.

---

## 26. Migration strategy

### Stage 1 — Preserve and surround

- Keep current client as diagnostic tool.
- Add protocol v5 and service.
- Move production control path to service.
- Do not rewrite every detector immediately.

### Stage 2 — Correct lifecycle and transport

- Per-file session.
- Launch ticket.
- Job liveness.
- Alert/snapshot split.
- Independent health loop.

### Stage 3 — Centralize policy

- Rule catalog.
- Typed evidence.
- Signed manifest/policy.
- Remove string-driven decisions and duplicated severity logic.

### Stage 4 — Improve detections

Only after lifecycle correctness:

- Production endpoint admission and explicit scan completeness.
- Loaded-driver trust, hash, and family policy.
- Signed runtime-module scope and event-driven target observations.
- Expected-export IAT validation and trusted-image section comparison where they add independent
  evidence.
- Game-specific integrity.

### Stage 5 — Backend and production operations

- Authenticated evidence.
- Lease/replay.
- Behavior analytics.
- Signing, support matrix, privacy, operations.

### Stage 6 — Close deployment boundaries

- Create-time job assignment and stable file identity.
- Durable local evidence recovery and key rotation.
- Production/diagnostic driver separation if the operational cost is justified.

---

## 27. Definition of a hardened foundation

OAC reaches the **hardened foundation** milestone when:

- Production driver access is service-restricted.
- Session is per-file-object and process-object bound.
- Target is bound during creation using a one-time ticket.
- Service death closes a kill-on-close job and revokes driver session.
- Critical evidence cannot be overwritten by inventory.
- Health/event loop remains independent from expensive work.
- Protocol uses typed rule/event IDs and preserves provenance.
- Policy is centralized and display strings have no security meaning.
- Current detections are categorized by confidence and mode.
- All P0 tests pass under Driver Verifier in a disposable VM.
- Documentation and CI reflect actual behavior.

This milestone is not equivalent to complete commercial production readiness.

---

## 28. Definition of production readiness

Production readiness additionally requires:

- Signed game manifests.
- Signed remote policy and rollback protection.
- Authenticated backend session, nonce, lease, evidence acknowledgement, and replay rejection.
- Game/server behavior detections.
- Compatibility and performance validation for supported games and systems.
- Production signing/HLK process.
- Secure updates and emergency revocation.
- Privacy, retention, deletion, access, and appeal procedures.
- Operational monitoring and incident response.
- Staged rollout and rollback.
- Independent security review.

---

## 29. Immediate implementation order

The next implementation sequence is:

1. Close the atomic launch, stable file-identity, evidence-recovery, and key-rotation gaps in
   `WP-17`.
2. Evaluate `WP-18` only after the production surface and deployment model are stable enough to
   justify a second driver package.

Prefer one coherent capability change and one attributable acceptance run. Do not expand the test
harness or add signatures without a concrete security boundary or evidence requirement.
