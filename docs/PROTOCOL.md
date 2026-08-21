# OAC protocol

**Status:** The production-control ABI is separate from the lab-only diagnostic compatibility ABI

**Foundation source:** Integrated after baseline `075ad2109f84cce90727f8ba65f87b807500e6b7`;
the complete runtime suite most recently passed at implementation commit
`974d2c474ff9515c5f11ab313bf644bf7dcbe89a` on Windows 11 build 26100 under standard Driver
Verifier, including endpoint admission, loaded-driver trust, signed-manifest and signed-policy
authorization, backend failure/recovery, job/liveness, typed evidence, bounded service scheduling,
and integrated policy evaluation. The current backend wire additionally carries signed-policy and
canonical game-decision operations for the separate production transport and .NET admission
service.

`shared/protocol/oac_v5.h` and `shared/protocol/oac_validate.h` are the production wire-format and
validation sources of truth. `shared/oac_protocol.h` defines the separate diagnostic compatibility
ABI. All wire headers are C-compatible and have compile-time size and offset assertions.

## Production control protocol

`OAC_PRODUCTION_PROTOCOL_VERSION` is `0x00050007`; the existing `OAC_V5_VERSION` name remains a
compatibility alias. Every request uses `METHOD_BUFFERED` and requires both read and
write access. The request and response headers carry an exact size, nonzero request ID, 128-bit
session ID, generation, flags, and explicit `MessageType`. The message type is tied to the IOCTL
function number and is validated even when every other field is well formed.

The current driver advertises session control, launch-ticket, session-liveness, typed-evidence,
paged-snapshot, kernel-scan, and driver-gate capabilities. Negotiate, claim, endpoint configuration
and scan, status, explicit revoke, launch control, evidence read, and snapshot management are
available:

| Function | IOCTL | Input | Output | Current behavior |
|---:|---|---|---|---|
| `0x810` | `IOCTL_OAC_V5_NEGOTIATE` | 56-byte negotiate request | 88-byte negotiate response | Selects the exact production revision and records negotiation on the file context |
| `0x811` | `IOCTL_OAC_V5_CLAIM_SESSION` | 88-byte claim request | 64-byte claim response | Claims one production or lab diagnostic session; production claim requires a nonzero backend binding digest |
| `0x812` | `IOCTL_OAC_V5_SET_CONFIG` | 56-byte configuration request | 64-byte configuration response | Arms the exact production image-log and driver-gate configuration once, before preflight |
| `0x813` | `IOCTL_OAC_V5_RUN_SCAN` | 56-byte scan request | 104-byte scan response | Runs the exact current-state endpoint checks once and returns explicit completion, failure, timing, evidence count, and scan identity |
| `0x814` | `IOCTL_OAC_READ_EVIDENCE` | 80-byte evidence request | 136-byte prefix plus up to 16 fixed records | Reads the retained alert or overwrite-event channel; alert reads acknowledge only previously delivered records |
| `0x815` | `IOCTL_OAC_MANAGE_SNAPSHOT` | 96-byte snapshot request | 152-byte prefix plus up to 16 fixed records | Opens, reads, or closes one frozen, expiring kernel-module snapshot |
| `0x816` | `IOCTL_OAC_V5_GET_STATUS` | 48-byte status request | 208-byte status response | Returns correlated session state, mode, capabilities, endpoint configuration and scan identity, counters, manifest and backend digests, and monotonic session-loss latch |
| `0x817` | `IOCTL_OAC_V5_REVOKE_SESSION` | 56-byte revoke request | 80-byte revoke response | Idempotently revokes the caller's exact session and records requested-shutdown provenance |
| `0x818` | `IOCTL_OAC_ARM_LAUNCH` | 2144-byte arm request | 88-byte arm response | Arms one bounded canonical-path ticket bound to a nonzero verified-manifest digest |
| `0x819` | `IOCTL_OAC_CANCEL_LAUNCH` | 64-byte cancel request | 64-byte cancel response | Terminally cancels the exact pending ticket |
| `0x81A` | `IOCTL_OAC_CONFIRM_TARGET` | 72-byte confirmation request | 72-byte confirmation response | Confirms the exact bound process handle and enters monitoring |

The separate diagnostic compatibility ABI retains its broader scan, optional private-profile, and
CPU-snapshot paths; it is not a fallback production authority.

### Endpoint admission

After claiming a production session, the service configures the exact image-log and driver-gate
flags before requesting the scan. Configuration and scanning are one-use operations in the
`CLAIMED` state: a scan cannot begin without the exact configuration, launch cannot arm while a scan
is active, and a failed or incomplete scan clears the production configuration. A successful scan
records one nonzero scan identity in session status and leaves the gate armed for the remainder of
the session.

The request names the complete required set: kernel-module cross-views, process and system-thread
state, dangerous handles, bounded kernel-integrity checks, and platform state. The response carries
the requested and completed masks, start and completion times, evidence count, state, and native
failure status. Allocation failure, malformed system information, evidence loss, missing scan
provenance, or any incomplete required check produces `INCOMPLETE`; it never becomes a clean scan.

The service then reads a frozen kernel-module snapshot. It resolves every reported path and requires
valid embedded or catalog trust plus a nonempty Authenticode SHA-256, rejects the generated exact
vulnerable-driver hashes and conservative family policy, evaluates all typed observations through
the signed rule set, uploads them through the backend interface, and waits for acknowledgement.
Launcher IPC is created only after this boundary succeeds. A post-start driver-gate trip remains a
terminal policy condition.

### Launch transaction

One production session may arm one ticket with a 100 ms to 10 second lifetime, one nonzero verified
manifest SHA-256, and two exact Windows
namespace spellings resolved from the same locked executable handle: the volume-device
`\Device\...` path and its DOS-device `\??\C:\...` path. The driver generates a nonzero 128-bit
launch ID and a boot-relative
`KeQueryInterruptTime` expiration value. The process-creation callback ignores unrelated creators;
for the exact referenced service process and creating-process ID it requires an available,
case-insensitively equal resolved image path before atomically consuming the ticket, referencing
the new process object, and entering
`LAUNCH_PENDING -> TARGET_BOUND`. The service must then present a real user-mode process handle with
the same launch ID. The driver resolves that handle to an exact process object before entering
`MONITORING`.

Handle filtering starts at creation-time binding. While the target is still suspended in
`TARGET_BOUND`, protected Windows bootstrap processes may retain the handles required to finish
process creation; ordinary callers remain filtered. Exact-handle confirmation enters `MONITORING`
before the service resumes the initial thread, at which point the bootstrap exception is closed.

The controller is permitted to create exactly one child process per production session. After a
target is bound, any additional process creation by that exact service process is denied for the
remaining target lifetime; helpers must run in a separate service that holds no production authority.

Cancellation, expiry, a trusted-creator path mismatch, and failed process-handle confirmation are
terminal revocations. Pending path data is cleared on consumption; the retained launch ID is cleared
on confirmation; path and launch-ID data is cleared on cancellation, revocation, cleanup, service
exit, and driver shutdown. The manifest digest remains available in correlated status through the
terminal session state. A live session-owned target remains protected after controller cleanup until its
process-exit notification retires the tombstone.

The service performs one serialized transaction: it authenticates the local launcher, resolves and
keeps one executable open under that caller identity, verifies its signed game manifest and
rollback state, arms the ticket with the verified manifest digest, creates the process suspended
with the caller's primary token, confirms the exact process handle, validates the monitoring state,
assigns the process to its kill-on-close job, and resumes the initial thread. Cancellation is issued
only after a failed synchronous create or a pre-create stop decision; later failures terminate the
suspended target and stop the service. The kernel callback deliberately performs no hashing,
signature verification, filesystem I/O, or registry access.

### Signed game-build authorization

`shared/oac_manifest.h` defines a packed 960-byte canonical record. It carries fixed identities,
monotonic per-game sequence, bounded issuance and expiry, minimum driver/service/launcher protocol
revisions, exact executable leaf name, size and SHA-256, signer-certificate SHA-256, up to sixteen
sorted unique approved runtime-module hashes, and an explicit flag for trusted Windows modules.
Unused entries and reserved fields must be zero, and the detached CMS signature is not part of the
canonical bytes.

The service opens both sidecars without following reparse points and accepts exactly one SHA-256/RSA
CMS signer with no countersignature or unsigned attributes. The signer certificate must be the exact
strong-RSA Authenticode signer of the locked and Windows-trusted executable, and its DER SHA-256
must match the signer explicitly provisioned under the protected OAC registry root. Only then does
the service evaluate the canonical record, exact file identity, expiry and component compatibility,
followed by the protected per-game high-water record. A lower sequence, or a different
manifest/build at the current sequence, is denied. A new high-water record is flushed and read back
before the driver ticket is armed.

Target image-load records are evaluated in the service against this manifest. The exact main image,
an explicit module digest, or—when the manifest enables the class—a Windows-directory file with
valid embedded or catalog trust is admitted. Everything else becomes a typed critical runtime-module
record. The current check binds the observed path, current file content, and trust result; complete
mapped-file identity, approved JIT regions, middleware classification, child-process policy,
and manifest-key rotation remain separate work.

### Signed policy record

`shared/oac_signed_policy.*` defines a fixed 2480-byte schema-3 canonical policy record and a fixed 160-byte
persistent cache record. The policy carries game, build, and channel scope; deployment mode;
component compatibility; a bounded validity interval; a complete typed rule set; a signer identity;
and explicit emergency-revocation or rollback-authorization fields. Its detached CMS signature is
verified by the service through the same non-reparse, exact-signer path used for manifests, with an
independent protected signer pin.

The policy also carries bounded backend lease, grace, renewal, and evidence-acknowledgement
intervals. The service records the current policy digest, update sequence, current version, and
historic high-water version per game and channel. A lower sequence is replay, conflicting content at the
current sequence is equivocation, and an ordinary version must advance beyond the historic
high-water mark. A rollback is accepted only when the new signed record names the exact current
version and digest; the historic high-water mark is preserved. An accepted emergency record is
committed and then prevents service startup, so replacing it with an older record cannot clear the
revocation. These records are local service authorization inputs, not production driver messages,
so they do not by themselves change the driver wire revision.

### Backend session contract

`shared/oac_backend.*` defines backend wire revision `0x00010002` with packed,
transport-independent records for signed-policy fetch, session open, lease renewal, evidence
submission, acknowledgement, and canonical game-event decisions. Every request carries an exact message type,
strict size, monotonic request sequence, fresh 256-bit nonce, bounded wall-clock validity, and—after
open—the exact 128-bit backend session identity. Responses correlate the request sequence, session,
message type, and SHA-256 of the request nonce. The replay window is bounded and rejects a nonce
digest already accepted in that backend session. Policy fetch is pre-session and binds the exact
game, build, channel, current policy version, and current digest. Game submission binds the
authoritative event's backend session and sequence to the outer request and returns the durable
backend sequence with the typed detector result.

Open returns a server nonce and bounded lease terms. The service hashes the backend session ID,
request-nonce digest, and server nonce into one nonzero binding digest, carries that digest in the
production driver claim, and requires it in every later driver status response. Diagnostic claims
must keep the field zero. This correlation does not make the kernel a network client: all transport,
authentication, policy evaluation, queuing, and time-based decisions remain in user mode.

Evaluated evidence uses a monotonic service sequence and a fixed 64-record service queue. Upload
responses may acknowledge only a sequence actually submitted and may never move backwards. The
service advances the retained-alert acknowledgement sent to the driver only after the backend has
acknowledged the corresponding record. Nonce replay, malformed correlation, lease expiry or
revocation, queue exhaustion, and acknowledgement timeout are terminal service errors; closing the
service-owned job then contains the target tree.

`BackendTransport` is the service integration seam. Disposable-VM tests keep the protected,
in-process deterministic transport for reproducible replay, withheld-acknowledgement, lease-loss,
and revocation cases. Production mode uses `backend_http.*`: an HTTPS-only, no-proxy, no-redirect
WinHTTP client with bounded timeouts, normal TLS validation, an additional exact server pin, and a
current strong client-authentication certificate selected from the protected machine store. The
separate .NET 8 service in `OAC-backend/` authenticates endpoint and game-server roles with disjoint
certificate pins, durably stores session/replay/evidence/game state, and acknowledges only after
flushing the associated record.

Remote policy uses the same detached signed-policy record accepted locally. Delivery over mutual
TLS is necessary but not sufficient: the endpoint revalidates the response correlation, CMS
signature, configured policy signer, scope, component compatibility, expiry, replay, rollback, and
emergency-revocation rules. An accepted update is written to an inactive protected cache slot and
flushed before the high-water record changes. Only connectivity and server-availability failures
may use the previously authenticated cache, and only while that policy remains within its signed
validity period.

### Strict validation and correlation

Shared validators reject:

- truncated, oversized, or falsely stated fixed lengths;
- revisions other than the exact production revision and negotiation ranges that exclude it;
- zero request IDs, unknown flags, nonzero reserved data, and unknown enum values;
- a `MessageType` that does not match the IOCTL;
- a session ID or generation where an open request requires zero, or a session request requires
  nonzero values;
- response/request mismatches in message type, request ID, session ID, or generation;
- overflow, misalignment, out-of-range payloads, hidden bytes after a payload, and malformed UTF-16.

Negotiation returns strict-length and typed-event support, the exact evidence page bound, and the
maximum buffered output size. It reports diagnostic compatibility only when `LabMode=1` was read
at driver start.

Protocol families are mutually exclusive per file. Negotiation is serialized with claim under the
session lock. Once a file negotiates production authority, privileged diagnostic calls cannot create
or use a diagnostic session. Once a file claims the unnegotiated diagnostic path, it cannot later
negotiate production authority. This
prevents a handle from switching authorization semantics after either path has established state.

### Per-file authority and lifetime

`IRP_MJ_CREATE` allocates a file context and references the process that opened that exact file
object. Outside lab mode, create succeeds only for the restricted `OACService` identity. A claim
requires prior production negotiation on the same file. Production claim then requires all of:

- the reviewed service SID present as an enabled token group and restricted SID;
- the current process object to be the CREATE owner and the service process;
- the exact claimed file object;
- the generated nonzero 128-bit session ID and monotonically increasing generation;
- an active, controllable session state.

Only one active session exists per device. Another file may negotiate, but cannot claim while that
session exists and cannot copy its authority. A duplicated handle used from another process is also
rejected. Numeric process IDs in status are diagnostic data, not authority.

Each accepted request acquires session rundown protection. Cleanup is one-shot: it marks the
session closing, records file-cleanup revocation when no earlier reason exists, prevents new
acquisitions, waits for outstanding requests, and then releases the controller file and process
references. Close releases the remaining file-context reference.

The service issues an explicit, correlated revoke before closing a healthy controller handle.
Explicit revoke is idempotent. The driver records the first cleanup or service-exit cause if
explicit revoke did not win the race; driver shutdown also closes the active session before device
teardown. A device-lifetime sequence and last-cause pair are returned by status, so a replacement
restricted service can distinguish a fresh driver lifetime from a prior controller loss. This
latch is independent of the retained production alert channel and remains useful when the
controlling service is no longer available to read that channel.

If cleanup occurs while a referenced target is still live, the cleaned session remains as an
unusable tombstone. It blocks a replacement claim until the target exit callback releases the
target and retires the session. This prevents a new controller from inheriting authority while
stale protection state still exists. The kernel invariant is implemented in source; its target-live
service-transaction path passed the named VM campaign.

### Typed evidence transport

`OAC_V5_EVENT_RECORD` is a defined and strictly validated 560-byte schema. It separates stable rule
and event IDs, observation severity, policy severity, confidence, category, payload type, and
evidence flags. It preserves source provenance through session ID, generation, kernel sequence and
timestamp, scan ID, occurrence count and range, process/thread IDs, address, and auxiliary data.
Optional service provenance uses an ingestion timestamp and service sequence that must appear
together, and ingestion cannot predate the source timestamp. Display text is optional payload and
has no policy meaning. Driver producers always leave `PolicySeverity` unevaluated; policy labels are
added only to the service's local copy after typed evaluation.

High and critical records enter a 32-record retained alert queue. Reading does not remove them;
the controller may acknowledge only a monotonically increasing sequence that the same session has
already received. Alert reads reject cursors older than the acknowledged sequence or newer than the
highest sequence previously delivered to that controller. If the queue is full, existing alerts
remain intact, the rejected record receives the next publication sequence, and the driver
permanently records the first lost sequence plus high/critical loss counts. A production session
applies that latch as an evidence-loss revocation on its next authenticated operation. The queue
publisher only fills one fixed record and copies it under a spin lock; it does not allocate, acquire
a push lock, or perform user-mode work.
Target-derived callbacks capture the exact session ID/generation under the existing session
synchronization before publication, and the queue rejects the record if that identity changed.

Info, low, and medium records use an independent 256-record overwrite queue. Its cursor is
non-destructive, and overwrite advances the first available sequence while recording an exact
drop count and first gap. Inventory pressure therefore cannot overwrite a retained alert.

One session may also own one frozen kernel-module snapshot. `OPEN` captures a bounded AuxKlib
module inventory, assigns random snapshot identity plus scan and cursor generations, and sets a
30-second boot-relative expiration. `READ` returns immutable pages by cursor; `CLOSE` retires the
snapshot. Collection failure is returned as a validated `FAILED` snapshot state with an exact NT
status rather than an ambiguous transport failure. A revoked session may finish reading existing
evidence but cannot start new snapshot work.

The restricted service polls the alert channel first and then the event channel every 250 ms while
waiting for stop, failure, or target exit. It validates every response and correlation tuple,
stamps each local copy with an ingestion time and monotonic service sequence, performs a final
bounded drain on orderly stop or target transition, and queues the evaluated record for backend
delivery. Alert acknowledgement on the next read advances only through the highest alert
acknowledged by the backend. Alert loss, a revoked response, backend queue exhaustion, or acknowledgement
timeout is a fail-closed service error. Lower-priority overwrite gaps remain explicit and do not
consume alert capacity.

`shared/oac_policy.*` binds every current rule to its exact event type, category, observation range,
and required provenance. It maps the record through deterministic Observe, Enforce, or Strict
tables and returns separate action, five-level policy confidence, and policy severity fields. The
service selects the authenticated policy's rule set and deployment mode. It preserves the
observation's original confidence and source provenance, queues the record with its exact decision,
and ends the service runtime for `RevokeSession`. Current endpoint-preflight and driver-trust rules
use `DenyLaunch`; runtime target violations may request review or revoke the session according to
the signed deployment mode. Both the deterministic test transport and production backend must
acknowledge the exact service sequence before the service advances retained-alert acknowledgement.

### Launcher/service IPC

The local launcher/service wire revision is `0x00010007`. Hello and status retain fixed 32-byte
requests. Status responses are 304 bytes and include the session-loss sequence and cause, endpoint
configuration, driver-gate count and completed-scan identity, a strict 32-byte backend record, and a
strict 184-byte scanner record. The backend record reports lease
state, authenticated/test flags, pending evidence, last error, lease sequence, and acknowledged
service sequence. The scanner record reports health-loop iterations and maximum delay,
queued/completed/coalesced/cancelled/failed slices, completed sweeps, memory and thread coverage,
last-slice timing and resource use, maximum scan and thread-suspension duration, and the current
worker state/outcome/error. Counts, state, timestamps, reserved fields, and success/error pairs are
validated by both endpoints. A launch request is a fixed 1056-byte message containing one counted
absolute drive path with no arguments;
its 56-byte response correlates the request, service, client, session, target PID, confirmed binding,
verified job assignment, and resumed-thread result. A rejection also carries an exact
launch stage and a bounded detail so failures remain attributable without enabling filesystem
logging in the restricted service. Manifest verification has explicit missing, malformed,
signature, build, expiry, and rollback details. Both endpoints reject unknown
types or flags, wrong sizes or revisions, zero request IDs, nonzero reserved data, malformed UTF-16,
unsafe path components, and dirty unused path units.

## Diagnostic compatibility protocol

`OAC_PROTOCOL_VERSION` is `0x00040000`. Ping remains a bounded compatibility query, while configure,
scan, finding drain, CPU snapshot, and status require `LabMode=1` plus a diagnostic session on the
same file object. `OAC-Client` retains one handle for its run and refuses production mode.

The diagnostic finding ring and report path retain their known limitations: one overwrite ring,
destructive batch reads without acknowledgement, and display-oriented user-mode re-sequencing. It is not a
fallback production authority and must remain unavailable when lab mode is off.

`shared/protocol/oac_test.h` defines one separately versioned injection request used only to stress
the transport in the disposable VM. The driver accepts it only with `LabMode=1` from the owner of an
authenticated diagnostic session; it is not advertised as a production capability.

## Test coverage and acceptance

The driver-free C/C++ unit executable covers layouts, distinct IOCTLs, exact message-type matching,
request/response validation, evidence and snapshot correlation, the session transition matrix,
hostile binary and UTF-16 event payloads, and backend record, replay, lease, queue, and
acknowledgement behavior. The current driver-free suite passes `739/739`; the driver-backed VM
campaign remains a separate runtime gate for each coherent kernel/runtime milestone.

The driver-backed suite contains production negotiation/claim/status/revoke malformed-input checks,
bidirectional diagnostic/production per-file exclusion, same-file and wrong-file authorization, a
duplicated-handle wrong-process check, cleanup authority loss, fresh session ID/generation checks,
and a bounded four-thread status/close race after 32 successful status calls per thread. The current
source additionally exercises retained alerts, monotonic acknowledgement, explicit event gaps,
10,000-record inventory pressure, concurrent producers, frozen snapshot paging/correlation, full
alert-queue loss provenance, and diagnostic authority after lab-only overflow. It also verifies
explicit revoke provenance and idempotency, malformed launch rejection, and that diagnostic
sessions cannot invoke production launch operations. The complete WP-01 through WP-12 suite passed
at implementation commit `67d3f616cdb13f1ac10877d067da1b54cca5e51c` on Windows 11 Pro build
26100. Four driver-backed protocol executions passed under the baseline and standard Driver
Verifier phases.

The endpoint-admission source adds malformed and authorization checks for the configuration and
scan messages, status invariants, current-state evidence correlation, loaded-driver trust, runtime
module policy, and target memory/thread observations. The exact `974d2c4` package passed those paths
in the Windows 11 build 26100 and standard Driver Verifier campaign.

Driver-free tests cover launch layouts, hostile paths and fields, expiry/cancel/replay decisions,
response correlation, explicit revoke/liveness layouts, lease-state decisions, IPC validation, and
the complete fixed policy catalog in every deployment mode. They also cover the canonical manifest
layout, malformed identities/names/reserved data, exact file matching, component compatibility,
expiry, monotonic updates, rollback, same-sequence equivocation, and corrupt high-water state.
Signed-policy tests cover canonical layout, scope, time and component bounds, emergency and rollback
operations, replay, equivocation, explicit rollback, preserved historic high-water state, and
malformed cache records. Policy tests cover typed drift,
malformed signer states, incomplete provenance, deterministic results, and display-text
independence.
The production-boundary test verified job ownership, service-crash and graceful-stop target-tree
termination, recovery, monotonic session-loss reporting, two accepted signed launches, and
modified, wrong-build, expired, and rollback manifest rejection in the same named campaign.
The same production boundary rejected policies with the wrong signature, scope, validity period, or
rollback state, accepted one explicitly authorized rollback, and persisted emergency revocation
before refusing startup. The current VM harness additionally contains bounded backend replay,
withheld-acknowledgement, lease-loss, target-tree termination, and clean-recovery cases; all passed
in the named campaign.
The current campaign required bounded scheduler coverage, health latency, slice duration, and
thread-resume metrics. It accepted 37 completed slices, eight completed sweeps, a 406 ms maximum
health-loop delay, a 107.878 ms maximum slice duration, a 1.750 ms maximum thread suspension, and no
failed or cancelled slice.
