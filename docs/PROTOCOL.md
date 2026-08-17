# OAC protocol

**Status:** The production-control ABI is separate from the lab-only diagnostic compatibility ABI

**Foundation source:** Integrated after baseline `075ad2109f84cce90727f8ba65f87b807500e6b7`;
current disposable-VM acceptance is pending

`shared/protocol/oac_v5.h` and `shared/protocol/oac_validate.h` are the production wire-format and
validation sources of truth. `shared/oac_protocol.h` defines the separate diagnostic compatibility
ABI. All wire headers are C-compatible and have compile-time size and offset assertions.

## Production control protocol

`OAC_PRODUCTION_PROTOCOL_VERSION` is `0x00050002`; the existing `OAC_V5_VERSION` name remains a
compatibility alias. Every request uses `METHOD_BUFFERED` and requires both read and
write access. The request and response headers carry an exact size, nonzero request ID, 128-bit
session ID, generation, flags, and explicit `MessageType`. The message type is tied to the IOCTL
function number and is validated even when every other field is well formed.

The current driver advertises `OAC_V5_CAP_SESSION_CONTROL | OAC_V5_CAP_LAUNCH_TICKET`. Negotiate,
claim, status, arm, cancel, and confirm are available:

| Function | IOCTL | Input | Output | Current behavior |
|---:|---|---|---|---|
| `0x810` | `IOCTL_OAC_V5_NEGOTIATE` | 56-byte negotiate request | 88-byte negotiate response | Selects the exact production revision and records negotiation on the file context |
| `0x811` | `IOCTL_OAC_V5_CLAIM_SESSION` | 56-byte claim request | 64-byte claim response | Claims one production or lab diagnostic session |
| `0x816` | `IOCTL_OAC_V5_GET_STATUS` | 48-byte status request | 120-byte status response | Returns correlated session state, identity, capability, and counter data |
| `0x818` | `IOCTL_OAC_ARM_LAUNCH` | 2112-byte arm request | 88-byte arm response | Arms one bounded canonical-path ticket on the claimed production session |
| `0x819` | `IOCTL_OAC_CANCEL_LAUNCH` | 64-byte cancel request | 64-byte cancel response | Terminally cancels the exact pending ticket |
| `0x81A` | `IOCTL_OAC_CONFIRM_TARGET` | 72-byte confirmation request | 72-byte confirmation response | Confirms the exact bound process handle and enters monitoring |

The shared header reserves config, scan, event-read, CPU-snapshot, and revoke IOCTL/message IDs for
later work. They are not dispatched by the production path and their capabilities are not
advertised. `OAC_V5_CAP_TYPED_EVENTS` therefore remains clear.

### Launch transaction

One production session may arm one ticket with a 100 ms to 10 second lifetime and two exact Windows
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

The controller is permitted to create exactly one child process per production session. After a
target is bound, any additional process creation by that exact service process is denied for the
remaining target lifetime; helpers must run in a separate service that holds no production authority.

Cancellation, expiry, a trusted-creator path mismatch, and failed process-handle confirmation are
terminal revocations. Pending path data is cleared on consumption; the retained launch ID is cleared
on confirmation; all launch data is cleared on cancellation, revocation, cleanup, service exit, and
driver shutdown. A live session-owned target remains protected after controller cleanup until its
process-exit notification retires the tombstone.

The service performs one serialized transaction: it authenticates the local launcher, resolves and
keeps one executable open under that caller identity, arms the ticket, creates the process suspended
with the caller's primary token, confirms the exact process handle, validates the monitoring state,
and resumes the initial thread. Cancellation is issued only after a failed synchronous create or a
pre-create stop decision; later failures terminate the suspended target and stop the service. The
kernel callback deliberately performs no hashing, signature verification, filesystem I/O, or
registry access. Signed-manifest identity and kill-on-close job ownership remain separate work
packages.

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

Negotiation currently returns strict-length support. It reports diagnostic compatibility only
when `LabMode=1` was read at driver start.

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

If cleanup occurs while a referenced target is still live, the cleaned session remains as an
unusable tombstone. It blocks a replacement claim until the target exit callback releases the
target and retires the session. This prevents a new controller from inheriting authority while
stale protection state still exists. The kernel invariant is implemented in source; its target-live
service-transaction VM acceptance remains pending.

### Typed event schema

`OAC_V5_EVENT_RECORD` is a defined and strictly validated 560-byte schema. It separates stable rule
and event IDs, observation severity, policy severity, confidence, category, payload type, and
evidence flags. It preserves source provenance through session ID, generation, kernel sequence and
timestamp, scan ID, occurrence count and range, process/thread IDs, address, and auxiliary data.
Optional service provenance uses an ingestion timestamp and service sequence that must appear
together, and ingestion cannot predate the source timestamp. Display text is optional payload and
has no policy meaning.

The driver does not yet publish production event records. Separate alert, event, and snapshot transports,
acknowledgement, cursors, and paging remain WP-06 work.

### Launcher/service IPC

The local launcher/service wire revision is `0x00010002`. Hello and status retain fixed 32-byte
requests and 56-byte responses. A launch request is a fixed 1056-byte message containing one counted
absolute drive path with no arguments; its 56-byte response correlates the request, service, client,
session, target PID, confirmed binding, and resumed-thread result. A rejection also carries an exact
launch stage and a bounded driver-revocation detail so failures remain attributable without enabling
filesystem logging in the restricted service. Both endpoints reject unknown
types or flags, wrong sizes or revisions, zero request IDs, nonzero reserved data, malformed UTF-16,
unsafe path components, and dirty unused path units.

## Diagnostic compatibility protocol

`OAC_PROTOCOL_VERSION` is `0x00040000`. Ping remains a bounded compatibility query, while configure,
scan, finding drain, CPU snapshot, and status require `LabMode=1` plus a diagnostic session on the
same file object. `OAC-Client` retains one handle for its run and refuses production mode.

The diagnostic finding ring and report path retain their known limitations: one overwrite ring,
destructive batch reads without acknowledgement, and display-oriented user-mode re-sequencing. It is not a
fallback production authority and must remain unavailable when lab mode is off.

## Test coverage and pending gate

The driver-free C/C++ unit executable covers layouts, distinct IOCTLs, exact message-type matching,
request/response validation, correlation, the session transition matrix, and hostile binary and
UTF-16 event payloads.

The driver-backed suite now contains production negotiation/claim/status malformed-input checks,
bidirectional diagnostic/production per-file exclusion, same-file and wrong-file authorization, a
duplicated-handle wrong-process check, cleanup authority loss, fresh session ID/generation checks,
and a bounded four-thread status/close race after 32 successful status calls per thread. It also
verifies that malformed launch messages are rejected and that diagnostic sessions cannot invoke
production launch operations. The source coverage is present, but its current disposable-VM
execution and Driver Verifier evidence remain pending.

Driver-free tests cover launch layouts, hostile paths and fields, expiry/cancel/replay decisions,
response correlation, and IPC validation. The VM production boundary supplies the successful
standard-user service transaction. Service-owned job/liveness, event transport, signed manifests
and policy, and authenticated backend sessions remain separate work packages.
