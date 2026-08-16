# OAC protocol

**Status:** Protocol v5 is the production-control ABI; protocol v4 is lab-only compatibility

**Foundation source:** Integrated after baseline `075ad2109f84cce90727f8ba65f87b807500e6b7`;
current disposable-VM acceptance is pending

`shared/protocol/oac_v5.h` and `shared/protocol/oac_validate.h` are the production wire-format and
validation sources of truth. `shared/oac_protocol.h` defines the separate protocol-v4 diagnostic
ABI. All wire headers are C-compatible and have compile-time size and offset assertions.

## Protocol v5 production control

`OAC_V5_VERSION` is `0x00050000`. Every request uses `METHOD_BUFFERED` and requires both read and
write access. The request and response headers carry an exact size, nonzero request ID, 128-bit
session ID, generation, flags, and explicit `MessageType`. The message type is tied to the IOCTL
function number and is validated even when every other field is well formed.

The current driver advertises only `OAC_V5_CAP_SESSION_CONTROL` and implements this production
surface:

| Function | IOCTL | Input | Output | Current behavior |
|---:|---|---|---|---|
| `0x810` | `IOCTL_OAC_V5_NEGOTIATE` | 56-byte negotiate request | 88-byte negotiate response | Selects exact v5 and records negotiation on the file context |
| `0x811` | `IOCTL_OAC_V5_CLAIM_SESSION` | 56-byte claim request | 64-byte claim response | Claims one production or lab diagnostic session |
| `0x816` | `IOCTL_OAC_V5_GET_STATUS` | 48-byte status request | 120-byte status response | Returns correlated session state, identity, capability, and counter data |

The shared header reserves config, scan, event-read, CPU-snapshot, and revoke IOCTL/message IDs for
later work. They are not dispatched by the production v5 path and their capabilities are not
advertised. In particular, `OAC_V5_CAP_TYPED_EVENTS` and `OAC_V5_CAP_LAUNCH_TICKET` remain clear.

### Strict validation and correlation

Shared validators reject:

- truncated, oversized, or falsely stated fixed lengths;
- versions other than exact v5 and negotiation ranges that do not include exact v5;
- zero request IDs, unknown flags, nonzero reserved data, and unknown enum values;
- a `MessageType` that does not match the IOCTL;
- a session ID or generation where an open request requires zero, or a session request requires
  nonzero values;
- response/request mismatches in message type, request ID, session ID, or generation;
- overflow, misalignment, out-of-range payloads, hidden bytes after a payload, and malformed UTF-16.

Negotiation currently returns strict-length support. It reports v4 diagnostic compatibility only
when `LabMode=1` was read at driver start.

Protocol families are mutually exclusive per file. Negotiation is serialized with claim under the
session lock. Once a file negotiates v5, privileged v4 calls cannot create or use a diagnostic
session. Once a file claims the unnegotiated v4 diagnostic path, it cannot later negotiate v5. This
prevents a handle from switching authorization semantics after either path has established state.

### Per-file authority and lifetime

`IRP_MJ_CREATE` allocates a file context and references the process that opened that exact file
object. Outside lab mode, create succeeds only for the restricted `OACService` identity. A claim
requires prior v5 negotiation on the same file. Production claim then requires all of:

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
stale protection state still exists. The invariant is implemented in source; its target-live VM
acceptance test is pending because production launch/target binding is not implemented yet.

### Typed event schema

`OAC_V5_EVENT_RECORD` is a defined and strictly validated 560-byte schema. It separates stable rule
and event IDs, observation severity, policy severity, confidence, category, payload type, and
evidence flags. It preserves source provenance through session ID, generation, kernel sequence and
timestamp, scan ID, occurrence count and range, process/thread IDs, address, and auxiliary data.
Optional service provenance uses an ingestion timestamp and service sequence that must appear
together, and ingestion cannot predate the source timestamp. Display text is optional payload and
has no policy meaning.

The driver does not yet publish v5 event records. Separate alert, event, and snapshot transports,
acknowledgement, cursors, and paging remain WP-06 work.

## Protocol v4 lab compatibility

`OAC_PROTOCOL_VERSION` is `0x00040000`. Ping remains a bounded compatibility query, while configure,
scan, finding drain, CPU snapshot, and status require `LabMode=1` plus a diagnostic session on the
same file object. `OAC-Client` retains one handle for its run and refuses production mode.

The v4 finding ring and report path retain their known limitations: one overwrite ring, destructive
batch reads without acknowledgement, and display-oriented user-mode re-sequencing. V4 is not a
fallback production authority and must remain unavailable when lab mode is off.

## Test coverage and pending gate

The driver-free C/C++ unit executable covers layouts, distinct IOCTLs, exact message-type matching,
request/response validation, correlation, the session transition matrix, and hostile binary and
UTF-16 event payloads.

The driver-backed suite now contains v5 negotiation/claim/status malformed-input checks, bidirectional
v4/v5 per-file exclusion, same-file and wrong-file authorization, a duplicated-handle wrong-process
check, cleanup authority loss, fresh session ID/generation checks, and a bounded four-thread
status/close race after 32 successful status calls per thread. The source coverage is present, but
its current disposable-VM execution and Driver Verifier evidence remain pending.

Launch tickets, production target binding, service-owned job/liveness, event transport, signed
manifests and policy, and authenticated backend sessions are not part of the current protocol
surface.
