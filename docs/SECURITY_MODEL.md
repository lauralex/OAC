# OAC security model

**Status:** WP-01 through WP-03 controls implemented in source; current disposable-VM acceptance
pending

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

This model separates source state, test evidence, planned controls, and unsupported guarantees.
[`../SECURITY.md`](../SECURITY.md) covers vulnerability reporting; this document covers assets,
trust boundaries, adversaries, and failure behavior.

## Assets

- Integrity and availability of the protected game process.
- Authority to configure and query the OAC driver.
- Kernel observations and their source sequence, time, and completeness.
- Game-build, rule, policy, and component identity.
- Player and hardware-identity privacy.
- Signing material, backend credentials, and revocation state.

## Current trust boundaries

| Boundary | Current behavior | Evidence state |
|---|---|---|
| Driver load | Windows Code Integrity decides whether the demand-start driver image may load | Existing control; current driver remains unsigned by default |
| Driver device | Production DACL grants SYSTEM and the exact service SID; Administrators are added only with `LabMode=1` | Implemented in source; VM ACL checks pending |
| Service identity | Restricted, session-0 LocalSystem service verifies its enabled and restricted service SID before opening the driver | Implemented in source; VM identity checks pending |
| Driver controller | One v5 session is bound to the CREATE-owner process object, service process object, exact file object, random session ID, and generation | Implemented in source; lifecycle VM checks pending |
| Launcher IPC | Local, remote-rejecting, status-only named pipe with server/client identity cross-checks | Implemented in source; unauthorized-client VM checks pending |
| Protected target | No production target binding or launch exists; v4 lab mode can bind an already-created diagnostic target | Production control planned in WP-04 |
| User-mode handles | Object callbacks strip selected dangerous process/thread rights for a bound target | Existing implementation; production use awaits target binding |
| Driver-load evidence | Load callback plus monotonic post-start counters | Existing implementation; current VM rerun pending |
| Typed evidence | Stable v5 IDs and provenance-preserving record schema are defined with pure validation tests | Test source present; v5 transport planned |
| Local report | V4 lab scanner uses a per-run unkeyed SHA-256 chain and artifact digests | Lab-only and not authenticated |
| Policy, manifest, backend | No production trust boundary exists | Planned |

## Production authority

Production file creation and claim require the exact restricted service token, not Administrator
membership. Negotiation and claim occur on one persistent service handle. Every later accepted v5
request must use that file from the referenced service process and match the session ID, generation,
and active state. Numeric PIDs are returned only for diagnostics and cannot authorize a request.

One active session is allowed. A different file can negotiate but cannot claim or reuse copied
session values. A duplicated handle used by another process is rejected by process-object identity.
Accepted requests hold rundown protection so cleanup can stop acquisition and wait for in-flight
work before releasing controller objects.

V4 and v5 authorization cannot be mixed on one file. Negotiation and claim are serialized: a
v5-negotiated or claimed file cannot issue privileged v4 operations, while a file that claimed the
unnegotiated v4 diagnostic path cannot later negotiate v5.

### Tombstone invariant

Cleanup marks the session closing and records file-cleanup revocation. If no target is referenced,
the session retires. If a target is still live, the cleaned session stays installed as an unusable
tombstone and blocks a replacement claim. Only target exit removes the last target reference and
permits retirement. This prevents a new controller from inheriting a driver whose prior target
protection state is still active.

The invariant is implemented in source. A production session cannot bind a target yet, so the
target-live case currently arises only through the v4 lab compatibility path; its current VM
acceptance evidence is pending.

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

An administrator capable of obtaining SYSTEM, replacing trusted binaries, changing protected
service configuration, or loading arbitrary kernel code is only partially observable. The service
SID and per-file session raise the control boundary but do not make a compromised local
administrator, kernel, firmware, or hypervisor trustworthy.

## Security invariants implemented in source

- The driver and service remain demand-start; `OAC/OAC.inf` keeps `StartType=3`.
- Production code does not load vulnerable drivers, patch Code Integrity or PatchGuard, hide kernel
  state, install undocumented loader hooks, or weaken host security controls.
- Kernel callbacks and IPI routines perform bounded, IRQL-appropriate work.
- Private kernel profiles are optional and exact-image gated.
- V5 uses fixed, C-compatible layouts with explicit `MessageType`, strict sizes, request/session
  correlation, reserved-field checks, flag masks, and bounded payload validation.
- Production device and claim authorization require the exact restricted service identity; direct
  administrator control is lab-only.
- Each file selects one protocol authority path; v4 and v5 cannot be combined to bypass state or
  identity checks.
- File cleanup drains in-flight requests, revokes authority, and preserves a live-target tombstone.
- Raw hardware serials are not written to reports; removable devices do not become core anchors.

These statements describe source behavior, not completed platform acceptance. Driver-backed v5,
service installation, ACL, lifecycle, race, and Driver Verifier tests must pass in the disposable VM
before WP-02 or WP-03 can be marked complete.

## Planned controls

- One-time launch tickets and creation-time target binding.
- Kill-on-close job ownership and deterministic target termination after service/session/backend
  loss.
- Separate critical alert, operational event, and paged snapshot transports.
- Independent health and bounded scan workers.
- Central typed policy, signed game manifests, signed remote policy, and authenticated backend
  lease/upload.

## Evidence and enforcement

An observation, confidence assessment, policy violation, and enforcement action are distinct. A
single weak heuristic such as an overlay style, virtualization indicator, or global DR7 value is
not proof of cheating. Evidence loss, incomplete scanning, unavailable security state, or an
unsupported platform must remain explicit rather than silently becoming a clean result. Display
text has no policy meaning in the v5 schema.

Load-image callbacks are observational and cannot veto a mapping before `DriverEntry`. The v4 lab
path can fail its gate after detecting the latch; the status-only production path cannot yet launch
or revoke a game and does not claim to replace Windows Code Integrity.

## Unsupported guarantees

- Universal detection after arbitrary kernel compromise.
- Reliable observation beneath a hostile hypervisor or malicious firmware.
- DMA prevention without platform/IOMMU support.
- Support for x86, ARM64, Windows XP, or every historical Windows release.
- A literal block on all process interaction or all kernel execution.
- Authentication from the current unkeyed local report chain.

Compatibility must be stated per tested Windows build, architecture, security configuration, and
game workload. The maintained design target is native x64 Windows 10, Windows 11, and corresponding
supported Server releases; the verified support matrix remains incomplete.

## Lab-only operations

Protocol v4 direct driver control, test signing, self-signed certificates, driver installation,
Driver Verifier, private kernel profiles, `DbgUiRemoteBreakin` patching, and
`ThreadHideFromDebugger` belong only in documented diagnostic or disposable-VM paths. They are not
production trust mechanisms.
