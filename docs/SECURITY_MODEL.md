# OAC security model

**Status:** WP-01 through WP-04 controls implemented and accepted on the named Windows 11 build
26100 disposable-VM campaign

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
| Driver device | Production DACL grants SYSTEM and the exact service SID; Administrators are added only with `LabMode=1` | Named VM campaign passed service access and denied direct opens from LocalSystem, limited-user, and administrator probes |
| Service identity | The test installer sets SYSTEM owner/group and explicitly grants Administrators and Interactive query-status/start only; the restricted, session-0 LocalSystem service verifies its enabled and restricted service SID before opening the driver | Structural readback and the complete service start/status/launch path passed on Windows 11 build 26100; broader effective-right and production-deployment testing remains pending |
| Driver controller | One production session is bound to the CREATE-owner process object, service process object, exact file object, random session ID, and generation | Driver-backed lifecycle, wrong-process, cleanup, and race cases passed on the named campaign |
| Launcher IPC | Local, remote-rejecting named pipe with server/client identity cross-checks for status and one executable launch | Two standard-user status calls and one launch passed; dedicated AppContainer, remote, and impersonation-negative cases remain pending |
| Protected target | The service resolves one executable under the authenticated caller identity, creates it suspended with that token, and uses a bounded one-use ticket to bind and confirm the exact process before resume | Creation-time binding, exact-handle confirmation, and resume passed on the named campaign |
| User-mode handles | Object callbacks strip selected dangerous process/thread rights for a bound target | Baseline and Verifier protected-launch/scanner paths passed on the named campaign |
| Driver-load evidence | Load callback plus monotonic post-start counters | Armed renamed-driver gate and persistent-latch checks passed on the named campaign |
| Typed evidence | Stable production IDs and a provenance-preserving record schema are defined with pure validation tests | Test source present; production transport planned |
| Local report | The diagnostic scanner uses a per-run unkeyed SHA-256 chain and artifact digests | Lab-only and not authenticated |
| Policy, manifest, backend | No production trust boundary exists | Planned |

## Production authority

Production file creation and claim require the exact restricted service token, not Administrator
membership. Negotiation and claim occur on one persistent service handle. Every later accepted production
request must use that file from the referenced service process and match the session ID, generation,
and active state. Numeric PIDs are returned only for diagnostics and cannot authorize a request.

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
for implementation commit `bbf8f06bd9383be2d9de079a95b67d87848c280c` on Windows 11 build 26100.

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
- Handle filtering covers the creation-bound target immediately. Only protected Windows bootstrap
  processes are exempt while that target remains suspended and awaits exact-handle confirmation;
  the exemption ends before its first thread resumes.
- The service authenticates the pipe client, opens and resolves the executable under impersonation,
  duplicates the same identity to a primary token, and keeps the selected file locked against writes
  and deletion through process creation.
- The production controller may create exactly one child process per session; additional children
  from that service process are denied after target binding.
- Raw hardware serials are not written to reports; removable devices do not become core anchors.

These statements describe source behavior plus one exact platform acceptance run. The current
driver-backed production, service installation, lifecycle, race, and standard Driver Verifier
campaign passed on Windows 11 build 26100 with zero crash events and minidumps. That result does not
replace the broader supported-platform, effective-right, compatibility, or production-deployment
matrix.

## Planned controls

- Signed-manifest and stable executable-identity verification before a launch ticket is armed.
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
text has no policy meaning in the production schema.

Load-image callbacks are observational and cannot veto a mapping before `DriverEntry`. The diagnostic
path can fail its gate after detecting the latch; the production launch transaction closes the
creation-time target-binding gap but does not replace Windows Code Integrity or the later signed
manifest and liveness controls.

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

Diagnostic direct driver control, test signing, self-signed certificates, driver installation,
Driver Verifier, private kernel profiles, `DbgUiRemoteBreakin` patching, and
`ThreadHideFromDebugger` belong only in documented diagnostic or disposable-VM paths. They are not
production trust mechanisms.
