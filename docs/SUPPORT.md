# Support scope

OAC is currently an engineering reference. This page distinguishes **build support**, **runtime
evidence**, and **production support** so that a successful laboratory campaign is not presented as
a general compatibility promise.

## Current status

| Area | Status | Boundary |
|---|---|---|
| Source build | Supported for contributors | Visual Studio 2022, v143, Windows SDK/WDK `10.0.26100.0`, x64 Debug and Release |
| Backend source build | Supported for contributors and CI | .NET 8 Debug and Release with locked dependencies, analyzers enabled, and framework-dependent publication |
| Driver-free tests | Supported for contributors and CI | Exact suite and revisions recorded in the current development evidence |
| Disposable VM | Tested on one named configuration | Windows 11 Pro build 26100, Generation 2 Hyper-V, networkless, Secure Boot off, test signing on, standard Driver Verifier |
| Public unsigned candidate | Implemented | Exact public/lab allowlists, deterministic metadata, SPDX SBOM, checksums, private-symbol separation |
| Production Windows deployment | Not supported | Microsoft certification, production signatures, rollout infrastructure, compatibility matrix, and operating approvals are absent |
| Backend and game integration | Reference implementation | Mutual-TLS admission, durable single-node state, typed .NET game adapter, and one movement detector are supplied; managed deployment, engine binding, account policy, and adjudication are not |

The named VM campaign demonstrates behavior only for its exact source commit, Windows build,
package, and security configuration. It does not certify Windows 10, Windows Server, other Windows
11 releases, HVCI/VBS, Secure Boot production loading, physical hardware, third-party overlays,
accessibility tools, anti-virus products, or a real game workload.

## Platform admission

A platform or configuration may be listed as supported only after all of these gates pass on a
production-signed package:

- installation, upgrade, rollback, removal, and reboot recovery;
- Secure Boot and the intended Code Integrity, HVCI, VBS, and virtualization configuration;
- production service identity, launcher IPC, backend admission, target launch, containment, and
  failure recovery;
- standard Driver Verifier with zero relevant crashes, dumps, or leaks;
- representative CPU, storage, graphics, input, accessibility, overlay, capture, security-product,
  and game-engine workloads;
- false-positive, performance, privacy, and data-retention review; and
- signed release-manifest, SBOM, symbol, support, and rollback records.

An OS update, driver ABI change, WDK/toolchain change, signing-policy change, or material hardware
class change reopens the affected part of the matrix. Unknown configurations must fail closed for
authority and degrade explicitly for optional observations; they must never inherit a support claim
from a similar build number.

## Compatibility reporting

Reports and support requests should include only what is necessary to reproduce the issue:

- OAC release and source commit from `release-manifest.json`;
- Windows edition, version, build, and relevant security configuration;
- CPU architecture and the broad hardware/driver class involved;
- signed package hashes and signature status;
- exact operation, error code, and bounded sanitized logs; and
- whether the issue reproduces without unrelated overlays or security software.

Do not attach raw hardware identifiers, full memory dumps, signing material, backend credentials,
or unredacted reports to a public issue. Use the private path in [SECURITY.md](../SECURITY.md) for a
security defect and follow the [privacy policy](PRIVACY.md) when collecting diagnostic material.

The detailed test inventory and exact historical evidence remain in the
[test matrix](TEST_MATRIX.md) and [development records](development/README.md).
