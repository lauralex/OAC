# Release engineering

OAC separates a **reviewable unsigned candidate** from the credentials and infrastructure required
to publish production software. The repository can build and validate the candidate. It cannot, by
itself, produce a supported production release.

> [!IMPORTANT]
> The public CI artifact is unsigned and must not be installed on a normal workstation. Production
> publication still requires Microsoft driver certification, protected signing keys, final
> signature verification, compatibility acceptance, and an approved rollout.

## Candidate contract

[`config/release-profile.json`](../config/release-profile.json) is the source of truth for the
release number, driver version, toolchain boundary, compatibility revisions, and exact artifact
allowlists. [`tools/Test-OACReleaseProfile.ps1`](../tools/Test-OACReleaseProfile.ps1) binds every
value back to the headers, INF, projects, and build settings that define it.

The candidate generator accepts only a clean source tree for a production candidate. A
`-DevelopmentBuild` switch exists for local validation, is marked in the manifest, and is rejected
when `CI` is set.

```text
candidate/
├── public/                         unsigned production-component set
│   ├── driver/
│   │   ├── OAC.sys
│   │   ├── OAC.inf
│   │   └── OAC.cat
│   ├── OAC-Service.exe
│   ├── OAC-Launcher.exe
│   ├── LICENSE.txt
│   ├── release-manifest.json
│   ├── sbom.spdx.json
│   └── SHA256SUMS
├── symbols/                        private; never uploaded by public CI
│   ├── OAC.pdb
│   ├── OAC-Service.pdb
│   ├── OAC-Launcher.pdb
│   ├── symbols-manifest.json
│   └── SHA256SUMS
└── lab/                            isolated test use only
    ├── OAC-Client.exe
    ├── OAC-Protocol-Test.exe
    ├── OAC-Protocol-Unit.exe
    ├── LAB-ONLY.txt
    ├── lab-manifest.json
    └── SHA256SUMS
```

The generator rejects missing, extra, renamed, signed, stale, or reparse-backed inputs. It copies
through a fresh staging directory, publishes by directory rename, and then reconstructs every
metadata file and checksum from the current build and source. Validation rejects alternate data
streams, public PDBs, symbol mismatches, and public/lab boundary violations. The hostile test suite
mutates a payload, manifest, PDB, allowlist, and lab marker and requires all five cases to fail.

```powershell
$candidate = Join-Path $env:TEMP 'oac-candidate'

.\tools\New-OACReleaseCandidate.ps1 `
  -BuildDirectory .\x64\Release `
  -OutputDirectory $candidate

.\tools\New-OACReleaseCandidate.ps1 `
  -BuildDirectory .\x64\Release `
  -OutputDirectory $candidate `
  -ValidateOnly
```

The output directory must be outside the repository and must not already exist.

## Backend deliverables

The Windows endpoint candidate above remains a narrow native package. The separately deployable
backend is built from [`OAC-backend`](../OAC-backend/) and published as two independent artifacts:

- a framework-dependent .NET 8 `OAC.Backend` application; and
- an `OAC.GameAdapter` NuGet package for authoritative game-server integration.

```powershell
dotnet restore .\OAC-backend\tests\OAC.Backend.Tests.csproj --locked-mode
dotnet publish .\OAC-backend\OAC.Backend.csproj -c Release --no-restore `
  -o $env:TEMP\oac-backend
dotnet pack .\OAC-backend\game-adapter\OAC.GameAdapter.csproj -c Release `
  --no-restore -o $env:TEMP\oac-game-adapter
```

The release profile binds the endpoint and backend wire compatibility, while backend server
configuration, certificate pins, policy records, private keys, and durable state remain deployment
inputs and must never enter either artifact. Public CI uploads these managed artifacts separately
for review; they are not a managed production deployment or a substitute for promotion approval.
The exact managed dependency is locked, and its separate license is recorded in
[`OAC-backend/THIRD-PARTY-NOTICES.md`](../OAC-backend/THIRD-PARTY-NOTICES.md). A production promotion
must add the managed artifacts and dependency inventory to the release SBOM and preserve their exact
hashes alongside the endpoint candidate.

## Reproducible metadata

The candidate records:

- the exact Git commit and clean-tree state;
- the source commit timestamp, used as the normalized metadata timestamp;
- the release, driver, protocol, IPC, backend, manifest, policy, and game-schema revisions;
- matching Windows file/product/original-name metadata in the driver, service, and launcher;
- Visual Studio, MSBuild, compiler, linker, SDK, configuration, and platform identities; and
- the exact size and SHA-256 of every distributed file.

Metadata JSON is emitted as UTF-8 without a byte-order mark, with LF endings and stable property
and artifact order. The SPDX 2.3 document uses the same normalized commit timestamp and states that
normalization explicitly. The build disables WDK wall-clock `DriverVer` stamping and preserves the
reviewed INF date and version.

This is **deterministic metadata**, not a claim that MSVC and WDK outputs are bit-for-bit
reproducible on arbitrary machines. A candidate is trusted only when the controlled workflow builds
it from a fresh clean checkout and the recorded hashes match the promoted files.

## SBOM

`sbom.spdx.json` is a schema-valid SPDX 2.3 document for the public candidate. It identifies every
distributed file, its SHA-256 checksum, the package verification code, the source commit namespace,
and the declared Apache-2.0 package license. File-level detected licenses are `NOASSERTION` because
the generator inventories release files; it is not a binary license scanner.

The [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/) and its
[conformance rules](https://spdx.github.io/spdx-spec/v2.3/conformance/) are the format authority.

The native endpoint candidate does not package third-party libraries. Windows system components and
the Microsoft toolchain are build/runtime prerequisites rather than redistributed components, so
they are captured in the build metadata and support boundary rather than listed as package files.
The separate backend artifact carries its locked managed cryptography dependency and therefore
requires its own dependency inventory during production promotion.

## Symbols

Release binaries record only the PDB leaf name through `/PDBALTPATH:%_PDB%`. The generator verifies
one matching RSDS record and the exact full PDB before separating symbols. Public CI uploads only
`public/` and `lab/`; it never uploads `symbols/`.

Production operators must retain the full PDBs and `symbols-manifest.json` in an access-controlled
symbol store keyed by release and source commit. Access should be limited to incident responders
who need to analyze trusted dumps. If public symbols are ever offered, generate a reviewed stripped
set with PDBCopy and publish it as a separate artifact; the repository currently publishes none.

Microsoft documents both [alternate PDB paths](https://learn.microsoft.com/en-us/cpp/build/reference/pdbaltpath-use-alternate-pdb-path?view=msvc-170)
and [private/public symbol separation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/using-pdbcopy).

## Production signing and certification

The production promotion boundary is deliberately outside public CI:

1. Create the exact unsigned candidate from a clean, reviewed tag on an isolated release runner.
2. Archive the private symbol bundle in the restricted symbol store.
3. Submit the driver package through the Microsoft Hardware Dev Center path appropriate to the
   supported Windows release. A retail release must satisfy the current HLK and certification
   requirements; lab attestation is not treated as retail certification.
4. Verify that the returned Microsoft-signed catalog is bound to the exact INF and SYS submitted.
5. Authenticode-sign the service and launcher with the production user-mode signing identity and a
   trusted timestamp. The private key must be non-exportable and held by an HSM or equivalent
   managed signing service.
6. Rebuild the final public manifest, SBOM, and checksums from the signed artifacts. Never edit the
   unsigned manifest in place.
7. Run malware scanning, signature validation, package identity checks, the supported-platform
   matrix, and staged deployment acceptance before publication.
8. Preserve the source tag, workflow identity, unsigned and signed hashes, Microsoft submission
   record, signatures, SBOM, private-symbol record, test evidence, approvals, and rollback package.

Required final checks include `InfVerif /w`, `SignTool verify /kp` for the driver package and catalog
membership, `SignTool verify /pa` for user-mode binaries, certificate-chain and timestamp review,
and an exact allowlist comparison against the signed release manifest. The Microsoft documentation
for [Hardware Dev Center submissions](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/)
and [validating a Microsoft signature](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-validate)
is authoritative; requirements must be rechecked at each promotion.

No PFX, certificate private key, Hardware Dev Center credential, HSM token, timestamp credential,
or backend secret belongs in Git, a GitHub Actions secret available to pull requests, or a public
artifact.

## Signing-key rotation

OAC has four distinct trust purposes and they must remain separate:

| Trust purpose | Custody and rotation rule |
|---|---|
| Microsoft driver submission | Organization-controlled Hardware Dev Center identity; rotate under current Microsoft enrollment rules and audit every submission |
| User-mode Authenticode | Non-exportable production key; overlap old/new certificates only for a reviewed migration window |
| Game-manifest authorization | Offline signing authority distinct from release signing; a future signed key-metadata record must authorize additions and revocations |
| Policy authorization | Separate offline policy authority; rollback and emergency-revocation semantics remain bound to the signed policy state |

The source currently pins explicitly provisioned manifest and policy signers. It does **not** yet
implement signed manifest-key rotation metadata. Until that feature exists, changing either pin is
a reviewed software update with a staged compatibility window, not a remote configuration change.
A suspected key compromise immediately stops promotion, revokes the affected identity at the
distribution boundary, preserves forensic records, and follows the incident runbook.

## Update and rollback model

Releases are immutable. An update receives a new release identity and manifest; files are never
silently replaced behind a running service. A production updater must:

1. authenticate the update metadata and channel;
2. verify release, component, protocol, policy, and game-manifest compatibility;
3. stop new launches, revoke the active driver session, and contain the target tree;
4. stop the service and demand-start driver, then replace the verified package atomically;
5. start the service, verify signatures and health, and admit launches only after backend lease and
   policy checks succeed; and
6. emit an auditable success or restore the previously approved package.

Rollback is allowed only to a retained, signed, previously approved package whose compatibility
contract is still accepted. It does not bypass manifest or policy high-water state: policy rollback
still needs its existing explicit signed authorization, and emergency revocation remains terminal.
Database/schema migrations must be forward/backward compatible for the rollback window or provide
a tested restoration procedure before rollout begins.

See [operations](OPERATIONS.md) for staged rollout, rollback, key compromise, and incident steps,
and [support scope](SUPPORT.md) for the compatibility evidence required before a platform is
advertised.
