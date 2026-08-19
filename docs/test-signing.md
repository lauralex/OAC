# OAC disposable-VM test signing

This workflow exists so the driver can be exercised under Windows test-signing policy without
turning the development workstation into a permissive kernel environment. The generated
certificate and package are explicitly unsuitable for distribution or production.

## Build the package

From an ordinary build workstation with Visual Studio, the WDK, `Inf2Cat`, and `SignTool`:

```powershell
$testPackage = Join-Path $env:TEMP 'OAC-TestPackage'
.\tools\New-OACTestPackage.ps1 -Configuration Debug -OutputDirectory $testPackage
```

By default, the script creates a non-exportable ephemeral signing key and emits only the public
CER needed by the VM. Use `-ExportPrivateKey` plus a PFX password only when a repeat-signing
campaign explicitly requires a recoverable key. The script:

1. performs a clean x64 build and validates the stamped package INF with the x64
   `InfVerif /w` tool;
2. creates a 30-day RSA-3072 code-signing certificate with a conspicuous test-only subject and,
   by default, a non-exportable private key;
3. signs `OAC.sys`, every packaged user-mode executable, and the regenerated catalog, then verifies
   each file digest and signer while requiring the expected untrusted-root result for the newly
   self-signed certificate;
4. packages `OAC-Client`, `OAC-Service`, `OAC-Launcher`, and both protocol tests and writes a
   SHA-256 manifest that distinguishes protocol v5 from legacy v4; and
5. leaves the host trust anchors unchanged, always removes the exact incidental CurrentUser `CA`
   cache entry, and by default deletes the exact CurrentUser `My` certificate and its private key.
   `-KeepCertificateInCurrentUserStore` retains only that `My` certificate and key when explicitly
   requested for repeat test builds.

If `-ExportPrivateKey` is explicitly used, treat the resulting PFX as a secret, store its password
outside the package, and delete both after the isolated campaign. The default workflow emits no
PFX and leaves no signing key in the package.

The package can be checked without changing trust stores, boot configuration, drivers, or services:

```powershell
.\tools\Install-OACTestDriver.ps1 `
  -PackageDirectory (Join-Path $testPackage 'package') `
  -ValidateOnly
```

## Prepare a disposable VM

- Use a snapshot that contains no personal credentials or valuable data.
- Keep the VM isolated from production services and networks.
- Copy the package and `tools\Install-OACTestDriver.ps1` into the VM.
- If Secure Boot prevents test-signing mode, disable Secure Boot manually in the VM firmware only.
  The script never changes firmware security.
- From an elevated terminal, run:

```powershell
.\Install-OACTestDriver.ps1 `
  -PackageDirectory .\package `
  -EnableTestSigning `
  -ConfirmDisposableVm
```

Reboot if requested. Installation and removal intentionally require a LocalSystem PowerShell
process so the script can enforce the final SYSTEM-owned ACLs and still roll back an incomplete
configuration. The automated VM harness supplies that boundary. For a manually provisioned
disposable VM, enter a LocalSystem shell through the lab's trusted provisioning mechanism, then
install and start the package:

```powershell
.\Install-OACTestDriver.ps1 `
  -PackageDirectory .\package `
  -ConfirmDisposableVm `
  -LegacyV4LabMode `
  -SmokeTestPid 1234
```

The installer validates that all resolved targets remain inside the selected package directory,
imports only the package certificate into LocalMachine test trust stores, verifies the SYS/catalog,
uses `pnputil` to stage the INF, starts the `OAC` service, and can perform a client smoke scan.
The smoke client requires the explicit `-LegacyV4LabMode` switch. Without that switch, the installer
sets `LabMode=0`, installs the restricted, manual `OACService`, and leaves it stopped for the
production-boundary test phase. The service object is assigned to SYSTEM and its exact DACL grants
interactive users and administrators only query-status and start rights. The installer reads
`HKLM\SYSTEM\CurrentControlSet\Services\OAC\Start` and refuses to load the driver unless the value
is exactly `3` (`SERVICE_DEMAND_START`). From the same LocalSystem shell, verify both services
independently with:

```powershell
reg.exe query HKLM\SYSTEM\CurrentControlSet\Services\OAC /v Start
sc.exe query OAC
sc.exe qc OACService
```

Ordinary and elevated interactive users are intentionally limited to query-status and start access
on `OACService`; they cannot run the configuration query above.

The first command must report `0x3`; never change it to boot, system, or automatic start.

For an end-to-end isolated campaign, `tools\vm\New-OACSeedIso.py` builds a Joliet seed ISO only
after verifying the complete file set and rejecting PFX/P12/key material. Run
`tools\vm\Start-OACHyperVTest.ps1` from a 64-bit elevated terminal with that seed and a Windows
installation ISO to create a
networkless Generation 2 VM, retain a clean pre-Verifier checkpoint, run the production service
boundary including crash and graceful-stop standard-user launches with job-owned child processes,
protocol lifecycle/race, baseline scanner, and standard Driver Verifier phases,
copy the durable result through PowerShell Direct, and shut the guest down. The orchestrator refuses
to replace an existing VM or VHDX. Membership in Hyper-V Administrators alone is insufficient
because the read-only VHD validation also requires `SeManageVolumePrivilege`. The current production
campaign passed at acceptance commit `5c476c246462c968d98185c6db159fdaf6a0238d` on Windows 11 Pro
build 26100: 30 exact results, verified job ownership and process-tree termination, bounded scheduler
latency and coverage, typed-evidence and local-policy integration, snapshot coverage, standard Driver
Verifier, zero crash events/minidumps, and final containment were accepted. The validated result ZIP SHA-256 was
`64DB55D10284C8C07C599A821C86D866B558FDAF86E21C146EE9D91127BEADEA`.
This is evidence for that exact test configuration, not authorization to use test signing outside
a disposable VM.

## Test matrix

Exercise each maintained Windows 10, Windows 11, and Windows Server release in separate VMs, with:

- HVCI/VBS off and on;
- Hyper-V off and on;
- Driver Verifier configured for the OAC driver (start with standard settings, then add pool,
  IRQL, I/O, deadlock, security, and miscellaneous checks);
- processor groups where practical;
- repeated install/start/scan/stop/uninstall cycles;
- target process exit, PID churn, client crash, concurrent IOCTL attempts, and malformed buffers;
- representative overlays, accessibility tools, endpoint security, debuggers, and performance
  monitors to tune signed allowlists without weakening high-confidence correlations.

Never enable Driver Verifier indiscriminately for all drivers on a machine you need to preserve.
Keep a recovery snapshot and know how to disable Verifier from recovery before beginning.

## Cleanup

After a campaign, use the installer's exact `-Remove` path to stop/delete `OACService`, remove its
verified binaries, remove the staged driver package, and delete only the manifest certificate from
LocalMachine `Root` and `TrustedPublisher`. Installation and removal both require a LocalSystem
PowerShell process inside the disposable VM; an ordinary elevated administrator is rejected before
any trust, driver, service, or file mutation. The automated VM harness supplies that boundary. From
a manually provisioned LocalSystem shell, run:

```powershell
.\Install-OACTestDriver.ps1 `
  -PackageDirectory .\package `
  -ConfirmDisposableVm `
  -Remove
```

After the verified stack has been removed, disable test-signing mode, reboot, and discard or roll
back the VM snapshot.

```powershell
bcdedit.exe /set testsigning off
shutdown.exe /r /t 0
```

If the verified removal path cannot complete, stop and inspect the VM instead of applying a broad
cleanup command. `pnputil.exe /enum-drivers` can identify the exact published name for `OAC.inf`;
remove only that entry and only the exact certificate thumbprint recorded in
`package-manifest.json`. Never use a subject wildcard.

The checked-in installer intentionally does not automate broad certificate deletion, Secure Boot
changes, VM rollback, or production-machine use.
