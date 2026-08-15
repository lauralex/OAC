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
3. signs `OAC.sys`, regenerates `oac.cat`, signs the catalog, and verifies each file digest and
   signer while requiring the expected untrusted-root result for the newly self-signed certificate;
4. copies `OAC-Client.exe` and writes a SHA-256 package manifest; and
5. leaves the host trust stores unchanged and removes that exact certificate from CurrentUser `My`
   unless retaining it was explicitly requested for repeat test builds.

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

Reboot if requested. Then install and start the package:

```powershell
.\Install-OACTestDriver.ps1 `
  -PackageDirectory .\package `
  -ConfirmDisposableVm `
  -SmokeTestPid 1234
```

The installer validates that all resolved targets remain inside the selected package directory,
imports only the package certificate into LocalMachine test trust stores, verifies the SYS/catalog,
uses `pnputil` to stage the INF, starts the `OAC` service, and can perform a client smoke scan.
It then reads `HKLM\SYSTEM\CurrentControlSet\Services\OAC\Start` and refuses to load the driver
unless the value is exactly `3` (`SERVICE_DEMAND_START`). Verify it independently with:

```powershell
reg.exe query HKLM\SYSTEM\CurrentControlSet\Services\OAC /v Start
sc.exe query OAC
```

The first command must report `0x3`; never change it to boot, system, or automatic start.

For an end-to-end isolated campaign, `tools\vm\New-OACSeedIso.py` builds a Joliet seed ISO only
after verifying the complete file set and rejecting PFX/P12/key material. Run
`tools\vm\Start-OACHyperVTest.ps1` with that seed and a Windows installation ISO to create a
networkless Generation 2 VM, retain a clean pre-Verifier checkpoint, run the baseline and standard
Driver Verifier phases, copy the durable result through PowerShell Direct, and shut the guest down.
The orchestrator refuses to replace an existing VM or VHDX.

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

After a campaign, stop/delete the `OAC` service, remove the staged driver package with `pnputil`,
remove only the test certificate matching the manifest thumbprint from LocalMachine `Root` and
`TrustedPublisher`, disable test-signing mode, reboot, and discard or roll back the VM snapshot.

```powershell
sc.exe stop OAC
sc.exe delete OAC
bcdedit.exe /set testsigning off
shutdown.exe /r /t 0
```

Use `pnputil.exe /enum-drivers` to identify the exact published name for `OAC.inf`, then remove only
that entry with `pnputil.exe /delete-driver <published-name> /uninstall`. Remove the exact
certificate thumbprint recorded in `package-manifest.json`; do not use a subject wildcard.

The checked-in installer intentionally does not automate broad certificate deletion, Secure Boot
changes, VM rollback, or production-machine use.
