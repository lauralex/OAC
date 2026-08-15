[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackageDirectory,

    [string]$CertificatePath,

    [switch]$EnableTestSigning,

    [switch]$ValidateOnly,

    [switch]$ConfirmDisposableVm,

    [uint32]$SmokeTestPid = 0,

    [string]$SmokeTestOutput = '.\oac-test-scan'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$packageInput = [IO.Path]::GetFullPath($PackageDirectory)
if (-not (Test-Path -LiteralPath $packageInput -PathType Container)) {
    throw "Package directory does not exist: $packageInput"
}
$package = (Resolve-Path -LiteralPath $packageInput).Path.TrimEnd(
    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$packagePrefix = $package + [IO.Path]::DirectorySeparatorChar

function Get-ContainedPackageFile([string]$Name) {
    if ([IO.Path]::GetFileName($Name) -ne $Name) {
        throw "Package manifest contains a non-leaf file name: $Name"
    }
    $candidate = Join-Path $package $Name
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Required package file is missing: $candidate"
    }
    $resolved = (Resolve-Path -LiteralPath $candidate).Path
    if (-not $resolved.StartsWith($packagePrefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Package file escaped the package directory: $resolved"
    }
    return $resolved
}

$inf = Get-ContainedPackageFile 'OAC.inf'
$driver = Get-ContainedPackageFile 'OAC.sys'
$catalog = Get-ContainedPackageFile 'OAC.cat'

$manifestPath = Join-Path (Split-Path -Parent $package) 'package-manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Package manifest was not found: $manifestPath"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or
    $manifest.purpose -ne 'OAC disposable-VM test package; never production' -or
    -not $manifest.certificate_thumbprint -or -not $manifest.files) {
    throw 'Package manifest is missing required OAC test-package metadata.'
}
$manifestNames = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $manifest.files) {
    $name = [string]$entry.name
    if (-not $manifestNames.Add($name)) {
        throw "Package manifest contains a duplicate file: $name"
    }
    $path = Get-ContainedPackageFile $name
    $item = Get-Item -LiteralPath $path
    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($item.Length -ne [int64]$entry.bytes -or
        $actualHash -ne [string]$entry.sha256) {
        throw "Package file does not match its manifest: $name"
    }
}
foreach ($requiredName in @('OAC.inf', 'OAC.sys', 'OAC.cat', 'OAC-Client.exe')) {
    if (-not $manifestNames.Contains($requiredName)) {
        throw "Package manifest does not cover required file: $requiredName"
    }
}

if (-not $CertificatePath) {
    $CertificatePath = Join-Path (Split-Path -Parent $package) 'certificate\OAC-Local-Test.cer'
}
$certificateInput = [IO.Path]::GetFullPath($CertificatePath)
if (-not (Test-Path -LiteralPath $certificateInput -PathType Leaf)) {
    throw "Test certificate was not found: $certificateInput"
}
$certificate = (Resolve-Path -LiteralPath $certificateInput).Path
$certificateObject = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
if ($certificateObject.Thumbprint -ne [string]$manifest.certificate_thumbprint -or
    $certificateObject.Subject -ne 'CN=OAC LOCAL TEST ONLY - NOT FOR PRODUCTION' -or
    $certificateObject.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
    throw 'Test certificate does not match the package manifest or is expired.'
}

if ($ValidateOnly) {
    Write-Host "OAC test package manifest and certificate validated: $package"
    return
}

if (-not $ConfirmDisposableVm) {
    throw 'Refusing to continue. Pass -ConfirmDisposableVm on an isolated disposable Windows test VM.'
}
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell session inside the disposable VM.'
}

if ($EnableTestSigning) {
    $secureBoot = $null
    try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { }
    if ($secureBoot -eq $true) {
        throw 'Secure Boot is enabled. Disable it manually in this disposable VM firmware before enabling Windows test-signing mode.'
    }
    & bcdedit.exe /set testsigning on
    if ($LASTEXITCODE -ne 0) { throw 'BCDEdit failed to enable test-signing mode.' }
    Write-Warning 'Test-signing mode was enabled in the boot configuration. Reboot the disposable VM, then rerun this script without -EnableTestSigning.'
    return
}

function Add-TestCertificateToMachineStore([string]$StoreName) {
    $output = & certutil.exe -f -addstore $StoreName $certificate 2>&1
    $exitCode = $LASTEXITCODE
    $output | Write-Output
    if ($exitCode -ne 0) {
        throw "CertUtil could not import the OAC test certificate into LocalMachine\$StoreName (exit code $exitCode)."
    }

    $installed = Get-ChildItem -LiteralPath "Cert:\LocalMachine\$StoreName" |
        Where-Object Thumbprint -EQ $certificateObject.Thumbprint |
        Select-Object -First 1
    if (-not $installed) {
        throw "The OAC test certificate is absent from LocalMachine\$StoreName after CertUtil reported success."
    }
}

# Import-Certificate can return E_ACCESSDENIED for LocalMachine\TrustedPublisher
# from a SYSTEM startup task on Windows 11 24H2.  CertUtil uses the native
# machine-store path and provides an exit code that the harness can verify.
Add-TestCertificateToMachineStore 'Root'
Add-TestCertificateToMachineStore 'TrustedPublisher'

foreach ($path in @($driver, $catalog)) {
    $signature = Get-AuthenticodeSignature -FilePath $path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $certificateObject.Thumbprint) {
        throw "Signature validation failed after trust import: $path ($($signature.Status))"
    }
}

& pnputil.exe /add-driver $inf /install
if ($LASTEXITCODE -ne 0) { throw 'PnPUtil failed to install the OAC test package.' }

$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\OAC'
$installedStartType = (Get-ItemProperty -LiteralPath $serviceKey -Name Start).Start
if ($installedStartType -ne 3) {
    throw "OAC must remain demand-start (registry Start=3); installed value is $installedStartType"
}

& sc.exe start OAC
$serviceExit = $LASTEXITCODE
if ($serviceExit -ne 0 -and $serviceExit -ne 1056) {
    throw "The OAC service failed to start; sc.exe exit code $serviceExit"
}
& sc.exe query OAC

if ($SmokeTestPid -ne 0) {
    $client = Get-ContainedPackageFile 'OAC-Client.exe'
    & $client --pid $SmokeTestPid --mode test --output $SmokeTestOutput
    $scanExit = $LASTEXITCODE
    if ($scanExit -gt 1) { throw "OAC smoke test failed with exit code $scanExit" }
    Write-Host "Smoke-test report: $SmokeTestOutput"
}

Write-Host 'OAC demand-start test driver is installed and started. This VM must remain isolated and non-production.'
