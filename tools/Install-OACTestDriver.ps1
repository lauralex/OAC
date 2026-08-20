[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackageDirectory,

    [string]$CertificatePath,

    [switch]$EnableTestSigning,

    [switch]$ValidateOnly,

    [switch]$ConfirmDisposableVm,

    [switch]$Remove,

    [switch]$LegacyV4LabMode,

    [uint32]$SmokeTestPid = 0,

    [string]$SmokeTestOutput = '.\oac-test-scan'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($SmokeTestPid -ne 0 -and -not $LegacyV4LabMode) {
    throw 'The legacy v4 smoke client requires -LegacyV4LabMode.'
}
if ($Remove -and
    ($EnableTestSigning -or $ValidateOnly -or $LegacyV4LabMode -or
     $SmokeTestPid -ne 0)) {
    throw '-Remove cannot be combined with signing, validation, lab-mode, or smoke-test options.'
}

$packageInput = [IO.Path]::GetFullPath($PackageDirectory)
if (-not (Test-Path -LiteralPath $packageInput -PathType Container)) {
    throw "Package directory does not exist: $packageInput"
}
$package = (Resolve-Path -LiteralPath $packageInput).Path.TrimEnd(
    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$packagePrefix = $package + [IO.Path]::DirectorySeparatorChar
$bundle = (Resolve-Path -LiteralPath (Split-Path -Parent $package)).Path.TrimEnd(
    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$bundlePrefix = $bundle + [IO.Path]::DirectorySeparatorChar

function Get-ContainedFile(
    [string]$Root,
    [string]$Prefix,
    [string]$Name
) {
    if ([IO.Path]::GetFileName($Name) -cne $Name) {
        throw "Package manifest contains a non-leaf file name: $Name"
    }
    $matches = @(Get-ChildItem -LiteralPath $Root -Force -File |
        Where-Object { $_.Name -ieq $Name })
    if ($matches.Count -eq 0) {
        throw "Required package file is missing: $(Join-Path $Root $Name)"
    }
    if ($matches.Count -ne 1) {
        throw "Package directory contains ambiguous file names for: $Name"
    }
    $item = $matches[0]
    if ($item.Name -cne $Name) {
        throw "Package file casing does not match its manifest: $Name"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Package file is a reparse point: $Name"
    }
    $resolved = $item.FullName
    if (-not $resolved.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Package file escaped its directory: $resolved"
    }
    return $item
}

$manifestPath = Join-Path $bundle 'package-manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Package manifest was not found: $manifestPath"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or
    $manifest.purpose -ne 'OAC disposable-VM test package; never production' -or
    [string]$manifest.configuration -cnotin @('Debug', 'Release') -or
    [string]$manifest.protocol_version -cne '0x00050006' -or
    [string]$manifest.legacy_protocol_version -cne '0x00040000' -or
    [string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
    -not $manifest.certificate_thumbprint -or -not $manifest.files -or
    -not $manifest.test_files) {
    throw 'Package manifest is missing required OAC test-package metadata.'
}

function Read-ManifestGroup(
    [object[]]$Entries,
    [string]$Root,
    [string]$Prefix
) {
    $paths = [Collections.Generic.Dictionary[string, string]]::new(
        [StringComparer]::Ordinal)
    foreach ($entry in @($Entries)) {
        $name = [string]$entry.name
        if ($paths.ContainsKey($name)) {
            throw "Package manifest contains a duplicate file: $name"
        }
        $item = Get-ContainedFile $Root $Prefix $name
        $path = $item.FullName
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if ($item.Length -ne [int64]$entry.bytes -or
            $actualHash -ne [string]$entry.sha256) {
            throw "Package file does not match its manifest: $name"
        }
        $paths[$name] = $path
    }
    return $paths
}

$packageFiles = Read-ManifestGroup @($manifest.files) $package $packagePrefix
$testFiles = Read-ManifestGroup @($manifest.test_files) $bundle $bundlePrefix
$requiredPackageFiles = @(
    'OAC.inf', 'OAC.sys', 'OAC.cat', 'OAC-Client.exe',
    'OAC-Service.exe', 'OAC-Launcher.exe',
    'OAC.policy', 'OAC.policy.p7s',
    'OAC-Liveness-Target.exe.oac-manifest',
    'OAC-Liveness-Target.exe.oac-manifest.p7s')
$requiredTestFiles = @(
    'OAC-Protocol-Test.exe', 'OAC-Protocol-Unit.exe',
    'OAC-Game-Manifest-Expired.bin',
    'OAC-Game-Manifest-Expired.bin.p7s',
    'OAC-Game-Manifest-Wrong-Build.bin',
    'OAC-Game-Manifest-Wrong-Build.bin.p7s',
    'OAC-Game-Manifest-Rollback.bin',
    'OAC-Game-Manifest-Rollback.bin.p7s',
    'OAC-Policy-Wrong-Signature.bin',
    'OAC-Policy-Wrong-Signature.bin.p7s',
    'OAC-Policy-Wrong-Scope.bin',
    'OAC-Policy-Wrong-Scope.bin.p7s',
    'OAC-Policy-Expired.bin',
    'OAC-Policy-Expired.bin.p7s',
    'OAC-Policy-Rollback.bin',
    'OAC-Policy-Rollback.bin.p7s',
    'OAC-Policy-Authorized-Rollback.bin',
    'OAC-Policy-Authorized-Rollback.bin.p7s',
    'OAC-Policy-Emergency-Revoke.bin',
    'OAC-Policy-Emergency-Revoke.bin.p7s')
foreach ($requiredName in $requiredPackageFiles) {
    if (-not $packageFiles.ContainsKey($requiredName)) {
        throw "Package manifest does not cover required file: $requiredName"
    }
}
foreach ($requiredName in $requiredTestFiles) {
    if (-not $testFiles.ContainsKey($requiredName)) {
        throw "Package manifest does not cover required test file: $requiredName"
    }
}

$inf = $packageFiles['OAC.inf']
$driver = $packageFiles['OAC.sys']
$catalog = $packageFiles['OAC.cat']
$client = $packageFiles['OAC-Client.exe']
$serviceSource = $packageFiles['OAC-Service.exe']
$launcherSource = $packageFiles['OAC-Launcher.exe']
$policySource = $packageFiles['OAC.policy']
$policySignatureSource = $packageFiles['OAC.policy.p7s']
$gameManifestSource = $packageFiles['OAC-Liveness-Target.exe.oac-manifest']
$gameManifestSignatureSource =
    $packageFiles['OAC-Liveness-Target.exe.oac-manifest.p7s']
$protocolTest = $testFiles['OAC-Protocol-Test.exe']
$protocolUnit = $testFiles['OAC-Protocol-Unit.exe']

if (-not $CertificatePath) {
    $CertificatePath = Join-Path $bundle 'certificate\OAC-Local-Test.cer'
}
$certificateInput = [IO.Path]::GetFullPath($CertificatePath)
if (-not (Test-Path -LiteralPath $certificateInput -PathType Leaf)) {
    throw "Test certificate was not found: $certificateInput"
}
$certificate = (Resolve-Path -LiteralPath $certificateInput).Path
$certificateObject = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $certificate)
if ($certificateObject.Thumbprint -ne [string]$manifest.certificate_thumbprint -or
    $certificateObject.Subject -ne 'CN=OAC LOCAL TEST ONLY - NOT FOR PRODUCTION' -or
    $certificateObject.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
    throw 'Test certificate does not match the package manifest or is expired.'
}
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
$manifestSignerSha256 = $sha256.ComputeHash($certificateObject.RawData)
$policySignerSha256 = [byte[]]$manifestSignerSha256.Clone()
} finally {
    $sha256.Dispose()
}

function Import-PkcsAssembly {
    if ($null -ne ('System.Security.Cryptography.Pkcs.SignedCms' -as [type])) {
        return
    }
    try {
        Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop
    } catch {
        Add-Type -AssemblyName System.Security -ErrorAction Stop
    }
    if ($null -eq ('System.Security.Cryptography.Pkcs.SignedCms' -as [type])) {
        throw 'The platform PKCS/CMS implementation is unavailable.'
    }
}

function Assert-DetachedRecordSignature(
    [string]$RecordPath,
    [string]$SignaturePath,
    [int]$ExpectedSize
) {
    Import-PkcsAssembly
    $recordBytes = [IO.File]::ReadAllBytes($RecordPath)
    if ($recordBytes.Length -ne $ExpectedSize) {
        throw "Signed record has an invalid size: $RecordPath"
    }
    $signatureBytes = [IO.File]::ReadAllBytes($SignaturePath)
    if ($signatureBytes.Length -eq 0 -or $signatureBytes.Length -gt 65536) {
        throw "Detached signature has an invalid size: $SignaturePath"
    }
    $signed = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new($recordBytes), $true)
    $signed.Decode($signatureBytes)
    $signed.CheckSignature($true)
    if ($signed.SignerInfos.Count -ne 1 -or
        $signed.SignerInfos[0].DigestAlgorithm.Value -ne
            '2.16.840.1.101.3.4.2.1' -or
        $signed.SignerInfos[0].CounterSignerInfos.Count -ne 0 -or
        $signed.SignerInfos[0].UnsignedAttributes.Count -ne 0 -or
        [Convert]::ToBase64String($signed.SignerInfos[0].Certificate.RawData) -cne
            [Convert]::ToBase64String($certificateObject.RawData)) {
        throw "Detached record signer validation failed: $RecordPath"
    }
}

Assert-DetachedRecordSignature `
    $gameManifestSource $gameManifestSignatureSource 512
foreach ($fixture in @('Expired', 'Wrong-Build', 'Rollback')) {
    $fixtureName = "OAC-Game-Manifest-$fixture.bin"
    Assert-DetachedRecordSignature `
        $testFiles[$fixtureName] $testFiles["$fixtureName.p7s"] 512
}

function Assert-SignedPolicyShape(
    [string]$Path,
    [switch]$AllowExpired
) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $magic = [Text.Encoding]::ASCII.GetString($bytes, 0, 8)
    $flags = [BitConverter]::ToUInt32($bytes, 16)
    $issued = [BitConverter]::ToUInt64($bytes, 104)
    $expires = [BitConverter]::ToUInt64($bytes, 112)
    if ($bytes.Length -ne 1024 -or $magic -cne 'OACPOLCY' -or
        [BitConverter]::ToUInt32($bytes, 8) -ne 2 -or
        [BitConverter]::ToUInt32($bytes, 12) -ne 1024 -or
        ($flags -band 0xFFFFFFFC) -ne 0 -or
        [BitConverter]::ToUInt32($bytes, 20) -notin @(1, 2, 3) -or
        [BitConverter]::ToUInt64($bytes, 88) -eq 0 -or
        [BitConverter]::ToUInt64($bytes, 96) -eq 0 -or
        $issued -eq 0 -or $expires -le $issued -or
        ($expires - $issued) -gt (31 * 24 * 60 * 60) -or
        [BitConverter]::ToUInt32($bytes, 120) -ne 0x00050006 -or
        [BitConverter]::ToUInt32($bytes, 124) -ne 0x00010006 -or
        [BitConverter]::ToUInt32($bytes, 128) -ne 0x00010006 -or
        [BitConverter]::ToUInt32($bytes, 132) -ne 1 -or
        [BitConverter]::ToUInt32($bytes, 136) -ne 14 -or
        [BitConverter]::ToUInt32($bytes, 1000) -ne 6000 -or
        [BitConverter]::ToUInt32($bytes, 1004) -ne 2000 -or
        [BitConverter]::ToUInt32($bytes, 1008) -ne 1000 -or
        [BitConverter]::ToUInt32($bytes, 1012) -ne 5000 -or
        @($bytes[1016..1023] | Where-Object { $_ -ne 0 }).Count -ne 0) {
        throw "Signed-policy canonical fields are invalid: $Path"
    }
    foreach ($range in @(@(24, 39), @(40, 55), @(56, 71), @(72, 87))) {
        if (@($bytes[$range[0]..$range[1]] | Where-Object { $_ -ne 0 }).Count -eq 0) {
            throw "Signed-policy identity is empty: $Path"
        }
    }
    if ([Convert]::ToBase64String($bytes[144..175]) -cne
        [Convert]::ToBase64String($policySignerSha256)) {
        throw "Signed-policy key identity is invalid: $Path"
    }
    $emergency = ($flags -band 1) -ne 0
    $rollback = ($flags -band 2) -ne 0
    $emergencyReason = [BitConverter]::ToUInt32($bytes, 140)
    $rollbackVersion = [BitConverter]::ToUInt64($bytes, 176)
    $rollbackDigestPresent =
        @($bytes[184..215] | Where-Object { $_ -ne 0 }).Count -ne 0
    if (($emergency -and ($rollback -or $emergencyReason -notin @(1, 2, 3))) -or
        (-not $emergency -and $emergencyReason -ne 0) -or
        ($rollback -and ($rollbackVersion -eq 0 -or -not $rollbackDigestPresent)) -or
        (-not $rollback -and ($rollbackVersion -ne 0 -or $rollbackDigestPresent))) {
        throw "Signed-policy operation fields are invalid: $Path"
    }
    if (-not $AllowExpired -and
        $expires + 300 -lt [uint64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) {
        throw "Signed policy is expired: $Path"
    }
    $expectedRuleIds = @(
        0x00010001, 0x00010002, 0x00010003, 0x00010004,
        0x00010005, 0x00010006, 0x00020001, 0x00020002,
        0x00030001, 0x00030002, 0x00030003, 0x00040001,
        0x00040002, 0x00080001)
    for ($index = 0; $index -lt $expectedRuleIds.Count; $index++) {
        $offset = 216 + ($index * 56)
        if ([BitConverter]::ToUInt32($bytes, $offset) -ne
            [uint32]$expectedRuleIds[$index] -or
            [BitConverter]::ToUInt32($bytes, $offset + 36) -ne 0 -or
            [BitConverter]::ToUInt32($bytes, $offset + 52) -ne 0) {
            throw "Signed-policy rule layout is invalid: $Path"
        }
    }
}
Assert-DetachedRecordSignature $policySource $policySignatureSource 1024
Assert-SignedPolicyShape $policySource
foreach ($fixture in @(
        'Wrong-Scope', 'Expired', 'Rollback', 'Authorized-Rollback',
        'Emergency-Revoke')) {
    $fixtureName = "OAC-Policy-$fixture.bin"
    Assert-DetachedRecordSignature `
        $testFiles[$fixtureName] $testFiles["$fixtureName.p7s"] 1024
    Assert-SignedPolicyShape `
        $testFiles[$fixtureName] -AllowExpired:($fixture -eq 'Expired')
}
Assert-SignedPolicyShape $testFiles['OAC-Policy-Wrong-Signature.bin']
$wrongSignatureRejected = $false
try {
    Assert-DetachedRecordSignature `
        $testFiles['OAC-Policy-Wrong-Signature.bin'] `
        $testFiles['OAC-Policy-Wrong-Signature.bin.p7s'] 1024
} catch {
    $wrongSignatureRejected = $true
}
if (-not $wrongSignatureRejected) {
    throw 'The wrong-signature policy fixture unexpectedly verified.'
}

$signedFiles = @(
    $driver, $catalog, $client, $serviceSource, $launcherSource,
    $protocolTest, $protocolUnit)
foreach ($path in $signedFiles) {
    $signature = Get-AuthenticodeSignature -FilePath $path
    if (-not $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $certificateObject.Thumbprint -or
        $signature.Status -in @(
            [Management.Automation.SignatureStatus]::HashMismatch,
            [Management.Automation.SignatureStatus]::NotSigned)) {
        throw "Signer validation failed for package file: $path ($($signature.Status))"
    }
}

if ($ValidateOnly) {
    Write-Host "OAC test package, hashes, certificate, and signers validated: $package"
    return
}

if (-not $ConfirmDisposableVm) {
    throw 'Refusing to continue. Pass -ConfirmDisposableVm on an isolated disposable Windows test VM.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell session inside the disposable VM.'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Run this installer from 64-bit PowerShell inside the disposable VM.'
}
if (-not $EnableTestSigning -and
    -not $identity.User.IsWellKnown(
        [Security.Principal.WellKnownSidType]::LocalSystemSid)) {
    throw 'Driver installation and removal must run as LocalSystem in the disposable VM.'
}

if ($null -eq ('Oac.ServicePolicy' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Oac
{
    public static class ServicePolicy
    {
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint GroupSecurityInformation = 0x00000002;
        private const uint DaclSecurityInformation = 0x00000004;
        private const uint UnprotectedDaclSecurityInformation = 0x20000000;
        private const int ServiceObject = 2;
        private const uint ScManagerConnect = 0x00000001;
        private const uint ServiceQueryConfig = 0x00000001;
        private const uint ServiceChangeConfig = 0x00000002;
        private const uint ServiceStart = 0x00000010;
        private const uint FailureActionsLevel = 2;
        private const uint FailureActionsFlagLevel = 4;
        private const int NoAction = 0;
        private const int RestartAction = 1;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetNamedSecurityInfoW(
            string objectName,
            int objectType,
            uint securityInformation,
            out IntPtr owner,
            out IntPtr group,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint SetNamedSecurityInfoW(
            string objectName,
            int objectType,
            uint securityInformation,
            IntPtr owner,
            IntPtr group,
            IntPtr dacl,
            IntPtr sacl);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr OpenSCManagerW(
            string machineName,
            string databaseName,
            uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr OpenServiceW(
            IntPtr serviceManager,
            string serviceName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceConfig2W(
            IntPtr service,
            uint informationLevel,
            IntPtr buffer,
            uint bufferSize,
            out uint bytesNeeded);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ChangeFailureActions(
            IntPtr service,
            uint informationLevel,
            ref ServiceFailureActions actions);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ChangeFailureActionsFlag(
            IntPtr service,
            uint informationLevel,
            ref ServiceFailureActionsFlag flag);

        [DllImport("advapi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string text,
            uint revision,
            out IntPtr securityDescriptor,
            out uint size);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorOwner(
            IntPtr securityDescriptor,
            out IntPtr owner,
            [MarshalAs(UnmanagedType.Bool)] out bool ownerDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorGroup(
            IntPtr securityDescriptor,
            out IntPtr group,
            [MarshalAs(UnmanagedType.Bool)] out bool groupDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorDacl(
            IntPtr securityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool daclPresent,
            out IntPtr dacl,
            [MarshalAs(UnmanagedType.Bool)] out bool daclDefaulted);

        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceFailureActions
        {
            public uint ResetPeriod;
            public IntPtr RebootMessage;
            public IntPtr Command;
            public uint ActionCount;
            public IntPtr Actions;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceAction
        {
            public int Type;
            public uint Delay;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceFailureActionsFlag
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool Enabled;
        }

        public static byte[] ReadSecurity(string serviceName)
        {
            IntPtr owner;
            IntPtr group;
            IntPtr dacl;
            IntPtr sacl;
            IntPtr descriptor;
            uint information = OwnerSecurityInformation |
                GroupSecurityInformation | DaclSecurityInformation;
            uint error = GetNamedSecurityInfoW(
                serviceName,
                ServiceObject,
                information,
                out owner,
                out group,
                out dacl,
                out sacl,
                out descriptor);
            if (error != 0)
            {
                throw new Win32Exception((int)error);
            }
            if (descriptor == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    "The service security descriptor was not returned.");
            }

            try
            {
                uint size = GetSecurityDescriptorLength(descriptor);
                if (size == 0 || size > 65536)
                {
                    throw new InvalidOperationException(
                        "The service security descriptor has an invalid size.");
                }
                byte[] bytes = new byte[(int)size];
                Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                return bytes;
            }
            finally
            {
                LocalFree(descriptor);
            }
        }

        public static void WriteSecurity(string serviceName, string sddl)
        {
            IntPtr descriptor;
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, 1, out descriptor, out size))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                IntPtr owner;
                IntPtr group;
                IntPtr dacl;
                bool ignored;
                bool daclPresent;
                if (!GetSecurityDescriptorOwner(descriptor, out owner, out ignored) ||
                    !GetSecurityDescriptorGroup(descriptor, out group, out ignored) ||
                    !GetSecurityDescriptorDacl(
                        descriptor, out daclPresent, out dacl, out ignored))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if (owner == IntPtr.Zero || group == IntPtr.Zero ||
                    !daclPresent || dacl == IntPtr.Zero)
                {
                    throw new InvalidOperationException(
                        "The requested service security descriptor is incomplete.");
                }

                uint information = OwnerSecurityInformation |
                    GroupSecurityInformation | DaclSecurityInformation |
                    UnprotectedDaclSecurityInformation;
                uint error = SetNamedSecurityInfoW(
                    serviceName,
                    ServiceObject,
                    information,
                    owner,
                    group,
                    dacl,
                    IntPtr.Zero);
                if (error != 0)
                {
                    throw new Win32Exception((int)error);
                }
            }
            finally
            {
                LocalFree(descriptor);
            }
        }

        public static bool HasRecoveryPolicy(
            string serviceName,
            uint expectedResetPeriod,
            uint expectedRestartDelay)
        {
            IntPtr manager = OpenSCManagerW(
                null, null, ScManagerConnect);
            if (manager == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                IntPtr service = OpenServiceW(
                    manager, serviceName, ServiceQueryConfig);
                if (service == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                try
                {
                    return FailureActionsMatch(
                            service,
                            expectedResetPeriod,
                            expectedRestartDelay) &&
                        FailureActionsEnabled(service);
                }
                finally
                {
                    CloseServiceHandle(service);
                }
            }
            finally
            {
                CloseServiceHandle(manager);
            }
        }

        public static void WriteRecoveryPolicy(
            string serviceName,
            uint resetPeriod,
            uint restartDelay)
        {
            IntPtr manager = OpenSCManagerW(
                null, null, ScManagerConnect);
            if (manager == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                IntPtr service = OpenServiceW(
                    manager,
                    serviceName,
                    ServiceChangeConfig | ServiceStart);
                if (service == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                try
                {
                    int actionSize = Marshal.SizeOf(typeof(ServiceAction));
                    IntPtr actionBuffer = Marshal.AllocHGlobal(actionSize * 2);
                    try
                    {
                        ServiceAction restart = new ServiceAction
                        {
                            Type = RestartAction,
                            Delay = restartDelay
                        };
                        ServiceAction stop = new ServiceAction
                        {
                            Type = NoAction,
                            Delay = 0
                        };
                        Marshal.StructureToPtr(restart, actionBuffer, false);
                        Marshal.StructureToPtr(
                            stop, IntPtr.Add(actionBuffer, actionSize), false);

                        ServiceFailureActions actions =
                            new ServiceFailureActions
                            {
                                ResetPeriod = resetPeriod,
                                RebootMessage = IntPtr.Zero,
                                Command = IntPtr.Zero,
                                ActionCount = 2,
                                Actions = actionBuffer
                            };
                        if (!ChangeFailureActions(
                                service, FailureActionsLevel, ref actions))
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(actionBuffer);
                    }

                    ServiceFailureActionsFlag flag =
                        new ServiceFailureActionsFlag { Enabled = true };
                    if (!ChangeFailureActionsFlag(
                            service, FailureActionsFlagLevel, ref flag))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }
                finally
                {
                    CloseServiceHandle(service);
                }
            }
            finally
            {
                CloseServiceHandle(manager);
            }
        }

        private static bool FailureActionsMatch(
            IntPtr service,
            uint expectedResetPeriod,
            uint expectedRestartDelay)
        {
            IntPtr buffer = ReadConfig(service, FailureActionsLevel);
            try
            {
                ServiceFailureActions actions =
                    (ServiceFailureActions)Marshal.PtrToStructure(
                        buffer, typeof(ServiceFailureActions));
                if (actions.ResetPeriod != expectedResetPeriod ||
                    !IsNullOrEmpty(actions.RebootMessage) ||
                    !IsNullOrEmpty(actions.Command) ||
                    actions.ActionCount != 2 ||
                    actions.Actions == IntPtr.Zero)
                {
                    return false;
                }
                ServiceAction action =
                    (ServiceAction)Marshal.PtrToStructure(
                        actions.Actions, typeof(ServiceAction));
                int actionSize = Marshal.SizeOf(typeof(ServiceAction));
                ServiceAction terminal =
                    (ServiceAction)Marshal.PtrToStructure(
                        IntPtr.Add(actions.Actions, actionSize),
                        typeof(ServiceAction));
                return action.Type == RestartAction &&
                    action.Delay == expectedRestartDelay &&
                    terminal.Type == NoAction && terminal.Delay == 0;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static bool FailureActionsEnabled(IntPtr service)
        {
            IntPtr buffer = ReadConfig(service, FailureActionsFlagLevel);
            try
            {
                ServiceFailureActionsFlag flag =
                    (ServiceFailureActionsFlag)Marshal.PtrToStructure(
                        buffer, typeof(ServiceFailureActionsFlag));
                return flag.Enabled;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static bool IsNullOrEmpty(IntPtr text)
        {
            return text == IntPtr.Zero ||
                String.IsNullOrEmpty(Marshal.PtrToStringUni(text));
        }

        private static IntPtr ReadConfig(IntPtr service, uint level)
        {
            uint bytesNeeded;
            bool unexpectedSuccess = QueryServiceConfig2W(
                service, level, IntPtr.Zero, 0, out bytesNeeded);
            int error = Marshal.GetLastWin32Error();
            if (unexpectedSuccess || error != 122 ||
                bytesNeeded == 0 || bytesNeeded > 65536)
            {
                throw new Win32Exception(error);
            }

            uint capacity = bytesNeeded;
            IntPtr buffer = Marshal.AllocHGlobal((int)capacity);
            try
            {
                if (!QueryServiceConfig2W(
                        service, level, buffer, capacity, out bytesNeeded) ||
                    bytesNeeded > capacity)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                IntPtr result = buffer;
                buffer = IntPtr.Zero;
                return result;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
    }
}
'@ -Language CSharp
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

function Stop-ServiceBounded([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    try {
        if ($null -eq $service -or $service.Status -eq 'Stopped') { return }
        Stop-Service -Name $Name -Force
        $service.WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(20))
        $service.Refresh()
        if ($service.Status -ne 'Stopped') {
            throw "Service $Name did not stop within the bounded wait."
        }
    } finally {
        if ($null -ne $service) { $service.Dispose() }
    }
}

function Start-ServiceBounded([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction Stop
    try {
        if ($service.Status -ne 'Running') {
            Start-Service -Name $Name
            $service.WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(20))
            $service.Refresh()
        }
        if ($service.Status -ne 'Running') {
            throw "Service $Name did not start within the bounded wait."
        }
    } finally {
        $service.Dispose()
    }
}

function Invoke-ScChecked([string[]]$Arguments) {
    & sc.exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "SC command failed with exit code $LASTEXITCODE`: $($Arguments -join ' ')"
    }
}

function Set-ProtectedInstallAcl([string]$Path) {
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($system)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $system,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administrators,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inheritance,
        $propagation,
        $allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $users,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inheritance,
        $propagation,
        $allow))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ProtectedInstallAcl([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]))
    $readAndExecute = [int](
        [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
        [Security.AccessControl.FileSystemRights]::Synchronize)
    $expectedRights = @{
        'S-1-5-18' = [int][Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-544' = $readAndExecute
        'S-1-5-32-545' = $readAndExecute
    }
    $expectedInheritance = [int](
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit)
    if (-not $acl.AreAccessRulesProtected -or $owner -ne 'S-1-5-18' -or
        $rules.Count -ne $expectedRights.Count) {
        throw "The OAC-Test install directory ACL is not protected as required: $Path"
    }
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (-not $expectedRights.ContainsKey($sid) -or
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            [int]$rule.FileSystemRights -ne $expectedRights[$sid] -or
            [int]$rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne
                [Security.AccessControl.PropagationFlags]::None) {
            throw "The OAC-Test install directory contains an unexpected ACL entry: $sid"
        }
    }
}

function Set-ProtectedFileAcl([string]$Path) {
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($system)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $system,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow))
    foreach ($sid in @($administrators, $users)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ProtectedFileAcl([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]))
    $readAndExecute = [int](
        [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
        [Security.AccessControl.FileSystemRights]::Synchronize)
    $expectedRights = @{
        'S-1-5-18' = [int][Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-544' = $readAndExecute
        'S-1-5-32-545' = $readAndExecute
    }
    if (-not $acl.AreAccessRulesProtected -or $owner -ne 'S-1-5-18' -or
        $rules.Count -ne $expectedRights.Count) {
        throw "The OAC-Test binary ACL is not protected as required: $Path"
    }
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (-not $expectedRights.ContainsKey($sid) -or
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            [int]$rule.FileSystemRights -ne $expectedRights[$sid] -or
            $rule.InheritanceFlags -ne
                [Security.AccessControl.InheritanceFlags]::None -or
            $rule.PropagationFlags -ne
                [Security.AccessControl.PropagationFlags]::None) {
            throw "The OAC-Test binary contains an unexpected ACL entry: $Path"
        }
    }
}

function New-ProtectedStateAcl {
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators =
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $service = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-80-1726785755-3364470821-2652420548-2779146334-590817200')
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = [Security.AccessControl.RegistrySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($system)
    $acl.SetGroup($system)
    foreach ($entry in @(
        @($system, [Security.AccessControl.RegistryRights]::FullControl),
        @($service, [Security.AccessControl.RegistryRights]::FullControl),
        @($administrators, [Security.AccessControl.RegistryRights]::ReadKey))) {
        $acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new(
            $entry[0], $entry[1], $inheritance, $propagation, $allow))
    }
    return $acl
}

function Assert-ProtectedStateAcl(
    [string]$Path,
    [switch]$Inherited
) {
    $key = Get-Item -LiteralPath $Path
    try {
        $sections =
            [Security.AccessControl.AccessControlSections]::Access -bor
            [Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Group
        $acl = $key.GetAccessControl($sections)
    } finally {
        $key.Close()
    }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $group = $acl.GetGroup([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]))
    $expectedRights = @{
        'S-1-5-18' = [int][Security.AccessControl.RegistryRights]::FullControl
        'S-1-5-80-1726785755-3364470821-2652420548-2779146334-590817200' =
            [int][Security.AccessControl.RegistryRights]::FullControl
        'S-1-5-32-544' = [int][Security.AccessControl.RegistryRights]::ReadKey
    }
    $expectedProtection = -not $Inherited
    if ($owner -ne 'S-1-5-18' -or $group -ne 'S-1-5-18' -or
        $acl.AreAccessRulesProtected -ne $expectedProtection -or
        $rules.Count -ne $expectedRights.Count) {
        throw "The protected OAC registry ACL is not exact: $Path"
    }
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (-not $expectedRights.ContainsKey($sid) -or
            [int]$rule.RegistryRights -ne $expectedRights[$sid] -or
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $rule.InheritanceFlags -ne
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -or
            $rule.PropagationFlags -ne
                [Security.AccessControl.PropagationFlags]::None -or
            $rule.IsInherited -ne [bool]$Inherited) {
            throw "The protected OAC registry ACL has an unexpected entry: $Path"
        }
    }
}

function Assert-ProtectedStateRoot(
    [string]$Path,
    [string]$KeyNamePattern,
    [int]$RecordSize,
    [string]$Description
) {
    $root = Get-Item -LiteralPath $Path
    if (@($root.GetValueNames()).Count -ne 0) {
        throw "The $Description state root contains unexpected values."
    }
    foreach ($keyName in @($root.GetSubKeyNames())) {
        if ($keyName -cnotmatch $KeyNamePattern) {
            throw "The $Description state has an invalid key: $keyName"
        }
        $keyPath = Join-Path $Path $keyName
        $key = Get-Item -LiteralPath $keyPath
        $valueNames = @($key.GetValueNames())
        if (@($key.GetSubKeyNames()).Count -ne 0 -or
            $valueNames.Count -ne 1 -or $valueNames[0] -cne 'HighWater') {
            throw "The $Description state has unexpected content: $keyPath"
        }
        $value = (Get-ItemProperty -LiteralPath $keyPath -Name HighWater).HighWater
        if ($value -isnot [byte[]] -or $value.Length -ne $RecordSize) {
            throw "The $Description high-water record is malformed: $keyPath"
        }
        Assert-ProtectedStateAcl $keyPath -Inherited
    }
}

function Assert-TrustStateRegistry(
    [byte[]]$ExpectedManifestSignerSha256,
    [byte[]]$ExpectedPolicySignerSha256,
    [switch]$AllowMissing
) {
    foreach ($signer in @(
            $ExpectedManifestSignerSha256,
            $ExpectedPolicySignerSha256)) {
        if ($signer.Length -ne 32 -or
            @($signer | Where-Object { $_ -ne 0 }).Count -eq 0) {
            throw 'A protected signer identity is invalid.'
        }
    }
    $rootPath = 'HKLM:\SOFTWARE\OAC'
    $manifestStatePath = Join-Path $rootPath 'ManifestState'
    $policyStatePath = Join-Path $rootPath 'PolicyState'
    if (-not (Test-Path -LiteralPath $rootPath)) {
        if ($AllowMissing) { return }
        throw 'The protected OAC registry root is missing.'
    }
    $root = Get-Item -LiteralPath $rootPath
    $rootValues = @($root.GetValueNames())
    $manifestStateExists = Test-Path -LiteralPath $manifestStatePath
    $policyStateExists = Test-Path -LiteralPath $policyStatePath
    if ($rootValues.Count -eq 0 -and $AllowMissing -and
        -not $manifestStateExists -and -not $policyStateExists) {
        return
    }
    $expectedSigners = @{
        ManifestSignerSha256 = $ExpectedManifestSignerSha256
        PolicySignerSha256 = $ExpectedPolicySignerSha256
    }
    $expectedValueNames = @(
        'ManifestSignerSha256', 'PolicySignerSha256',
        'BackendMode', 'BackendScenario')
    if ($rootValues.Count -ne $expectedValueNames.Count -or
        @($rootValues | Where-Object {
                $expectedValueNames -cnotcontains $_
            }).Count -ne 0) {
        throw 'The protected OAC registry root contains unexpected values.'
    }
    foreach ($valueName in $expectedSigners.Keys) {
        if ($root.GetValueKind($valueName) -ne
                [Microsoft.Win32.RegistryValueKind]::Binary) {
            throw "The protected signer has an invalid registry type: $valueName"
        }
        $observedSigner = [byte[]]$root.GetValue($valueName)
        $expectedSigner = [byte[]]$expectedSigners[$valueName]
        if ($observedSigner.Length -ne $expectedSigner.Length -or
            [Convert]::ToBase64String($observedSigner) -cne
                [Convert]::ToBase64String($expectedSigner)) {
            throw "The protected OAC registry root has an unexpected signer: $valueName"
        }
    }
    foreach ($backendValue in @{
            BackendMode = [uint32]1
            BackendScenario = [uint32]0
        }.GetEnumerator()) {
        if ($root.GetValueKind($backendValue.Key) -ne
                [Microsoft.Win32.RegistryValueKind]::DWord -or
            [uint32]($root.GetValue($backendValue.Key)) -ne
                [uint32]$backendValue.Value) {
            throw "The protected backend setting is invalid: $($backendValue.Key)"
        }
    }
    $rootChildren = @($root.GetSubKeyNames())
    if ($rootChildren.Count -ne 2 -or
        $rootChildren -cnotcontains 'ManifestState' -or
        $rootChildren -cnotcontains 'PolicyState') {
        throw 'The protected OAC registry root contains unexpected keys.'
    }
    if (-not $manifestStateExists -or -not $policyStateExists) {
        throw 'A protected OAC state key is missing.'
    }
    Assert-ProtectedStateAcl $rootPath
    Assert-ProtectedStateAcl $manifestStatePath
    Assert-ProtectedStateAcl $policyStatePath
    Assert-ProtectedStateRoot `
        $manifestStatePath '^[0-9A-F]{32}$' 96 'game-manifest'
    Assert-ProtectedStateRoot `
        $policyStatePath '^[0-9A-F]{32}-[0-9A-F]{32}$' 160 'signed-policy'
}

function Initialize-TrustStateRegistry(
    [byte[]]$ExpectedManifestSignerSha256,
    [byte[]]$ExpectedPolicySignerSha256
) {
    $rootPath = 'HKLM:\SOFTWARE\OAC'
    $statePaths = @(
        (Join-Path $rootPath 'ManifestState'),
        (Join-Path $rootPath 'PolicyState'))
    if (Test-Path -LiteralPath $rootPath) {
        Assert-TrustStateRegistry `
            $ExpectedManifestSignerSha256 $ExpectedPolicySignerSha256 `
            -AllowMissing
    } else {
        New-Item -Path $rootPath | Out-Null
    }
    foreach ($statePath in $statePaths) {
        if (-not (Test-Path -LiteralPath $statePath)) {
            New-Item -Path $statePath | Out-Null
        }
    }
    New-ItemProperty -LiteralPath $rootPath -Name ManifestSignerSha256 `
        -PropertyType Binary -Value $ExpectedManifestSignerSha256 -Force | Out-Null
    New-ItemProperty -LiteralPath $rootPath -Name PolicySignerSha256 `
        -PropertyType Binary -Value $ExpectedPolicySignerSha256 -Force | Out-Null
    New-ItemProperty -LiteralPath $rootPath -Name BackendMode `
        -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -LiteralPath $rootPath -Name BackendScenario `
        -PropertyType DWord -Value 0 -Force | Out-Null
    $acl = New-ProtectedStateAcl
    Set-Acl -LiteralPath $rootPath -AclObject $acl
    foreach ($statePath in $statePaths) {
        $acl = New-ProtectedStateAcl
        Set-Acl -LiteralPath $statePath -AclObject $acl
    }
    Assert-TrustStateRegistry `
        $ExpectedManifestSignerSha256 $ExpectedPolicySignerSha256
}

function Remove-TrustStateRegistry(
    [byte[]]$ExpectedManifestSignerSha256,
    [byte[]]$ExpectedPolicySignerSha256
) {
    Assert-TrustStateRegistry `
        $ExpectedManifestSignerSha256 $ExpectedPolicySignerSha256
    $rootPath = 'HKLM:\SOFTWARE\OAC'
    foreach ($stateName in @('ManifestState', 'PolicyState')) {
        $statePath = Join-Path $rootPath $stateName
        $state = Get-Item -LiteralPath $statePath
        foreach ($keyName in @($state.GetSubKeyNames())) {
            Remove-Item -LiteralPath (Join-Path $statePath $keyName) -Confirm:$false
        }
        Remove-Item -LiteralPath $statePath -Confirm:$false
    }
    Remove-Item -LiteralPath $rootPath -Confirm:$false
    if (Test-Path -LiteralPath $rootPath) {
        throw 'The protected OAC trust state was not removed.'
    }
}

function Assert-ServiceConfiguration(
    [string]$ServicePath,
    [string]$ExpectedImagePath,
    [switch]$AllowDisabled
) {
    $configuration = Get-ItemProperty -LiteralPath $ServicePath
    $dependencies = @($configuration.DependOnService)
    $privileges = @($configuration.RequiredPrivileges)
    $expectedPrivileges = @(
        'SeAssignPrimaryTokenPrivilege',
        'SeChangeNotifyPrivilege',
        'SeImpersonatePrivilege',
        'SeIncreaseQuotaPrivilege')
    $start = [int]$configuration.Start
    if ([int]$configuration.Type -ne 0x10 -or
        ($start -ne 3 -and (-not $AllowDisabled -or $start -ne 4)) -or
        [string]$configuration.ObjectName -ne 'LocalSystem' -or
        [string]$configuration.ImagePath -cne $ExpectedImagePath -or
        $dependencies.Count -ne 1 -or $dependencies[0] -ne 'OAC' -or
        $privileges.Count -ne $expectedPrivileges.Count -or
        @($expectedPrivileges | Where-Object {
            $privileges -cnotcontains $_
        }).Count -ne 0 -or
        [int]$configuration.ServiceSidType -ne 3) {
        throw 'OACService does not match the required restricted configuration.'
    }
}

function Get-UnsignedAccessMask([int]$AccessMask) {
    return [BitConverter]::ToUInt32([BitConverter]::GetBytes($AccessMask), 0)
}

function Get-ServiceAceMap(
    [Security.AccessControl.RawSecurityDescriptor]$Descriptor
) {
    $policyFlags =
        [Security.AccessControl.ControlFlags]::OwnerDefaulted -bor
        [Security.AccessControl.ControlFlags]::GroupDefaulted -bor
        [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent -bor
        [Security.AccessControl.ControlFlags]::DiscretionaryAclDefaulted -bor
        [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInheritRequired -bor
        [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited -bor
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    if ($null -eq $Descriptor.DiscretionaryAcl -or
        ($Descriptor.ControlFlags -band $policyFlags) -ne
            [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) {
        return $null
    }

    $entries = [Collections.Generic.Dictionary[string, uint32]]::new(
        [StringComparer]::Ordinal)
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or
            $ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or
            $ace.AceFlags -ne [Security.AccessControl.AceFlags]::None -or
            $ace.IsCallback -or $ace.OpaqueLength -ne 0 -or
            $null -eq $ace.SecurityIdentifier) {
            return $null
        }
        $sid = $ace.SecurityIdentifier.Value
        if ($entries.ContainsKey($sid)) { return $null }
        $entries.Add($sid, (Get-UnsignedAccessMask $ace.AccessMask))
    }
    return $entries
}

function Test-ServiceDescriptor(
    [Security.AccessControl.RawSecurityDescriptor]$Actual,
    [Security.AccessControl.RawSecurityDescriptor]$Expected
) {
    if ($null -eq $Actual.Owner -or $null -eq $Actual.Group -or
        $null -eq $Expected.Owner -or $null -eq $Expected.Group -or
        $Actual.Owner.Value -ne $Expected.Owner.Value -or
        $Actual.Group.Value -ne $Expected.Group.Value) {
        return $false
    }

    $actualEntries = Get-ServiceAceMap $Actual
    $expectedEntries = Get-ServiceAceMap $Expected
    if ($null -eq $actualEntries -or $null -eq $expectedEntries -or
        $actualEntries.Count -ne $expectedEntries.Count) {
        return $false
    }
    foreach ($entry in $expectedEntries.GetEnumerator()) {
        [uint32]$actualMask = 0
        if (-not $actualEntries.TryGetValue($entry.Key, [ref]$actualMask) -or
            $actualMask -ne $entry.Value) {
            return $false
        }
    }
    return $true
}

function Assert-ServicePolicy([string]$ExpectedDescriptor) {
    try {
        $expected = [Security.AccessControl.RawSecurityDescriptor]::new(
            $ExpectedDescriptor)
        $actual = [Security.AccessControl.RawSecurityDescriptor]::new(
            [Oac.ServicePolicy]::ReadSecurity('OACService'), 0)
    } catch {
        throw "OACService security descriptor could not be read or parsed: $($_.Exception.Message)"
    }
    if (-not (Test-ServiceDescriptor $actual $expected)) {
        $actualText = $actual.GetSddlForm(
            [Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Group -bor
            [Security.AccessControl.AccessControlSections]::Access)
        throw "OACService does not retain the required owner, group, and DACL: $actualText"
    }

    try {
        $recoveryValid = [Oac.ServicePolicy]::HasRecoveryPolicy(
            'OACService', 86400, 5000)
    } catch {
        throw "OACService recovery policy could not be queried: $($_.Exception.Message)"
    }
    if (-not $recoveryValid) {
        throw 'OACService does not have the bounded one-restart recovery policy.'
    }
}

function Assert-ExistingInstallDirectory(
    [string]$Path,
    [hashtable]$ExpectedFiles,
    [string]$ExpectedThumbprint,
    [string[]]$UnsignedFiles
) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $directory = Get-Item -LiteralPath $Path -Force
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing an invalid OAC-Test install directory: $Path"
    }
    Assert-ProtectedInstallAcl $Path
    $unexpected = @(Get-ChildItem -LiteralPath $Path -Force | Where-Object {
            -not $ExpectedFiles.ContainsKey($_.Name)
        })
    if ($unexpected.Count -ne 0) {
        throw "The OAC-Test install directory contains unexpected content: $Path"
    }
    foreach ($name in $ExpectedFiles.Keys) {
        $installedPath = Join-Path $Path $name
        if (-not (Test-Path -LiteralPath $installedPath -PathType Leaf)) {
            throw "The existing OAC-Test install is incomplete: $installedPath"
        }
        $item = Get-Item -LiteralPath $installedPath -Force
        Assert-ProtectedFileAcl $installedPath
        $sourcePath = [string]$ExpectedFiles[$name]
        $requiresAuthenticode = $UnsignedFiles -cnotcontains $name
        $signature = if ($requiresAuthenticode) {
            Get-AuthenticodeSignature -FilePath $installedPath
        } else {
            $null
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash -ne
                (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -or
            ($requiresAuthenticode -and (
                -not $signature.SignerCertificate -or
                $signature.SignerCertificate.Thumbprint -ne $ExpectedThumbprint -or
                $signature.Status -in @(
                    [Management.Automation.SignatureStatus]::HashMismatch,
                    [Management.Automation.SignatureStatus]::NotSigned)))) {
            throw "Refusing an unowned OAC-Test file: $installedPath"
        }
    }
}

function Resolve-DriverImagePath([string]$ImagePath) {
    if ([string]::IsNullOrWhiteSpace($ImagePath)) {
        throw 'The OAC driver ImagePath is empty.'
    }
    $candidate = $ImagePath.Trim()
    if ($candidate.StartsWith('"', [StringComparison]::Ordinal)) {
        if (-not $candidate.EndsWith('"', [StringComparison]::Ordinal) -or
            $candidate.Length -lt 3) {
            throw 'The OAC driver ImagePath has invalid quoting.'
        }
        $candidate = $candidate.Substring(1, $candidate.Length - 2)
    }
    if ($candidate.Contains('"')) {
        throw 'The OAC driver ImagePath contains arguments or invalid quoting.'
    }
    if ($candidate.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $candidate = Join-Path $env:SystemRoot $candidate.Substring(12)
    } elseif ($candidate.StartsWith(
            '%SystemRoot%\', [StringComparison]::OrdinalIgnoreCase)) {
        $candidate = Join-Path $env:SystemRoot $candidate.Substring(13)
    } elseif ($candidate.StartsWith('\??\', [StringComparison]::Ordinal)) {
        $candidate = $candidate.Substring(4)
    } elseif ($candidate.StartsWith(
            'System32\', [StringComparison]::OrdinalIgnoreCase)) {
        $candidate = Join-Path $env:SystemRoot $candidate
    } elseif (-not [IO.Path]::IsPathRooted($candidate)) {
        throw 'The OAC driver ImagePath is not an accepted absolute system path.'
    }
    return [IO.Path]::GetFullPath($candidate)
}

function Assert-SignedFileIdentity(
    [string]$InstalledPath,
    [string]$PackagePath,
    [string]$ExpectedThumbprint
) {
    if (-not (Test-Path -LiteralPath $InstalledPath -PathType Leaf)) {
        throw "A verified OAC installed file is missing: $InstalledPath"
    }
    $item = Get-Item -LiteralPath $InstalledPath -Force
    $signature = Get-AuthenticodeSignature -FilePath $InstalledPath
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-FileHash -LiteralPath $InstalledPath -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash -or
        -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $ExpectedThumbprint -or
        $signature.Status -in @(
            [Management.Automation.SignatureStatus]::HashMismatch,
            [Management.Automation.SignatureStatus]::NotSigned)) {
        throw "An installed OAC file does not match the signed package: $InstalledPath"
    }
}

function Clear-ReadOnlyFile([string]$Path) {
    $attributes = [IO.File]::GetAttributes($Path)
    if (($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
        $attributes = $attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
        [IO.File]::SetAttributes($Path, $attributes)
    }
    if (([IO.File]::GetAttributes($Path) -band
            [IO.FileAttributes]::ReadOnly) -ne 0) {
        throw "Could not clear the read-only attribute: $Path"
    }
}

function Get-VerifiedDriverPackage([switch]$Required) {
    $driverKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\OAC'
    $driverService = Get-Service -Name OAC -ErrorAction SilentlyContinue
    $driverKeyExists = Test-Path -LiteralPath $driverKey
    $driverServiceExists = $null -ne $driverService
    if ($null -ne $driverService) {
        $driverService.Dispose()
        $driverService = $null
    }
    if ($driverServiceExists -ne $driverKeyExists) {
        throw 'The OAC driver registration is inconsistent between SCM and the registry.'
    }

    $records = @(Get-WindowsDriver -Online -ErrorAction Stop | Where-Object {
            $_.OriginalFileName -and
            [IO.Path]::GetFileName([string]$_.OriginalFileName) -ieq 'OAC.inf'
        })
    if ($records.Count -eq 0) {
        if ($Required -or $driverServiceExists) {
            throw 'The registered OAC driver has no uniquely verifiable published INF.'
        }
        return $null
    }
    if ($records.Count -ne 1) {
        throw 'More than one published OAC.inf package exists; refusing ambiguous mutation.'
    }

    $record = $records[0]
    $publishedInf = [string]$record.Driver
    if ($publishedInf -notmatch '^oem[0-9]+\.inf$' -or
        [string]$record.ProviderName -cne 'OAC Project' -or
        [string]$record.ClassName -cne 'System' -or
        [bool]$record.Inbox) {
        throw 'The published OAC driver metadata does not match the reviewed package.'
    }

    $publishedInfPath = [IO.Path]::GetFullPath((Join-Path `
        $env:SystemRoot (Join-Path 'INF' $publishedInf)))
    if (-not (Test-Path -LiteralPath $publishedInfPath -PathType Leaf)) {
        throw 'The published OAC INF is missing from the Windows INF directory.'
    }
    $publishedInfItem = Get-Item -LiteralPath $publishedInfPath -Force
    if (($publishedInfItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-FileHash -LiteralPath $publishedInfPath -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash) {
        throw 'The published Windows INF does not match this package.'
    }

    $storeRoot = [IO.Path]::GetFullPath((Join-Path `
        $env:SystemRoot 'System32\DriverStore\FileRepository')).TrimEnd(
            [IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $storeInf = (Resolve-Path -LiteralPath ([string]$record.OriginalFileName)).Path
    if (-not $storeInf.StartsWith(
            $storeRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The published OAC INF is outside the Driver Store.'
    }
    $storeDirectory = Split-Path -Parent $storeInf
    $storeDirectoryItem = Get-Item -LiteralPath $storeDirectory -Force
    if (($storeDirectoryItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-FileHash -LiteralPath $storeInf -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash) {
        throw 'The published OAC INF does not match this package.'
    }

    $storeBinary = Join-Path $storeDirectory 'OAC.sys'
    Assert-SignedFileIdentity `
        $storeBinary $driver $certificateObject.Thumbprint
    $catalogRoot = Join-Path $env:SystemRoot `
        'System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
    $catalogValue = [string]$record.CatalogFile
    $catalogLeaf = [IO.Path]::GetFileName($catalogValue)
    if ([string]::IsNullOrWhiteSpace($catalogValue) -or
        $catalogLeaf -ine [IO.Path]::GetFileName($catalog)) {
        throw 'The installed OAC catalog metadata does not match this package.'
    }
    $storeCatalog = Join-Path $storeDirectory ([IO.Path]::GetFileName($catalog))
    Assert-SignedFileIdentity `
        $storeCatalog $catalog $certificateObject.Thumbprint
    if (-not (Test-Path -LiteralPath $catalogRoot -PathType Container)) {
        throw "The system catalog store is missing: $catalogRoot"
    }
    $catalogRootItem = Get-Item -LiteralPath $catalogRoot -Force
    if (($catalogRootItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The system catalog store is a reparse point.'
    }
    # SetupCopyOEMInf gives the published INF and catalog the same oemN stem.
    $publishedCatalog = [IO.Path]::ChangeExtension($publishedInf, '.cat')
    $installedCatalog = Join-Path $catalogRoot $publishedCatalog
    Assert-SignedFileIdentity `
        $installedCatalog $catalog $certificateObject.Thumbprint

    if ($Required -and -not $driverServiceExists) {
        throw 'The published OAC package has no registered OAC driver service.'
    }
    $serviceBinary = $null
    if ($driverServiceExists) {
        $configuration = Get-ItemProperty -LiteralPath $driverKey
        if ([int]$configuration.Type -ne 1 -or
            [int]$configuration.Start -ne 3 -or
            [int]$configuration.ErrorControl -ne 1) {
            throw 'The OAC driver service registration does not match the package.'
        }
        $serviceBinary = Resolve-DriverImagePath ([string]$configuration.ImagePath)
        $legacyBinary = [IO.Path]::GetFullPath((Join-Path `
            $env:SystemRoot 'System32\drivers\OAC.sys'))
        if (-not $serviceBinary.Equals(
                [IO.Path]::GetFullPath($storeBinary),
                [StringComparison]::OrdinalIgnoreCase) -and
            -not $serviceBinary.Equals(
                $legacyBinary,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The OAC driver ImagePath is outside its exact package locations.'
        }
        Assert-SignedFileIdentity `
            $serviceBinary $driver $certificateObject.Thumbprint
    }

    return [pscustomobject]@{
        PublishedInf = $publishedInf
        PublishedInfPath = $publishedInfPath
        StoreInf = $storeInf
        StoreBinary = $storeBinary
        StoreCatalog = $storeCatalog
        ServiceBinary = $serviceBinary
        Catalog = $installedCatalog
    }
}

function Assert-TestCertificateStores {
    $expectedRaw = [Convert]::ToBase64String($certificateObject.RawData)
    foreach ($storeName in @('Root', 'TrustedPublisher')) {
        $matches = @(Get-ChildItem -LiteralPath "Cert:\LocalMachine\$storeName" |
            Where-Object Thumbprint -EQ $certificateObject.Thumbprint)
        if ($matches.Count -ne 1 -or
            [Convert]::ToBase64String($matches[0].RawData) -cne $expectedRaw) {
            throw "The OAC test certificate is not uniquely owned in LocalMachine\$storeName."
        }
    }
}

function Remove-TestCertificateStores {
    $expectedRaw = [Convert]::ToBase64String($certificateObject.RawData)
    foreach ($storeName in @('Root', 'TrustedPublisher')) {
        $store = [Security.Cryptography.X509Certificates.X509Store]::new(
            $storeName,
            [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $matches = $store.Certificates.Find(
                [Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $certificateObject.Thumbprint,
                $false)
            if ($matches.Count -ne 1 -or
                [Convert]::ToBase64String($matches[0].RawData) -cne $expectedRaw) {
                throw "The OAC test certificate changed in LocalMachine\$storeName."
            }
            $store.Remove($matches[0])
        } finally {
            $store.Close()
        }
    }
}

function Wait-ServiceRemoved([string]$Name, [string]$RegistryPath) {
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        $exists = $null -ne $service
        if ($null -ne $service) { $service.Dispose() }
        if (-not $exists -and -not (Test-Path -LiteralPath $RegistryPath)) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Service $Name was not removed within the bounded wait."
}

function Invoke-BoundedProcess(
    [string]$FilePath,
    [string[]]$Arguments,
    [int]$TimeoutSeconds = 30
) {
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments `
        -WindowStyle Hidden -PassThru
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            throw "$FilePath exceeded its bounded wait."
        }
        if ($process.ExitCode -ne 0) {
            throw "$FilePath failed with exit code $($process.ExitCode)."
        }
    } finally {
        $process.Dispose()
    }
}

$installDirectory = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'OAC-Test'))
$serviceInstallPath = Join-Path $installDirectory 'OAC-Service.exe'
$quotedServicePath = '"{0}"' -f $serviceInstallPath
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\OACService'
$serviceDescriptor =
    'O:SYG:SYD:(A;;0x000F01FF;;;SY)(A;;0x00000014;;;BA)(A;;0x00000014;;;IU)'
$registeredService = Get-Service -Name OACService -ErrorAction SilentlyContinue
$serviceKeyExists = Test-Path -LiteralPath $serviceKey
$serviceRegistrationExists = $null -ne $registeredService
if ($serviceRegistrationExists -ne $serviceKeyExists) {
    throw 'Refusing an OACService name collision that cannot be verified in both SCM and the registry.'
}
if ($null -ne $registeredService) {
    $registeredService.Dispose()
    $registeredService = $null
}
if ($serviceKeyExists) {
    $registeredImagePath = [string](
        Get-ItemProperty -LiteralPath $serviceKey -Name ImagePath).ImagePath
    if ($registeredImagePath -cne $quotedServicePath) {
        throw 'Refusing an OACService registration outside OAC-Test.'
    }
    Assert-ServiceConfiguration `
        $serviceKey $quotedServicePath -AllowDisabled
    Assert-ServicePolicy $serviceDescriptor
}
$expectedInstalledFiles = @{
    'OAC-Service.exe' = $serviceSource
    'OAC-Launcher.exe' = $launcherSource
    'OAC.policy' = $policySource
    'OAC.policy.p7s' = $policySignatureSource
    'OAC-Liveness-Target.exe.oac-manifest' = $gameManifestSource
    'OAC-Liveness-Target.exe.oac-manifest.p7s' =
        $gameManifestSignatureSource
}
$unsignedInstalledFiles = @(
    'OAC.policy',
    'OAC.policy.p7s',
    'OAC-Liveness-Target.exe.oac-manifest',
    'OAC-Liveness-Target.exe.oac-manifest.p7s')
Assert-ExistingInstallDirectory `
    $installDirectory $expectedInstalledFiles $certificateObject.Thumbprint `
    $unsignedInstalledFiles
Assert-TrustStateRegistry $manifestSignerSha256 $policySignerSha256 `
    -AllowMissing:(-not $serviceKeyExists)
if ($serviceKeyExists -and
    -not (Test-Path -LiteralPath $serviceInstallPath -PathType Leaf)) {
    throw 'Refusing an OACService registration without its verified OAC-Test binary.'
}
$installDirectoryExists = Test-Path -LiteralPath $installDirectory -PathType Container
if ($Remove -and (-not $serviceKeyExists -or -not $installDirectoryExists)) {
    throw 'No complete, verified OAC test service installation exists to remove.'
}
$verifiedDriverPackage = Get-VerifiedDriverPackage -Required:$Remove

if ($Remove) {
    Assert-TestCertificateStores

    Invoke-BoundedProcess 'sc.exe' @(
        'config', 'OACService', 'start=', 'disabled')
    if ([int](Get-ItemProperty -LiteralPath $serviceKey -Name Start).Start -ne 4) {
        throw 'OACService did not become disabled before removal.'
    }
    Stop-ServiceBounded 'OACService'
    Stop-ServiceBounded 'OAC'
    Invoke-BoundedProcess 'sc.exe' @('delete', 'OACService')
    Wait-ServiceRemoved 'OACService' $serviceKey
    Invoke-BoundedProcess 'sc.exe' @('delete', 'OAC')
    Wait-ServiceRemoved 'OAC' 'HKLM:\SYSTEM\CurrentControlSet\Services\OAC'

    Invoke-BoundedProcess 'pnputil.exe' @(
        '/delete-driver',
        [string]$verifiedDriverPackage.PublishedInf,
        '/uninstall')
    Wait-ServiceRemoved 'OAC' 'HKLM:\SYSTEM\CurrentControlSet\Services\OAC'
    $remainingDriver = @(Get-WindowsDriver -Online -ErrorAction Stop |
        Where-Object Driver -IEQ $verifiedDriverPackage.PublishedInf)
    if ($remainingDriver.Count -ne 0 -or
        (Test-Path -LiteralPath $verifiedDriverPackage.PublishedInfPath) -or
        (Test-Path -LiteralPath $verifiedDriverPackage.StoreInf) -or
        (Test-Path -LiteralPath $verifiedDriverPackage.StoreBinary) -or
        (Test-Path -LiteralPath $verifiedDriverPackage.StoreCatalog) -or
        ($null -ne $verifiedDriverPackage.ServiceBinary -and
            (Test-Path -LiteralPath $verifiedDriverPackage.ServiceBinary)) -or
        (Test-Path -LiteralPath $verifiedDriverPackage.Catalog)) {
        throw 'Windows retained part of the exact OAC driver package after removal.'
    }

    foreach ($installedName in $expectedInstalledFiles.Keys) {
        $installedPath = Join-Path $installDirectory $installedName
        Clear-ReadOnlyFile $installedPath
        [IO.File]::Delete($installedPath)
    }
    if (@(Get-ChildItem -LiteralPath $installDirectory -Force).Count -ne 0) {
        throw 'Refusing to remove a non-empty OAC-Test directory.'
    }
    [IO.Directory]::Delete($installDirectory)
    Remove-TrustStateRegistry $manifestSignerSha256 $policySignerSha256
    Remove-TestCertificateStores
    foreach ($storeName in @('Root', 'TrustedPublisher')) {
        if (@(Get-ChildItem -LiteralPath "Cert:\LocalMachine\$storeName" |
                Where-Object Thumbprint -EQ $certificateObject.Thumbprint).Count -ne 0) {
            throw "The OAC test certificate remains in LocalMachine\$storeName."
        }
    }
    Write-Host 'Removed the verified OAC disposable-VM test stack.'
    return
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

# Import-Certificate can fail for TrustedPublisher from a SYSTEM startup task
# on Windows 11 24H2. CertUtil uses the native machine-store path.
Add-TestCertificateToMachineStore 'Root'
Add-TestCertificateToMachineStore 'TrustedPublisher'

foreach ($path in $signedFiles) {
    $signature = Get-AuthenticodeSignature -FilePath $path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $certificateObject.Thumbprint) {
        throw "Signature validation failed after trust import: $path ($($signature.Status))"
    }
}

if ($null -eq $verifiedDriverPackage -or
    $null -eq $verifiedDriverPackage.ServiceBinary) {
    & pnputil.exe /add-driver $inf /install
    if ($LASTEXITCODE -ne 0) {
        throw 'PnPUtil failed to install the OAC test package.'
    }
} else {
    Write-Host "Reusing verified driver package $($verifiedDriverPackage.PublishedInf)."
}

$driverServiceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\OAC'
$driverConfiguration = Get-ItemProperty -LiteralPath $driverServiceKey
if ([int]$driverConfiguration.Type -ne 1 -or
    [int]$driverConfiguration.Start -ne 3) {
    throw 'OAC must remain a demand-start kernel driver (Type=1, Start=3).'
}
$installedDriverPackage = Get-VerifiedDriverPackage -Required
if ($null -eq $installedDriverPackage) {
    throw 'The installed OAC driver package could not be verified.'
}

Stop-ServiceBounded 'OACService'
Stop-ServiceBounded 'OAC'
$parametersKey = Join-Path $driverServiceKey 'Parameters'
New-Item -Path $parametersKey -Force | Out-Null
$labMode = if ($LegacyV4LabMode) { 1 } else { 0 }
New-ItemProperty -LiteralPath $parametersKey -Name LabMode -PropertyType DWord `
    -Value $labMode -Force | Out-Null
if ([int](Get-ItemProperty -LiteralPath $parametersKey -Name LabMode).LabMode -ne
    $labMode) {
    throw 'The OAC LabMode registry value could not be verified.'
}

$createdDirectory = $false
$createdService = $false
$trustStateExisted = Test-Path -LiteralPath 'HKLM:\SOFTWARE\OAC'
$copiedFiles = [Collections.Generic.List[string]]::new()
try {
    if (Test-Path -LiteralPath $installDirectory) {
        Assert-ExistingInstallDirectory `
            $installDirectory $expectedInstalledFiles `
            $certificateObject.Thumbprint $unsignedInstalledFiles
    } else {
        New-Item -ItemType Directory -Path $installDirectory | Out-Null
        $createdDirectory = $true
    }

    if (Test-Path -LiteralPath $serviceKey) {
        $existingImagePath = [string](
            Get-ItemProperty -LiteralPath $serviceKey -Name ImagePath).ImagePath
        if ($existingImagePath -cne $quotedServicePath) {
            throw 'Refusing to replace an OACService registration outside OAC-Test.'
        }
    }

    foreach ($installedName in @($expectedInstalledFiles.Keys | Sort-Object)) {
        $sourcePath = [string]$expectedInstalledFiles[$installedName]
        $destinationPath = Join-Path $installDirectory $installedName
        if (Test-Path -LiteralPath $destinationPath) {
            $destination = Get-Item -LiteralPath $destinationPath -Force
            if (($destination.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash -ne
                    (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash) {
                throw "Refusing to overwrite an unexpected OAC-Test binary: $destinationPath"
            }
        } else {
            Copy-Item -LiteralPath $sourcePath -Destination $destinationPath
            $copiedFiles.Add($destinationPath)
        }
        Clear-ReadOnlyFile $destinationPath
        if ($unsignedInstalledFiles -cnotcontains $installedName) {
            $installedSignature =
                Get-AuthenticodeSignature -FilePath $destinationPath
            if ($installedSignature.Status -ne
                    [Management.Automation.SignatureStatus]::Valid -or
                -not $installedSignature.SignerCertificate -or
                $installedSignature.SignerCertificate.Thumbprint -ne
                    $certificateObject.Thumbprint) {
                throw "Installed OAC-Test binary signature is invalid: $destinationPath"
            }
        }
    }
    Set-ProtectedInstallAcl $installDirectory
    foreach ($installedName in $expectedInstalledFiles.Keys) {
        Set-ProtectedFileAcl (Join-Path $installDirectory $installedName)
    }
    Assert-ExistingInstallDirectory `
        $installDirectory $expectedInstalledFiles $certificateObject.Thumbprint `
        $unsignedInstalledFiles
    Initialize-TrustStateRegistry $manifestSignerSha256 $policySignerSha256

    if (-not (Test-Path -LiteralPath $serviceKey)) {
        New-Service -Name 'OACService' -BinaryPathName $quotedServicePath `
            -DisplayName 'OAC Test Control Service' `
            -Description 'Disposable-VM OAC production control service' `
            -StartupType Manual -DependsOn 'OAC' | Out-Null
        $createdService = $true
    } else {
        Invoke-ScChecked @(
            'config', 'OACService', 'type=', 'own', 'start=', 'demand',
            'error=', 'normal', 'depend=', 'OAC', 'obj=', 'LocalSystem')
    }
    Invoke-ScChecked @('sidtype', 'OACService', 'restricted')
    Invoke-ScChecked @(
        'privs', 'OACService',
        ('SeAssignPrimaryTokenPrivilege/SeChangeNotifyPrivilege/' +
            'SeImpersonatePrivilege/SeIncreaseQuotaPrivilege'))
    Invoke-ScChecked @(
        'description', 'OACService',
        'Disposable-VM OAC production control service')
    [Oac.ServicePolicy]::WriteRecoveryPolicy('OACService', 86400, 5000)
    Assert-ServiceConfiguration $serviceKey $quotedServicePath

    [Oac.ServicePolicy]::WriteSecurity('OACService', $serviceDescriptor)
    Assert-ServicePolicy $serviceDescriptor

    $sidText = & sc.exe showsid OACService 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or
        $sidText -notmatch
            'S-1-5-80-1726785755-3364470821-2652420548-2779146334-590817200') {
        throw 'The installed OACService SID is not the reviewed fixed SID.'
    }
    & sc.exe qc OACService
    & sc.exe qsidtype OACService
    & sc.exe qprivs OACService
} catch {
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    if ($createdService) {
        try {
            & sc.exe stop OACService 2>&1 | Out-Null
            & sc.exe delete OACService 2>&1 | Out-Null
            Wait-ServiceRemoved 'OACService' $serviceKey
        } catch {
            $cleanupErrors.Add($_.Exception.Message)
        }
    }
    foreach ($copiedFile in $copiedFiles) {
        try {
            if ([IO.File]::Exists($copiedFile)) {
                Clear-ReadOnlyFile $copiedFile
                [IO.File]::Delete($copiedFile)
            }
        } catch {
            $cleanupErrors.Add($_.Exception.Message)
        }
    }
    if (-not $trustStateExisted -and
        (Test-Path -LiteralPath 'HKLM:\SOFTWARE\OAC')) {
        try {
            Remove-TrustStateRegistry $manifestSignerSha256 $policySignerSha256
        } catch {
            $cleanupErrors.Add($_.Exception.Message)
        }
    }
    try {
        if ($createdDirectory -and [IO.Directory]::Exists($installDirectory) -and
            @(Get-ChildItem -LiteralPath $installDirectory -Force).Count -eq 0) {
            [IO.Directory]::Delete($installDirectory)
        }
    } catch {
        $cleanupErrors.Add($_.Exception.Message)
    }
    foreach ($cleanupError in $cleanupErrors) {
        $message = "Installation rollback also failed: $cleanupError"
        try {
            Write-Warning $message
        } catch {
            try { [Console]::Error.WriteLine($message) } catch { }
        }
    }
    throw
}

Start-ServiceBounded 'OAC'
$installedControlService = Get-Service -Name OACService -ErrorAction Stop
try {
    if ($installedControlService.Status -ne 'Stopped') {
        throw 'OACService must remain stopped until the production-boundary phase.'
    }
} finally {
    $installedControlService.Dispose()
}

if ($SmokeTestPid -ne 0) {
    & $client --pid $SmokeTestPid --mode test --output $SmokeTestOutput
    $scanExit = $LASTEXITCODE
    if ($scanExit -gt 1) { throw "OAC smoke test failed with exit code $scanExit" }
    Write-Host "Smoke-test report: $SmokeTestOutput"
}

$modeText = if ($LegacyV4LabMode) { 'legacy v4 LabMode=1' } else { 'LabMode=0' }
Write-Host "OAC test stack is installed in $modeText; OACService remains demand-start."
