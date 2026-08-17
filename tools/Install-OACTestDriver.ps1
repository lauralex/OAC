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
    'OAC-Service.exe', 'OAC-Launcher.exe')
$requiredTestFiles = @('OAC-Protocol-Test.exe', 'OAC-Protocol-Unit.exe')
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
    if ($null -eq $service -or $service.Status -eq 'Stopped') { return }
    Stop-Service -Name $Name -Force
    $service.WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(20))
    $service.Refresh()
    if ($service.Status -ne 'Stopped') {
        throw "Service $Name did not stop within the bounded wait."
    }
}

function Start-ServiceBounded([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction Stop
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

function Assert-ServiceConfiguration(
    [string]$ServicePath,
    [string]$ExpectedImagePath,
    [switch]$AllowDisabled
) {
    $configuration = Get-ItemProperty -LiteralPath $ServicePath
    $dependencies = @($configuration.DependOnService)
    $privileges = @($configuration.RequiredPrivileges)
    $start = [int]$configuration.Start
    if ([int]$configuration.Type -ne 0x10 -or
        ($start -ne 3 -and (-not $AllowDisabled -or $start -ne 4)) -or
        [string]$configuration.ObjectName -ne 'LocalSystem' -or
        [string]$configuration.ImagePath -cne $ExpectedImagePath -or
        $dependencies.Count -ne 1 -or $dependencies[0] -ne 'OAC' -or
        $privileges.Count -ne 1 -or
        $privileges[0] -ne 'SeChangeNotifyPrivilege' -or
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
    [string]$ExpectedThumbprint
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
        $signature = Get-AuthenticodeSignature -FilePath $installedPath
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash -ne
                (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -or
            -not $signature.SignerCertificate -or
            $signature.SignerCertificate.Thumbprint -ne $ExpectedThumbprint -or
            $signature.Status -in @(
                [Management.Automation.SignatureStatus]::HashMismatch,
                [Management.Automation.SignatureStatus]::NotSigned)) {
            throw "Refusing an unowned OAC-Test binary: $installedPath"
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
$launcherInstallPath = Join-Path $installDirectory 'OAC-Launcher.exe'
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
        $serviceKey $quotedServicePath -AllowDisabled:$Remove
    Assert-ServicePolicy $serviceDescriptor
}
$expectedInstalledFiles = @{
    'OAC-Service.exe' = $serviceSource
    'OAC-Launcher.exe' = $launcherSource
}
Assert-ExistingInstallDirectory `
    $installDirectory $expectedInstalledFiles $certificateObject.Thumbprint
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
$copiedFiles = [Collections.Generic.List[string]]::new()
try {
    if (Test-Path -LiteralPath $installDirectory) {
        Assert-ExistingInstallDirectory `
            $installDirectory $expectedInstalledFiles $certificateObject.Thumbprint
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

    foreach ($copy in @(
        @($serviceSource, $serviceInstallPath),
        @($launcherSource, $launcherInstallPath))) {
        $sourcePath = [string]$copy[0]
        $destinationPath = [string]$copy[1]
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
        $installedSignature = Get-AuthenticodeSignature -FilePath $destinationPath
        if ($installedSignature.Status -ne
                [Management.Automation.SignatureStatus]::Valid -or
            -not $installedSignature.SignerCertificate -or
            $installedSignature.SignerCertificate.Thumbprint -ne
                $certificateObject.Thumbprint) {
            throw "Installed OAC-Test binary signature is invalid: $destinationPath"
        }
    }
    Set-ProtectedInstallAcl $installDirectory
    foreach ($installedName in $expectedInstalledFiles.Keys) {
        Set-ProtectedFileAcl (Join-Path $installDirectory $installedName)
    }
    Assert-ExistingInstallDirectory `
        $installDirectory $expectedInstalledFiles $certificateObject.Thumbprint

    if (-not (Test-Path -LiteralPath $serviceKey)) {
        New-Service -Name 'OACService' -BinaryPathName $quotedServicePath `
            -DisplayName 'OAC Test Control Service' `
            -Description 'Disposable-VM OAC v5 control service' `
            -StartupType Manual -DependsOn 'OAC' | Out-Null
        $createdService = $true
    } else {
        Invoke-ScChecked @(
            'config', 'OACService', 'type=', 'own', 'start=', 'demand',
            'error=', 'normal', 'depend=', 'OAC', 'obj=', 'LocalSystem')
    }
    Invoke-ScChecked @('sidtype', 'OACService', 'restricted')
    Invoke-ScChecked @('privs', 'OACService', 'SeChangeNotifyPrivilege')
    Invoke-ScChecked @(
        'description', 'OACService', 'Disposable-VM OAC v5 control service')
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
if ((Get-Service -Name OACService).Status -ne 'Stopped') {
    throw 'OACService must remain stopped until the production-boundary phase.'
}

if ($SmokeTestPid -ne 0) {
    & $client --pid $SmokeTestPid --mode test --output $SmokeTestOutput
    $scanExit = $LASTEXITCODE
    if ($scanExit -gt 1) { throw "OAC smoke test failed with exit code $scanExit" }
    Write-Host "Smoke-test report: $SmokeTestOutput"
}

$modeText = if ($LegacyV4LabMode) { 'legacy v4 LabMode=1' } else { 'LabMode=0' }
Write-Host "OAC test stack is installed in $modeText; OACService remains demand-start."
