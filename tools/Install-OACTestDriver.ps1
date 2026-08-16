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
    if ([IO.Path]::GetFileName($Name) -ne $Name) {
        throw "Package manifest contains a non-leaf file name: $Name"
    }
    $candidate = Join-Path $Root $Name
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Required package file is missing: $candidate"
    }
    $resolved = (Resolve-Path -LiteralPath $candidate).Path
    if (-not $resolved.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Package file escaped its directory: $resolved"
    }
    return $resolved
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
    $paths = @{}
    foreach ($entry in @($Entries)) {
        $name = [string]$entry.name
        if ($paths.ContainsKey($name)) {
            throw "Package manifest contains a duplicate file: $name"
        }
        $path = Get-ContainedFile $Root $Prefix $name
        $item = Get-Item -LiteralPath $path
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
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell session inside the disposable VM.'
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
    $expectedRights = @{
        'S-1-5-18' = [int][Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-544' = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
        'S-1-5-32-545' = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
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
    $expectedRights = @{
        'S-1-5-18' = [int][Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-544' = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
        'S-1-5-32-545' = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
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
    [string]$ExpectedImagePath
) {
    $configuration = Get-ItemProperty -LiteralPath $ServicePath
    $dependencies = @($configuration.DependOnService)
    $privileges = @($configuration.RequiredPrivileges)
    if ([int]$configuration.Type -ne 0x10 -or
        [int]$configuration.Start -ne 3 -or
        [string]$configuration.ObjectName -ne 'LocalSystem' -or
        [string]$configuration.ImagePath -cne $ExpectedImagePath -or
        $dependencies.Count -ne 1 -or $dependencies[0] -ne 'OAC' -or
        $privileges.Count -ne 1 -or
        $privileges[0] -ne 'SeChangeNotifyPrivilege' -or
        [int]$configuration.ServiceSidType -ne 3) {
        throw 'OACService does not match the required demand-start restricted configuration.'
    }
}

function Assert-ServicePolicy([string]$ExpectedDacl) {
    $securityLines = @(& sc.exe sdshow OACService 2>&1)
    if ($LASTEXITCODE -ne 0 -or
        -not ($securityLines | Where-Object {
                $_.ToString().Trim() -eq $ExpectedDacl
            })) {
        throw 'OACService did not retain the protected service-object DACL.'
    }

    $failureText = & sc.exe qfailure OACService 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or
        $failureText -notmatch '(?im)RESET_PERIOD[^\r\n]*86400' -or
        [regex]::Matches($failureText, '(?im)\bRESTART\b').Count -ne 1 -or
        $failureText -notmatch '(?im)Delay[^\r\n]*5000' -or
        $failureText -match '(?im)RUN PROCESS|REBOOT\s+--' -or
        $failureText -notmatch '(?im)^[ \t]*REBOOT_MESSAGE[ \t]*:[ \t]*$' -or
        $failureText -notmatch '(?im)^[ \t]*COMMAND_LINE[ \t]*:[ \t]*$') {
        throw 'OACService does not have the bounded one-restart recovery policy.'
    }
    $failureFlagText = & sc.exe qfailureflag OACService 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or
        $failureFlagText -notmatch '(?im)\bTRUE\b') {
        throw 'OACService failure actions are not enabled for non-crash failures.'
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
        [string]$record.Version -cne '3.0.0.0' -or
        [bool]$record.Inbox) {
        throw 'The published OAC driver metadata does not match the reviewed package.'
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
    if ([string]::IsNullOrWhiteSpace($catalogValue)) {
        throw 'DISM did not return the installed OAC catalog identity.'
    }
    if ([IO.Path]::IsPathRooted($catalogValue)) {
        $installedCatalog = [IO.Path]::GetFullPath($catalogValue)
    } else {
        if ([IO.Path]::GetFileName($catalogValue) -ne $catalogValue) {
            throw 'The installed OAC catalog has an invalid relative path.'
        }
        $installedCatalog = [IO.Path]::GetFullPath((Join-Path `
            $catalogRoot $catalogValue))
    }
    $catalogPrefix = [IO.Path]::GetFullPath($catalogRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $installedCatalog.StartsWith(
            $catalogPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The installed OAC catalog is outside the system catalog store.'
    }
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
        StoreInf = $storeInf
        StoreBinary = $storeBinary
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
$serviceDacl =
    'D:P(A;;GA;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)'
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
    Assert-ServiceConfiguration $serviceKey $quotedServicePath
    Assert-ServicePolicy $serviceDacl
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
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.User.IsWellKnown(
            [Security.Principal.WellKnownSidType]::LocalSystemSid)) {
        throw '-Remove must run as LocalSystem in the disposable VM.'
    }
    Assert-TestCertificateStores

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
        (Test-Path -LiteralPath $verifiedDriverPackage.StoreInf) -or
        (Test-Path -LiteralPath $verifiedDriverPackage.StoreBinary) -or
        (Test-Path -LiteralPath $verifiedDriverPackage.Catalog)) {
        throw 'Windows retained part of the exact OAC driver package after removal.'
    }

    foreach ($installedName in $expectedInstalledFiles.Keys) {
        $installedPath = Join-Path $installDirectory $installedName
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

& pnputil.exe /add-driver $inf /install
if ($LASTEXITCODE -ne 0) { throw 'PnPUtil failed to install the OAC test package.' }

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
    Invoke-ScChecked @(
        'failure', 'OACService', 'reset=', '86400',
        'actions=', 'restart/5000')
    Invoke-ScChecked @('failureflag', 'OACService', '1')
    Assert-ServiceConfiguration $serviceKey $quotedServicePath

    Invoke-ScChecked @('sdset', 'OACService', $serviceDacl)
    Assert-ServicePolicy $serviceDacl

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
    if ($createdService) {
        & sc.exe stop OACService 2>&1 | Out-Null
        & sc.exe delete OACService 2>&1 | Out-Null
    }
    foreach ($copiedFile in $copiedFiles) {
        if ([IO.File]::Exists($copiedFile)) { [IO.File]::Delete($copiedFile) }
    }
    if ($createdDirectory -and [IO.Directory]::Exists($installDirectory) -and
        @(Get-ChildItem -LiteralPath $installDirectory -Force).Count -eq 0) {
        [IO.Directory]::Delete($installDirectory)
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
