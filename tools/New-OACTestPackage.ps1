[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [string]$OutputDirectory,

    [SecureString]$PfxPassword,

    [switch]$ExportPrivateKey,

    [switch]$KeepCertificateInCurrentUserStore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-MSBuildPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $installation = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($LASTEXITCODE -eq 0 -and $installation) {
            $candidate = Join-Path $installation 'MSBuild\Current\Bin\amd64\MSBuild.exe'
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }
    }
    throw 'Visual Studio 2022 with the x64 MSBuild host was not found.'
}

function Get-WindowsSdkTool([string]$Name, [string[]]$Architectures) {
    $kitRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
    foreach ($toolRootName in @('bin', 'Tools')) {
        $toolRoot = Join-Path $kitRoot $toolRootName
        if (-not (Test-Path -LiteralPath $toolRoot -PathType Container)) { continue }
        $versions = Get-ChildItem -LiteralPath $toolRoot -Directory |
            Where-Object { $_.Name -match '^10\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($version in $versions) {
            foreach ($architecture in $Architectures) {
                $candidate = Join-Path $version.FullName (Join-Path $architecture $Name)
                if (Test-Path -LiteralPath $candidate) { return $candidate }
            }
        }
    }
    throw "$Name was not found in the installed Windows SDK/WDK."
}

function Invoke-Checked([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath"
    }
}

function Get-CleanSourceCommit([string]$RepositoryRoot) {
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        throw 'Git is required to bind the test package to an exact source commit.'
    }
    $commit = (& git.exe -C $RepositoryRoot rev-parse --verify 'HEAD^{commit}' 2>&1 |
        Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'The repository HEAD is not a canonical Git commit.'
    }
    $status = @(& git.exe -C $RepositoryRoot status --porcelain=v1 `
        --untracked-files=all --ignore-submodules=none 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'Git could not verify the repository worktree state.'
    }
    if ($status.Count -ne 0) {
        throw 'Refusing to package a dirty worktree; commit the reviewed source first.'
    }
    return $commit
}

function Invoke-SelfSignedVerification(
    [string]$SignTool,
    [string]$FilePath,
    [string]$ExpectedThumbprint
) {
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        # An untrusted root is expected until the package reaches the disposable
        # VM. Windows PowerShell otherwise promotes SignTool's stderr to a
        # terminating NativeCommandError before the result can be classified.
        $ErrorActionPreference = 'Continue'
        $verification = & $SignTool verify /v /pa $FilePath 2>&1
        $verifyExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    $verificationText = [string]::Join(
        [Environment]::NewLine,
        @($verification | ForEach-Object { $_.ToString() }))
    $authenticode = Get-AuthenticodeSignature -LiteralPath $FilePath
    $actualThumbprint = if ($authenticode.SignerCertificate) {
        $authenticode.SignerCertificate.Thumbprint
    } else {
        ''
    }

    $expectedTrustFailure =
        $verifyExit -eq 1 -and
        $verificationText.Contains('terminated in a root') -and
        $verificationText.Contains(
            'certificate which is not trusted by the trust provider.') -and
        $verificationText.Contains('Number of errors: 1') -and
        $verificationText.Contains("SHA1 hash: $ExpectedThumbprint")
    if (-not $expectedTrustFailure -or
        $actualThumbprint -ne $ExpectedThumbprint) {
        $verification | Write-Output
        throw "Self-signed signature verification failed for $FilePath."
    }
    Write-Host "Verified signature and signer for $(Split-Path -Leaf $FilePath); trust is intentionally deferred to the disposable VM."
}

function Remove-CurrentUserCertificate(
    [ValidateSet('My', 'CA')]
    [string]$StoreName,
    [string]$Thumbprint,
    [switch]$DeletePrivateKey
) {
    if ($Thumbprint -cnotmatch '^[0-9A-Fa-f]{40}$') {
        throw 'The generated certificate thumbprint is invalid.'
    }
    if ($DeletePrivateKey -and $StoreName -cne 'My') {
        throw 'Private-key deletion is restricted to the CurrentUser My store.'
    }

    $path = "Cert:\CurrentUser\$StoreName\$Thumbprint"
    if (Test-Path -LiteralPath $path) {
        if ($DeletePrivateKey) {
            Remove-Item -Path $path -DeleteKey -Confirm:$false
        } else {
            Remove-Item -Path $path -Confirm:$false
        }
    }
    if (Test-Path -LiteralPath $path) {
        throw "The generated certificate remains in CurrentUser\$StoreName."
    }
}

function Convert-HexToBytes([string]$Hex) {
    if ($Hex -cnotmatch '^(?:[0-9A-F]{2})+$') {
        throw 'A canonical uppercase hexadecimal byte string was required.'
    }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return ,$bytes
}

function Get-Sha256Bytes([byte[]]$Bytes) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ,$sha256.ComputeHash($Bytes)
    } finally {
        $sha256.Dispose()
    }
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

function New-GameManifestBytes(
    [byte[]]$ManifestId,
    [byte[]]$GameId,
    [byte[]]$BuildId,
    [uint64]$Sequence,
    [uint64]$IssuedAtUnixSeconds,
    [uint64]$ExpiresAtUnixSeconds,
    [uint64]$ExecutableSize,
    [byte[]]$ExecutableSha256,
    [byte[]]$SigningKeyId,
    [string]$ExecutableName
) {
    foreach ($identity in @($ManifestId, $GameId, $BuildId)) {
        if ($identity.Length -ne 16) {
            throw 'Game-manifest identities must contain exactly 16 bytes.'
        }
    }
    if ($ExecutableSha256.Length -ne 32 -or $SigningKeyId.Length -ne 32) {
        throw 'Game-manifest hashes must contain exactly 32 bytes.'
    }
    if ($ExecutableName.Length -lt 5 -or $ExecutableName.Length -ge 128 -or
        [IO.Path]::GetFileName($ExecutableName) -cne $ExecutableName) {
        throw 'The game-manifest executable name must be a bounded leaf name.'
    }

    $stream = [IO.MemoryStream]::new(512)
    $writer = [IO.BinaryWriter]::new($stream, [Text.Encoding]::Unicode, $true)
    try {
        $writer.Write([byte[]]@(
            [byte][char]'O', [byte][char]'A', [byte][char]'C', [byte][char]'G',
            [byte][char]'M', [byte][char]'A', [byte][char]'N', 0))
        $writer.Write([uint32]1)
        $writer.Write([uint32]512)
        $writer.Write([uint32]0)
        $writer.Write([uint32]$ExecutableName.Length)
        $writer.Write($ManifestId)
        $writer.Write($GameId)
        $writer.Write($BuildId)
        $writer.Write($Sequence)
        $writer.Write($IssuedAtUnixSeconds)
        $writer.Write($ExpiresAtUnixSeconds)
        $writer.Write($ExecutableSize)
        $writer.Write([uint32]0x00050006)
        $writer.Write([uint32]0x00010006)
        $writer.Write([uint32]0x00010006)
        $writer.Write([uint32]0)
        $writer.Write($ExecutableSha256)
        $writer.Write($SigningKeyId)
        foreach ($character in $ExecutableName.ToCharArray()) {
            $writer.Write([uint16][char]$character)
        }
        for ($index = $ExecutableName.Length; $index -lt 128; $index++) {
            $writer.Write([uint16]0)
        }
        $writer.Write([byte[]]::new(72))
        $writer.Flush()
        $bytes = $stream.ToArray()
        if ($bytes.Length -ne 512) {
            throw "The canonical game manifest has an unexpected size: $($bytes.Length)"
        }
        return ,$bytes
    } finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

function Write-SignedRecord(
    [byte[]]$RecordBytes,
    [string]$RecordPath,
    [string]$SignaturePath,
    [Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate
) {
    Import-PkcsAssembly
    $content = [Security.Cryptography.Pkcs.ContentInfo]::new($RecordBytes)
    $signed = [Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,
        $SigningCertificate)
    $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new(
        '2.16.840.1.101.3.4.2.1')
    $signer.IncludeOption =
        [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $signed.ComputeSignature($signer, $false)
    $signature = $signed.Encode()
    [IO.File]::WriteAllBytes($RecordPath, $RecordBytes)
    [IO.File]::WriteAllBytes($SignaturePath, $signature)

    $verified = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new($RecordBytes), $true)
    $verified.Decode($signature)
    $verified.CheckSignature($true)
    if ($verified.SignerInfos.Count -ne 1 -or
        $verified.SignerInfos[0].DigestAlgorithm.Value -ne
            '2.16.840.1.101.3.4.2.1' -or
        $verified.SignerInfos[0].CounterSignerInfos.Count -ne 0 -or
        $verified.SignerInfos[0].UnsignedAttributes.Count -ne 0 -or
        [Convert]::ToBase64String($verified.SignerInfos[0].Certificate.RawData) -cne
            [Convert]::ToBase64String($SigningCertificate.RawData)) {
        throw "Detached signature verification failed: $RecordPath"
    }
}

function Get-PolicyRules {
    $kernel = [uint64]1
    $callback = [uint64]2
    return ,@(
        @(0x00010001, 7, 10, 0, 0, 0, 0, 0, 0, $kernel, 0),
        @(0x00010002, 9, 10, 4, 4, 4, 1, 5, 5, $kernel, 0),
        @(0x00010003, 9, 10, 0, 0, 3, 1, 1, 1, $kernel, 0),
        @(0x00010004, 1, 0, 1, 4, 2, 1, 2, 3, $kernel, 0),
        @(0x00010005, 7, 1, 0, 0, 0, 0, 0, 0, $kernel, 0),
        @(0x00010006, 7, 1, 0, 0, 0, 0, 0, 0, ($kernel -bor $callback), 0),
        @(0x00020001, 1, 2, 1, 2, 2, 1, 2, 3, ($kernel -bor $callback), 0),
        @(0x00020002, 1, 3, 0, 3, 1, 1, 1, 2, ($kernel -bor $callback), 0),
        @(0x00030001, 1, 4, 2, 2, 2, 1, 2, 5, ($kernel -bor $callback), 1),
        @(0x00030002, 1, 4, 4, 4, 4, 1, 5, 5, ($kernel -bor $callback), 0),
        @(0x00030003, 1, 4, 4, 4, 4, 1, 5, 5, ($kernel -bor $callback), 0),
        @(0x00040001, 1, 8, 3, 4, 3, 1, 6, 5, $kernel, 0),
        @(0x00040002, 1, 8, 1, 3, 1, 1, 2, 3, $kernel, 0),
        @(0x00080001, 1, 9, 1, 3, 1, 1, 1, 2, $kernel, 0)
    )
}

function New-SignedPolicyBytes(
    [byte[]]$PolicyId,
    [byte[]]$GameId,
    [byte[]]$BuildId,
    [byte[]]$ChannelId,
    [uint64]$PolicyVersion,
    [uint64]$UpdateSequence,
    [uint64]$IssuedAtUnixSeconds,
    [uint64]$ExpiresAtUnixSeconds,
    [byte[]]$SigningKeyId,
    [uint32]$Flags = 0,
    [uint32]$EmergencyReason = 0,
    [uint64]$RollbackFromPolicyVersion = 0,
    [byte[]]$RollbackFromPolicySha256 = $null
) {
    foreach ($identity in @($PolicyId, $GameId, $BuildId, $ChannelId)) {
        if ($identity.Length -ne 16) {
            throw 'Signed-policy identities must contain exactly 16 bytes.'
        }
    }
    if ($SigningKeyId.Length -ne 32) {
        throw 'The signed-policy key identity must contain exactly 32 bytes.'
    }
    if ($null -eq $RollbackFromPolicySha256) {
        $RollbackFromPolicySha256 = [byte[]]::new(32)
    }
    if ($RollbackFromPolicySha256.Length -ne 32) {
        throw 'The signed-policy rollback digest must contain exactly 32 bytes.'
    }
    $rules = Get-PolicyRules
    if ($rules.Count -ne 14) {
        throw 'The canonical signed-policy rule catalog must contain 14 rules.'
    }

    $stream = [IO.MemoryStream]::new(1024)
    $writer = [IO.BinaryWriter]::new($stream, [Text.Encoding]::Unicode, $true)
    try {
        $writer.Write([Text.Encoding]::ASCII.GetBytes('OACPOLCY'))
        $writer.Write([uint32]2)
        $writer.Write([uint32]1024)
        $writer.Write($Flags)
        $writer.Write([uint32]2)
        $writer.Write($PolicyId)
        $writer.Write($GameId)
        $writer.Write($BuildId)
        $writer.Write($ChannelId)
        $writer.Write($PolicyVersion)
        $writer.Write($UpdateSequence)
        $writer.Write($IssuedAtUnixSeconds)
        $writer.Write($ExpiresAtUnixSeconds)
        $writer.Write([uint32]0x00050006)
        $writer.Write([uint32]0x00010006)
        $writer.Write([uint32]0x00010006)
        $writer.Write([uint32]1)
        $writer.Write([uint32]$rules.Count)
        $writer.Write($EmergencyReason)
        $writer.Write($SigningKeyId)
        $writer.Write($RollbackFromPolicyVersion)
        $writer.Write($RollbackFromPolicySha256)
        foreach ($rule in $rules) {
            for ($field = 0; $field -lt 9; $field++) {
                $writer.Write([uint32]$rule[$field])
            }
            $writer.Write([uint32]0)
            $writer.Write([uint64]$rule[9])
            $writer.Write([uint32]$rule[10])
            $writer.Write([uint32]0)
        }
        # Task Scheduler starts the standard-user launcher during the VM test.
        # Keep the disposable policy lease long enough for that bounded handoff;
        # the lease-loss scenario still stops renewals and proves termination.
        $writer.Write([uint32]20000)
        $writer.Write([uint32]2000)
        $writer.Write([uint32]1000)
        $writer.Write([uint32]5000)
        $writer.Write([byte[]]::new(8))
        $writer.Flush()
        $bytes = $stream.ToArray()
        if ($bytes.Length -ne 1024) {
            throw "The canonical signed policy has an unexpected size: $($bytes.Length)"
        }
        return ,$bytes
    } finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$solution = Join-Path $repoRoot 'OAC.sln'
if (-not (Test-Path -LiteralPath $solution -PathType Leaf)) {
    throw "Repository solution was not found at $solution"
}
$sourceCommit = Get-CleanSourceCommit $repoRoot

if (-not $OutputDirectory) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) "OAC-TestPackage-$stamp"
}
$output = [IO.Path]::GetFullPath($OutputDirectory)
$repoPrefix = $repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
if ($output -ieq $repoRoot -or
    $output.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The generated package directory must be outside the source worktree.'
}
if (Test-Path -LiteralPath $output) {
    if (Get-ChildItem -LiteralPath $output -Force | Select-Object -First 1) {
        throw "Output directory is not empty: $output"
    }
} else {
    New-Item -ItemType Directory -Path $output | Out-Null
}
$package = Join-Path $output 'package'
$certificateDirectory = Join-Path $output 'certificate'
New-Item -ItemType Directory -Path $package | Out-Null
New-Item -ItemType Directory -Path $certificateDirectory | Out-Null

$msbuild = Get-MSBuildPath
$signTool = Get-WindowsSdkTool 'signtool.exe' @('x64', 'x86')
$inf2Cat = Get-WindowsSdkTool 'inf2cat.exe' @('x86', 'x64')
$infVerif = Get-WindowsSdkTool 'infverif.exe' @('x64', 'x86')
Invoke-Checked $msbuild @(
    $solution, '/m', '/nodeReuse:false', '/t:Rebuild',
    "/p:Configuration=$Configuration", '/p:Platform=x64',
    '/p:PreferredToolArchitecture=x64', '/p:SkipPackageVerification=true',
    '/p:Inf2CatUseLocalTime=true'
)
$postBuildCommit = Get-CleanSourceCommit $repoRoot
if ($postBuildCommit -cne $sourceCommit) {
    throw 'The source commit changed while the package was being built.'
}

$builtPackage = Join-Path $repoRoot "x64\$Configuration\OAC"
$client = Join-Path $repoRoot "x64\$Configuration\OAC-Client.exe"
$service = Join-Path $repoRoot "x64\$Configuration\OAC-Service.exe"
$launcher = Join-Path $repoRoot "x64\$Configuration\OAC-Launcher.exe"
$protocolTest = Join-Path $repoRoot "x64\$Configuration\OAC-Protocol-Test.exe"
$protocolUnit = Join-Path $repoRoot "x64\$Configuration\OAC-Protocol-Unit.exe"
foreach ($required in @(
    (Join-Path $builtPackage 'OAC.sys'),
    (Join-Path $builtPackage 'OAC.inf'),
    $client,
    $service,
    $launcher,
    $protocolTest,
    $protocolUnit
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Expected build artifact is missing: $required"
    }
}
Copy-Item -LiteralPath (Join-Path $builtPackage 'OAC.sys') -Destination $package
Copy-Item -LiteralPath (Join-Path $builtPackage 'OAC.inf') -Destination $package
Copy-Item -LiteralPath $client -Destination $package
Copy-Item -LiteralPath $service -Destination $package
Copy-Item -LiteralPath $launcher -Destination $package
$protocolTestOutput = Join-Path $output 'OAC-Protocol-Test.exe'
$protocolUnitOutput = Join-Path $output 'OAC-Protocol-Unit.exe'
Copy-Item -LiteralPath $protocolTest -Destination $protocolTestOutput
Copy-Item -LiteralPath $protocolUnit -Destination $protocolUnitOutput
Invoke-Checked $infVerif @('/w', '/v', (Join-Path $package 'OAC.inf'))

if ($PfxPassword -and -not $ExportPrivateKey) {
    throw 'PfxPassword was supplied without -ExportPrivateKey.'
}
if ($ExportPrivateKey -and -not $PfxPassword) {
    $PfxPassword = Read-Host 'Password for the exported local-test PFX' -AsSecureString
}

$certificate = $null
$certificateThumbprint = $null
$packageError = $null
try {
    $keyExportPolicy = if ($ExportPrivateKey) { 'Exportable' } else { 'NonExportable' }
    Write-Host 'Generating an ephemeral RSA-3072 local-test certificate.'
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=OAC LOCAL TEST ONLY - NOT FOR PRODUCTION' `
        -FriendlyName 'OAC local test signing certificate (disposable VM only)' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy $keyExportPolicy `
        -NotAfter (Get-Date).AddDays(30) `
        -TextExtension @('2.5.29.19={text}CA=FALSE', '2.5.29.37={text}1.3.6.1.5.5.7.3.3')
    $certificateThumbprint = $certificate.Thumbprint.ToUpperInvariant()
    if ($certificateThumbprint -cnotmatch '^[0-9A-F]{40}$') {
        throw 'The generated certificate has an invalid thumbprint.'
    }

    $cerPath = Join-Path $certificateDirectory 'OAC-Local-Test.cer'
    [IO.File]::WriteAllBytes(
        $cerPath,
        $certificate.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    Write-Host 'Exported the public test certificate.'
    if ($ExportPrivateKey) {
        $pfxPath = Join-Path $certificateDirectory 'OAC-Local-Test.pfx'
        Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $PfxPassword |
            Out-Null
    }
    $driver = Join-Path $package 'OAC.sys'
    $signedExecutables = @(
        (Join-Path $package 'OAC-Client.exe'),
        (Join-Path $package 'OAC-Service.exe'),
        (Join-Path $package 'OAC-Launcher.exe'),
        $protocolTestOutput,
        $protocolUnitOutput
    )
    foreach ($signedFile in @($driver) + $signedExecutables) {
        Invoke-Checked $signTool @(
            'sign', '/v', '/fd', 'SHA256', '/sha1', $certificateThumbprint,
            '/s', 'My', $signedFile
        )
    }

    Invoke-Checked $inf2Cat @("/driver:$package", '/os:10_X64', '/uselocaltime')
    $catalogFiles = @(Get-ChildItem -LiteralPath $package -File |
        Where-Object { $_.Extension -ieq '.cat' })
    if ($catalogFiles.Count -ne 1 -or $catalogFiles[0].Name -ine 'OAC.cat') {
        throw 'Inf2Cat did not create the single expected OAC catalog.'
    }
    if ($catalogFiles[0].Name -cne 'OAC.cat') {
        $originalCatalog = $catalogFiles[0].FullName
        $temporaryCatalog = Join-Path $package `
            ".oac-$([Guid]::NewGuid().ToString('N')).tmp"
        Move-Item -LiteralPath $originalCatalog -Destination $temporaryCatalog
        try {
            Move-Item -LiteralPath $temporaryCatalog `
                -Destination (Join-Path $package 'OAC.cat')
        } catch {
            $renameError = $_
            if (Test-Path -LiteralPath $temporaryCatalog -PathType Leaf) {
                if (-not (Test-Path -LiteralPath $originalCatalog)) {
                    try {
                        Move-Item -LiteralPath $temporaryCatalog -Destination $originalCatalog
                    } catch {
                        Write-Warning 'Could not restore the catalog name after rename failure.'
                    }
                }
                if (Test-Path -LiteralPath $temporaryCatalog -PathType Leaf) {
                    Remove-Item -LiteralPath $temporaryCatalog -Force `
                        -ErrorAction SilentlyContinue
                }
            }
            throw $renameError
        }
    }
    $catalog = Join-Path $package 'OAC.cat'
    Invoke-Checked $signTool @(
        'sign', '/v', '/fd', 'SHA256', '/sha1', $certificateThumbprint,
        '/s', 'My', $catalog
    )
    foreach ($signedFile in @($driver, $catalog) + $signedExecutables) {
        Invoke-SelfSignedVerification `
            $signTool $signedFile $certificateThumbprint
    }

    $launcherOutput = Join-Path $package 'OAC-Launcher.exe'
    $serviceOutput = Join-Path $package 'OAC-Service.exe'
    $targetName = 'OAC-Liveness-Target.exe'
    $targetManifest = Join-Path $package "$targetName.oac-manifest"
    $targetSignature = "$targetManifest.p7s"
    $gameId = [Guid]'9f2e4b47-b779-4a07-8149-4c647742a7de'
    $buildId = (Get-Sha256Bytes `
        ([Text.Encoding]::ASCII.GetBytes($sourceCommit)))[0..15]
    $signingKeyId = Get-Sha256Bytes $certificate.RawData
    $launcherHash = Convert-HexToBytes `
        (Get-FileHash -LiteralPath $launcherOutput -Algorithm SHA256).Hash
    $serviceHash = Convert-HexToBytes `
        (Get-FileHash -LiteralPath $serviceOutput -Algorithm SHA256).Hash
    $now = [uint64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $certificateExpiry = [uint64]([DateTimeOffset]::new(
        $certificate.NotAfter.ToUniversalTime())).ToUnixTimeSeconds()
    $validExpiry = [uint64][Math]::Min(
        [double]($now + 7 * 24 * 60 * 60),
        [double]($certificateExpiry - 3600))
    $validManifest = New-GameManifestBytes `
        ([Guid]::NewGuid().ToByteArray()) `
        $gameId.ToByteArray() `
        ([byte[]]$buildId) `
        3 `
        ($now - 60) `
        $validExpiry `
        (Get-Item -LiteralPath $launcherOutput).Length `
        $launcherHash `
        $signingKeyId `
        $targetName
    Write-SignedRecord `
        $validManifest $targetManifest $targetSignature $certificate

    $fixtureDefinitions = @(
        [pscustomobject]@{
            Name = 'Expired'
            Sequence = [uint64]4
            Issued = [uint64]($now - 2 * 24 * 60 * 60)
            Expires = [uint64]($now - 24 * 60 * 60)
            Hash = $launcherHash
        },
        [pscustomobject]@{
            Name = 'Wrong-Build'
            Sequence = [uint64]4
            Issued = [uint64]($now - 60)
            Expires = $validExpiry
            Hash = $serviceHash
        },
        [pscustomobject]@{
            Name = 'Rollback'
            Sequence = [uint64]2
            Issued = [uint64]($now - 60)
            Expires = $validExpiry
            Hash = $launcherHash
        })
    $manifestFixtures = [Collections.Generic.List[string]]::new()
    foreach ($fixture in $fixtureDefinitions) {
        $fixtureManifest = Join-Path $output `
            "OAC-Game-Manifest-$($fixture.Name).bin"
        $fixtureSignature = "$fixtureManifest.p7s"
        $fixtureBytes = New-GameManifestBytes `
            ([Guid]::NewGuid().ToByteArray()) `
            $gameId.ToByteArray() `
            ([byte[]]$buildId) `
            $fixture.Sequence `
            $fixture.Issued `
            $fixture.Expires `
            (Get-Item -LiteralPath $launcherOutput).Length `
            $fixture.Hash `
            $signingKeyId `
            $targetName
        Write-SignedRecord `
            $fixtureBytes $fixtureManifest $fixtureSignature $certificate
        $manifestFixtures.Add($fixtureManifest)
        $manifestFixtures.Add($fixtureSignature)
    }

    $policyId = [Guid]::NewGuid().ToByteArray()
    $channelId = ([Guid]'16f42141-ca73-49a0-80a8-86df64076964').ToByteArray()
    $validPolicy = New-SignedPolicyBytes `
        $policyId $gameId.ToByteArray() ([byte[]]$buildId) $channelId `
        3 3 ($now - 60) $validExpiry $signingKeyId
    $policyPath = Join-Path $package 'OAC.policy'
    $policySignature = "$policyPath.p7s"
    Write-SignedRecord $validPolicy $policyPath $policySignature $certificate

    $policyFixtures = [Collections.Generic.List[string]]::new()
    $wrongScopePolicy = New-SignedPolicyBytes `
        ([Guid]::NewGuid().ToByteArray()) $gameId.ToByteArray() `
        ([Guid]::NewGuid().ToByteArray()) `
        ([Guid]::NewGuid().ToByteArray()) `
        1 1 ($now - 60) $validExpiry $signingKeyId
    $wrongScopePath = Join-Path $output 'OAC-Policy-Wrong-Scope.bin'
    Write-SignedRecord `
        $wrongScopePolicy $wrongScopePath "$wrongScopePath.p7s" $certificate
    $policyFixtures.Add($wrongScopePath)
    $policyFixtures.Add("$wrongScopePath.p7s")

    $expiredPolicy = New-SignedPolicyBytes `
        ([Guid]::NewGuid().ToByteArray()) $gameId.ToByteArray() `
        ([byte[]]$buildId) ([Guid]::NewGuid().ToByteArray()) `
        1 1 ($now - 2 * 24 * 60 * 60) ($now - 24 * 60 * 60) $signingKeyId
    $expiredPolicyPath = Join-Path $output 'OAC-Policy-Expired.bin'
    Write-SignedRecord `
        $expiredPolicy $expiredPolicyPath "$expiredPolicyPath.p7s" $certificate
    $policyFixtures.Add($expiredPolicyPath)
    $policyFixtures.Add("$expiredPolicyPath.p7s")

    $rollbackPolicy = New-SignedPolicyBytes `
        ([Guid]::NewGuid().ToByteArray()) $gameId.ToByteArray() `
        ([byte[]]$buildId) $channelId `
        2 4 ($now - 60) $validExpiry $signingKeyId
    $rollbackPolicyPath = Join-Path $output 'OAC-Policy-Rollback.bin'
    Write-SignedRecord `
        $rollbackPolicy $rollbackPolicyPath "$rollbackPolicyPath.p7s" $certificate
    $policyFixtures.Add($rollbackPolicyPath)
    $policyFixtures.Add("$rollbackPolicyPath.p7s")

    $authorizedRollbackPolicy = New-SignedPolicyBytes `
        ([Guid]::NewGuid().ToByteArray()) $gameId.ToByteArray() `
        ([byte[]]$buildId) $channelId `
        2 4 ($now - 60) $validExpiry $signingKeyId 2 0 3 `
        (Get-Sha256Bytes $validPolicy)
    $authorizedRollbackPath =
        Join-Path $output 'OAC-Policy-Authorized-Rollback.bin'
    Write-SignedRecord `
        $authorizedRollbackPolicy $authorizedRollbackPath `
        "$authorizedRollbackPath.p7s" $certificate
    $policyFixtures.Add($authorizedRollbackPath)
    $policyFixtures.Add("$authorizedRollbackPath.p7s")

    $emergencyPolicy = New-SignedPolicyBytes `
        ([Guid]::NewGuid().ToByteArray()) $gameId.ToByteArray() `
        ([byte[]]$buildId) $channelId `
        4 5 ($now - 60) $validExpiry $signingKeyId 1 3
    $emergencyPolicyPath = Join-Path $output 'OAC-Policy-Emergency-Revoke.bin'
    Write-SignedRecord `
        $emergencyPolicy $emergencyPolicyPath `
        "$emergencyPolicyPath.p7s" $certificate
    $policyFixtures.Add($emergencyPolicyPath)
    $policyFixtures.Add("$emergencyPolicyPath.p7s")

    $wrongSignaturePath = Join-Path $output 'OAC-Policy-Wrong-Signature.bin'
    $wrongSignatureFile = "$wrongSignaturePath.p7s"
    [IO.File]::WriteAllBytes($wrongSignaturePath, $validPolicy)
    [IO.File]::WriteAllBytes(
        $wrongSignatureFile,
        [IO.File]::ReadAllBytes("$wrongScopePath.p7s"))
    $policyFixtures.Add($wrongSignaturePath)
    $policyFixtures.Add($wrongSignatureFile)

    $finalSourceCommit = Get-CleanSourceCommit $repoRoot
    if ($finalSourceCommit -cne $sourceCommit) {
        throw 'The source commit changed while the package was being signed.'
    }

    $files = Get-ChildItem -LiteralPath $package -File | Sort-Object Name | ForEach-Object {
        [ordered]@{
            name = $_.Name
            bytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
    }
    $testFiles = @($protocolTestOutput, $protocolUnitOutput) +
        @($manifestFixtures) + @($policyFixtures) | ForEach-Object {
        $item = Get-Item -LiteralPath $_
        [ordered]@{
            name = $item.Name
            bytes = $item.Length
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        }
    }
    $manifest = [ordered]@{
        schema = 1
        purpose = 'OAC disposable-VM test package; never production'
        created_utc = [DateTime]::UtcNow.ToString('o')
        source_commit = $sourceCommit
        configuration = $Configuration
        protocol_version = '0x00050006'
        legacy_protocol_version = '0x00040000'
        certificate_subject = $certificate.Subject
        certificate_thumbprint = $certificateThumbprint
        certificate_not_after_utc = $certificate.NotAfter.ToUniversalTime().ToString('o')
        files = @($files)
        test_files = $testFiles
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText(
        (Join-Path $output 'package-manifest.json'),
        $manifestJson,
        [Text.UTF8Encoding]::new($false))

} catch {
    $packageError = $_
    throw
} finally {
    if ($certificate) {
        $cleanupErrors = [Collections.Generic.List[string]]::new()
        $stores = @(
            [pscustomobject]@{
                Name = 'CA'
                DeletePrivateKey = $false
            })
        if (-not $KeepCertificateInCurrentUserStore) {
            $stores += [pscustomobject]@{
                Name = 'My'
                DeletePrivateKey = $true
            }
        }
        foreach ($storeToClean in $stores) {
            try {
                Remove-CurrentUserCertificate `
                    $storeToClean.Name `
                    $certificateThumbprint `
                    -DeletePrivateKey:$storeToClean.DeletePrivateKey
            } catch {
                $cleanupErrors.Add(
                    "CurrentUser\$($storeToClean.Name)`: $($_.Exception.Message)")
            }
        }
        try {
            $certificate.Dispose()
        } catch {
            $cleanupErrors.Add("Certificate handle: $($_.Exception.Message)")
        }
        if ($cleanupErrors.Count -ne 0) {
            $cleanupMessage = 'Test certificate cleanup failed: ' +
                [string]::Join('; ', $cleanupErrors)
            if ($packageError) {
                try {
                    [Console]::Error.WriteLine($cleanupMessage)
                } catch {
                }
            } else {
                throw $cleanupMessage
            }
        }
    }
}

Write-Host "Test package created: $output"
Write-Host 'The certificate is self-signed, expires in 30 days, and is only for a disposable VM.'
if ($KeepCertificateInCurrentUserStore) {
    Write-Host 'The exact CurrentUser\My certificate and private key were retained by request; the incidental CurrentUser\CA copy was removed.'
} else {
    Write-Host 'The temporary CurrentUser\My certificate and private key, plus the incidental CurrentUser\CA copy, were removed.'
}
if (-not $ExportPrivateKey) {
    Write-Host 'No private-key file was exported.'
}
