[CmdletBinding()]
param(
    [string]$BuildDirectory,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [switch]$ValidateOnly,

    [switch]$DevelopmentBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Git([string[]]$Arguments) {
    $output = @(& git.exe @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Git failed: $($output -join [Environment]::NewLine)"
    }
    return @($output)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-Sha1([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToUpperInvariant()
}

function ConvertTo-CanonicalJson([object]$Value) {
    $json = $Value | ConvertTo-Json -Depth 24 -Compress
    return ($json.Replace("`r`n", "`n").TrimEnd("`r", "`n") + "`n")
}

function Write-Utf8File([string]$Path, [string]$Text) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $parent)
    }
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($Path, $Text, $encoding)
}

function Copy-ReleaseFile([string]$Source, [string]$Destination) {
    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $parent)
    }
    [IO.File]::Copy($Source, $Destination, $false)
    [IO.File]::SetAttributes($Destination, [IO.FileAttributes]::Normal)
}

function Assert-OutsideRepository([string]$Path, [string]$RepositoryRoot) {
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
    if ($fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith(
            $fullRoot + '\',
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Release output must be outside the repository.'
    }
}

function Get-SourceState([string]$RepositoryRoot, [switch]$Development) {
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        throw 'Git is required to bind release metadata to source.'
    }
    $commitOutput = @(Invoke-Git @(
            '-C', $RepositoryRoot, 'rev-parse', '--verify', 'HEAD^{commit}'))
    $commit = [string]$commitOutput[0]
    if ($commit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'Git returned a noncanonical source commit.'
    }
    $status = @(Invoke-Git @(
            '-C', $RepositoryRoot, 'status', '--porcelain=v1',
            '--untracked-files=all', '--ignore-submodules=none'))
    $clean = $status.Count -eq 0
    if (-not $clean -and -not $Development) {
        throw 'A release candidate requires a clean worktree.'
    }
    if ($Development -and -not [string]::IsNullOrEmpty($env:CI)) {
        throw 'Development release candidates are forbidden in CI.'
    }
    $epochOutput = @(Invoke-Git @(
            '-C', $RepositoryRoot, 'show', '-s', '--format=%ct', $commit))
    $epochText = [string]$epochOutput[0]
    [int64]$epoch = 0
    if (-not [int64]::TryParse(
            $epochText,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$epoch) -or $epoch -le 0) {
        throw 'Git returned an invalid source timestamp.'
    }
    $timestamp = [DateTimeOffset]::FromUnixTimeSeconds($epoch).
        ToUniversalTime().ToString(
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture)
    return [pscustomobject]@{
        Commit = $commit
        Epoch = $epoch
        Timestamp = $timestamp
        Clean = $clean
    }
}

function Get-VisualStudioRoot {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} `
        'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'Visual Studio Installer discovery is unavailable.'
    }
    $installation = @(& $vswhere -latest -products * `
        -requires Microsoft.Component.MSBuild -property installationPath)
    if ($LASTEXITCODE -ne 0 -or $installation.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$installation[0])) {
        throw 'Visual Studio 2022 could not be resolved.'
    }
    return [IO.Path]::GetFullPath([string]$installation[0])
}

function Get-VisualStudioTool([string]$VisualStudioRoot, [string]$Name) {
    if ($Name -ceq 'MSBuild.exe') {
        $candidate = Join-Path $VisualStudioRoot `
            'MSBuild\Current\Bin\amd64\MSBuild.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
        throw 'The x64 MSBuild host is unavailable.'
    }
    $toolsRoot = Join-Path $VisualStudioRoot 'VC\Tools\MSVC'
    $versions = @(Get-ChildItem -LiteralPath $toolsRoot -Directory |
        Where-Object { $_.Name -match '^[0-9]+(?:\.[0-9]+){2,3}$' } |
        Sort-Object { [version]$_.Name } -Descending)
    foreach ($version in $versions) {
        $candidate = Join-Path $version.FullName `
            (Join-Path 'bin\Hostx64\x64' $Name)
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    throw "$Name is unavailable in the x64 Visual C++ toolchain."
}

function Get-FileVersion([string]$Path) {
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "A file version is unavailable for $Path."
    }
    return $version
}

function Get-CodeViewRecord(
    [string]$Dumpbin,
    [string]$BinaryPath,
    [string]$ExpectedPdbPath,
    [string]$BuildRoot
) {
    $headerOutput = @(& $Dumpbin /headers $BinaryPath 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "DUMPBIN could not read $BinaryPath."
    }
    $records = [Collections.Generic.List[object]]::new()
    foreach ($line in $headerOutput) {
        $match = [regex]::Match(
            [string]$line,
            'Format:\s*RSDS,\s*\{(?<guid>[0-9A-Fa-f-]{36})\},\s*' +
            '(?<age>[0-9]+),\s*(?<path>.+\.pdb)\s*$')
        if ($match.Success) {
            $records.Add([pscustomobject]@{
                    Guid = $match.Groups['guid'].Value.ToUpperInvariant()
                    Age = [int64]$match.Groups['age'].Value
                    Path = $match.Groups['path'].Value
                })
        }
    }
    if ($records.Count -ne 1) {
        throw "$BinaryPath must contain exactly one RSDS CodeView record."
    }
    $record = $records[0]
    $expectedLeaf = [IO.Path]::GetFileName($ExpectedPdbPath)
    if ([IO.Path]::GetFileName($record.Path) -cne $record.Path -or
        $record.Path -cne $expectedLeaf) {
        throw "$BinaryPath exposes a noncanonical PDB path: $($record.Path)"
    }

    Push-Location $BuildRoot
    try {
        $pathOutput = @(& $Dumpbin /PDBPATH:VERBOSE $BinaryPath 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "DUMPBIN could not verify symbols for $BinaryPath."
        }
    } finally {
        Pop-Location
    }
    $found = @($pathOutput | ForEach-Object {
            $match = [regex]::Match(
                [string]$_,
                "PDB file found at '(?<path>[^']+)'" )
            if ($match.Success) { $match.Groups['path'].Value }
        })
    if ($found.Count -ne 1 -or
        -not [IO.Path]::GetFullPath($found[0]).Equals(
            [IO.Path]::GetFullPath($ExpectedPdbPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$ExpectedPdbPath does not match $BinaryPath."
    }
    return $record
}

function New-ArtifactRecord(
    [string]$Component,
    [string]$Source,
    [string]$Target
) {
    $item = Get-Item -LiteralPath $Source -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Release input is not a direct file: $Source"
    }
    return [pscustomobject]@{
        Component = $Component
        Source = $Source
        Target = $Target
        Size = [int64]$item.Length
        Sha256 = Get-Sha256 $Source
        Sha1 = Get-Sha1 $Source
    }
}

function Get-SafeTree([string]$RootPath) {
    $rootItem = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The release-candidate root is unsafe.'
    }
    $directories = [Collections.Generic.List[string]]::new()
    $files = [Collections.Generic.List[string]]::new()
    $pending = [Collections.Generic.Queue[IO.DirectoryInfo]]::new()
    $pending.Enqueue($rootItem)
    $prefixLength = $rootItem.FullName.TrimEnd('\').Length + 1
    while ($pending.Count -ne 0) {
        $directory = $pending.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory.FullName -Force)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Release candidate contains a reparse point: $($item.FullName)"
            }
            $relative = $item.FullName.Substring($prefixLength).Replace('\', '/')
            if ($item.PSIsContainer) {
                $directories.Add($relative)
                $pending.Enqueue($item)
            } else {
                $streams = @(Get-Item -LiteralPath $item.FullName -Stream * |
                    Where-Object { $_.Stream -cne ':$DATA' })
                if ($streams.Count -ne 0) {
                    throw "Release candidate contains an alternate data stream: $relative"
                }
                $files.Add($relative)
            }
        }
    }
    return [pscustomobject]@{
        Directories = @($directories)
        Files = @($files)
    }
}

function Assert-ExactStrings(
    [string[]]$Actual,
    [string[]]$Expected,
    [string]$Context
) {
    $actualSet = @($Actual | Sort-Object -CaseSensitive)
    $expectedSet = @($Expected | Sort-Object -CaseSensitive)
    if ($actualSet.Count -ne $expectedSet.Count -or
        [string]::Join("`n", $actualSet) -cne
        [string]::Join("`n", $expectedSet)) {
        throw "$Context differs from the exact release contract."
    }
}

function Get-SpdxFileType([string]$Path) {
    $extension = [IO.Path]::GetExtension($Path)
    if ($extension -ieq '.inf') { return 'SOURCE' }
    if ($extension -ieq '.txt') { return 'TEXT' }
    return 'BINARY'
}

function New-SpdxDocument(
    [object]$Profile,
    [object]$SourceState,
    [object[]]$Artifacts
) {
    $sha1Values = @($Artifacts | ForEach-Object { $_.Sha1.ToLowerInvariant() } |
        Sort-Object -CaseSensitive)
    $verificationInput = [Text.Encoding]::ASCII.GetBytes(
        [string]::Join('', $sha1Values))
    $sha1 = [Security.Cryptography.SHA1]::Create()
    try {
        $verificationCode = [BitConverter]::ToString(
            $sha1.ComputeHash($verificationInput)).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha1.Dispose()
    }

    $spdxFiles = [Collections.Generic.List[object]]::new()
    $relationships = [Collections.Generic.List[object]]::new()
    $relationships.Add([ordered]@{
            spdxElementId = 'SPDXRef-DOCUMENT'
            relationshipType = 'DESCRIBES'
            relatedSpdxElement = 'SPDXRef-Package-OAC'
        })
    foreach ($artifact in $Artifacts) {
        $identifier = 'SPDXRef-File-' +
            ([regex]::Replace($artifact.Component, '[^A-Za-z0-9.-]', '-'))
        $spdxFiles.Add([ordered]@{
                fileName = './' + $artifact.Target
                SPDXID = $identifier
                checksums = @([ordered]@{
                        algorithm = 'SHA256'
                        checksumValue = $artifact.Sha256.ToLowerInvariant()
                    })
                fileTypes = @(Get-SpdxFileType $artifact.Target)
                licenseConcluded = 'Apache-2.0'
                licenseInfoInFiles = @('NOASSERTION')
                copyrightText = 'NOASSERTION'
            })
        $relationships.Add([ordered]@{
                spdxElementId = 'SPDXRef-Package-OAC'
                relationshipType = 'CONTAINS'
                relatedSpdxElement = $identifier
            })
    }
    return [ordered]@{
        spdxVersion = 'SPDX-2.3'
        dataLicense = 'CC0-1.0'
        SPDXID = 'SPDXRef-DOCUMENT'
        name = "OAC-$($Profile.release)-unsigned-candidate"
        documentNamespace =
            "$($Profile.repository)/spdx/$($Profile.release)/$($SourceState.Commit)"
        creationInfo = [ordered]@{
            created = $SourceState.Timestamp
            creators = @('Tool: OAC release candidate generator')
            comment = 'Creation time is normalized to the source commit time for deterministic output.'
        }
        packages = @([ordered]@{
                name = 'OAC'
                SPDXID = 'SPDXRef-Package-OAC'
                versionInfo = [string]$Profile.release
                supplier = 'Organization: OAC project'
                downloadLocation = 'NOASSERTION'
                filesAnalyzed = $true
                packageVerificationCode = [ordered]@{
                    packageVerificationCodeValue = $verificationCode
                }
                licenseConcluded = 'Apache-2.0'
                licenseDeclared = 'Apache-2.0'
                licenseInfoFromFiles = @('Apache-2.0')
                copyrightText = 'NOASSERTION'
                homepage = [string]$Profile.repository
                summary = 'Defensive Windows anti-cheat research platform.'
            })
        files = @($spdxFiles)
        relationships = @($relationships)
    }
}

function New-ChecksumText([string]$RootPath, [string[]]$RelativePaths) {
    $orderedPaths = @($RelativePaths | Sort-Object -CaseSensitive)
    $lines = @($orderedPaths | ForEach-Object {
            $nativePath = $_.Replace('/', [IO.Path]::DirectorySeparatorChar)
            "$(Get-Sha256 (Join-Path $RootPath $nativePath))  $_"
        })
    return ([string]::Join("`n", $lines) + "`n")
}

function Assert-ExactFile([string]$Path, [string]$ExpectedText) {
    $actualBytes = [IO.File]::ReadAllBytes($Path)
    $expectedBytes = [Text.UTF8Encoding]::new($false).GetBytes($ExpectedText)
    if ($actualBytes.Length -ne $expectedBytes.Length) {
        throw "Release metadata length mismatch: $Path"
    }
    for ($index = 0; $index -lt $actualBytes.Length; $index++) {
        if ($actualBytes[$index] -ne $expectedBytes[$index]) {
            throw "Release metadata content mismatch: $Path"
        }
    }
}

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
    $BuildDirectory = Join-Path $root 'x64\Release'
}
$buildRoot = [IO.Path]::GetFullPath($BuildDirectory)
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
Assert-OutsideRepository $outputRoot $root
if (-not (Test-Path -LiteralPath $buildRoot -PathType Container)) {
    throw 'The Release build directory is missing.'
}

$profile = & (Join-Path $PSScriptRoot 'Test-OACReleaseProfile.ps1') -PassThru
$sourceState = Get-SourceState $root -Development:$DevelopmentBuild
$visualStudioRoot = Get-VisualStudioRoot
$msbuild = Get-VisualStudioTool $visualStudioRoot 'MSBuild.exe'
$compiler = Get-VisualStudioTool $visualStudioRoot 'cl.exe'
$linker = Get-VisualStudioTool $visualStudioRoot 'link.exe'
$dumpbin = Get-VisualStudioTool $visualStudioRoot 'dumpbin.exe'

$publicArtifacts = [Collections.Generic.List[object]]::new()
$symbolRecords = [Collections.Generic.List[object]]::new()
foreach ($definition in @($profile.public_artifacts)) {
    $sourcePath = Join-Path $buildRoot `
        ([string]$definition.source).Replace('/', '\')
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Release artifact is missing: $($definition.source)"
    }
    $artifact = New-ArtifactRecord `
        ([string]$definition.component) $sourcePath ([string]$definition.target)
    if (-not $DevelopmentBuild -and
        (Get-Item -LiteralPath $sourcePath).LastWriteTimeUtc -lt
        [DateTimeOffset]::FromUnixTimeSeconds($sourceState.Epoch).UtcDateTime) {
        throw "Release artifact predates the source commit: $($definition.source)"
    }
    if ([IO.Path]::GetExtension($sourcePath) -in @('.exe', '.sys', '.cat')) {
        $signature = Get-AuthenticodeSignature -LiteralPath $sourcePath
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::NotSigned) {
            throw "Unsigned candidate contains a signed artifact: $($definition.source)"
        }
    }
    if ([IO.Path]::GetExtension($sourcePath) -in @('.exe', '.sys')) {
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($sourcePath)
        if ($version.FileVersion -cne [string]$profile.driver_version -or
            $version.ProductVersion -cne [string]$profile.driver_version -or
            $version.ProductName -cne 'OAC' -or
            $version.OriginalFilename -cne
                [IO.Path]::GetFileName([string]$definition.target) -or
            [string]::IsNullOrWhiteSpace($version.FileDescription)) {
            throw "Release artifact has invalid embedded version metadata: $($definition.source)"
        }
    }
    $publicArtifacts.Add($artifact)

    if ($null -ne $definition.symbol) {
        $pdbPath = Join-Path $buildRoot ([string]$definition.symbol)
        if (-not (Test-Path -LiteralPath $pdbPath -PathType Leaf)) {
            throw "Release symbol is missing: $($definition.symbol)"
        }
        $codeView = Get-CodeViewRecord `
            $dumpbin $sourcePath $pdbPath $buildRoot
        $symbolRecords.Add([pscustomobject]@{
                Component = [string]$definition.component
                BinaryPath = [string]$definition.target
                Source = $pdbPath
                Target = [string]$definition.symbol
                Size = [int64](Get-Item -LiteralPath $pdbPath).Length
                Sha256 = Get-Sha256 $pdbPath
                CodeViewGuid = $codeView.Guid
                CodeViewAge = $codeView.Age
            })
    }
}

$licensePath = Join-Path $root 'LICENSE'
$licenseRecord = New-ArtifactRecord 'license' $licensePath 'LICENSE.txt'
$publicArtifacts.Add($licenseRecord)

$labArtifacts = [Collections.Generic.List[object]]::new()
foreach ($definition in @($profile.lab_artifacts)) {
    $sourcePath = Join-Path $buildRoot `
        ([string]$definition.source).Replace('/', '\')
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Lab artifact is missing: $($definition.source)"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $sourcePath
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::NotSigned) {
        throw "Lab bundle contains a signed artifact: $($definition.source)"
    }
    $labPdbPath = Join-Path $buildRoot `
        ([IO.Path]::ChangeExtension([string]$definition.source, '.pdb'))
    if (-not (Test-Path -LiteralPath $labPdbPath -PathType Leaf)) {
        throw "Lab build symbol is missing: $($definition.source)"
    }
    [void](Get-CodeViewRecord $dumpbin $sourcePath $labPdbPath $buildRoot)
    $labArtifacts.Add((New-ArtifactRecord `
            ([string]$definition.component) $sourcePath ([string]$definition.target)))
}

$buildMetadata = [ordered]@{
    configuration = [string]$profile.configuration
    platform = [string]$profile.platform
    windows_sdk = [string]$profile.windows_sdk
    msbuild = Get-FileVersion $msbuild
    compiler = Get-FileVersion $compiler
    linker = Get-FileVersion $linker
}
$manifestArtifacts = @($publicArtifacts | ForEach-Object {
        [ordered]@{
            component = $_.Component
            path = $_.Target
            size = $_.Size
            sha256 = $_.Sha256
        }
    })
$releaseManifest = [ordered]@{
    schema = 1
    candidate = if ($DevelopmentBuild) {
        'development-unsigned'
    } else {
        'production-unsigned'
    }
    release = [string]$profile.release
    driver_version = [string]$profile.driver_version
    source = [ordered]@{
        repository = [string]$profile.repository
        commit = $sourceState.Commit
        commit_time_utc = $sourceState.Timestamp
        clean = $sourceState.Clean
    }
    build = $buildMetadata
    compatibility = [ordered]@{
        production_protocol = [string]$profile.compatibility.production_protocol
        diagnostic_protocol = [string]$profile.compatibility.diagnostic_protocol
        launcher_ipc = [string]$profile.compatibility.launcher_ipc
        backend_protocol = [string]$profile.compatibility.backend_protocol
        manifest_schema = [int64]$profile.compatibility.manifest_schema
        signed_policy_schema = [int64]$profile.compatibility.signed_policy_schema
        game_event_schema = [int64]$profile.compatibility.game_event_schema
    }
    artifacts = $manifestArtifacts
    sbom = 'sbom.spdx.json'
    private_symbols_retained_separately = $true
}
$symbolsManifest = [ordered]@{
    schema = 1
    release = [string]$profile.release
    source_commit = $sourceState.Commit
    visibility = 'private'
    symbols = @($symbolRecords | ForEach-Object {
            [ordered]@{
                component = $_.Component
                binary = $_.BinaryPath
                path = $_.Target
                size = $_.Size
                sha256 = $_.Sha256
                codeview_guid = $_.CodeViewGuid
                codeview_age = $_.CodeViewAge
            }
        })
}
$labNotice = @'
OAC LAB TOOLS - NOT FOR PRODUCTION

These unsigned executables are diagnostic and test tools. They are not part of
the production candidate and must be used only in an isolated disposable VM.
'@.Replace("`r`n", "`n").TrimEnd("`r", "`n") + "`n"
$labManifest = [ordered]@{
    schema = 1
    release = [string]$profile.release
    source_commit = $sourceState.Commit
    purpose = 'isolated-lab-testing-only'
    artifacts = @($labArtifacts | ForEach-Object {
            [ordered]@{
                component = $_.Component
                path = $_.Target
                size = $_.Size
                sha256 = $_.Sha256
            }
        })
}
$releaseManifestText = ConvertTo-CanonicalJson $releaseManifest
$spdxText = ConvertTo-CanonicalJson `
    (New-SpdxDocument $profile $sourceState @($publicArtifacts))
$symbolsManifestText = ConvertTo-CanonicalJson $symbolsManifest
$labManifestText = ConvertTo-CanonicalJson $labManifest

$publicPayloadPaths = @($publicArtifacts | ForEach-Object { $_.Target })
$publicMetadataPaths = @('release-manifest.json', 'sbom.spdx.json')
$symbolPayloadPaths = @($symbolRecords | ForEach-Object { $_.Target })
$labPayloadPaths = @($labArtifacts | ForEach-Object { $_.Target }) +
    @('LAB-ONLY.txt', 'lab-manifest.json')
$expectedFiles =
    @($publicPayloadPaths | ForEach-Object { 'public/' + $_ }) +
    @(
        'public/release-manifest.json'
        'public/sbom.spdx.json'
        'public/SHA256SUMS'
    ) +
    @($symbolPayloadPaths | ForEach-Object { 'symbols/' + $_ }) +
    @(
        'symbols/symbols-manifest.json'
        'symbols/SHA256SUMS'
    ) +
    @($labPayloadPaths | ForEach-Object { 'lab/' + $_ }) +
    @('lab/SHA256SUMS')
$expectedDirectories = @('public', 'public/driver', 'symbols', 'lab')

if (-not $ValidateOnly) {
    if (Test-Path -LiteralPath $outputRoot) {
        throw 'The release-candidate output already exists.'
    }
    $outputParent = Split-Path -Parent $outputRoot
    if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $outputParent)
    }
    $stagingRoot = Join-Path $outputParent `
        ('.oac-release-' + [Guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -ItemType Directory -Path $stagingRoot)
        foreach ($artifact in $publicArtifacts) {
            Copy-ReleaseFile $artifact.Source `
                (Join-Path $stagingRoot ('public\' + $artifact.Target.Replace('/', '\')))
        }
        foreach ($symbol in $symbolRecords) {
            Copy-ReleaseFile $symbol.Source `
                (Join-Path $stagingRoot ('symbols\' + $symbol.Target))
        }
        foreach ($artifact in $labArtifacts) {
            Copy-ReleaseFile $artifact.Source `
                (Join-Path $stagingRoot ('lab\' + $artifact.Target.Replace('/', '\')))
        }
        Write-Utf8File (Join-Path $stagingRoot 'public\release-manifest.json') `
            $releaseManifestText
        Write-Utf8File (Join-Path $stagingRoot 'public\sbom.spdx.json') $spdxText
        Write-Utf8File (Join-Path $stagingRoot 'symbols\symbols-manifest.json') `
            $symbolsManifestText
        Write-Utf8File (Join-Path $stagingRoot 'lab\LAB-ONLY.txt') $labNotice
        Write-Utf8File (Join-Path $stagingRoot 'lab\lab-manifest.json') `
            $labManifestText

        Write-Utf8File (Join-Path $stagingRoot 'public\SHA256SUMS') `
            (New-ChecksumText (Join-Path $stagingRoot 'public') `
                ($publicPayloadPaths + $publicMetadataPaths))
        Write-Utf8File (Join-Path $stagingRoot 'symbols\SHA256SUMS') `
            (New-ChecksumText (Join-Path $stagingRoot 'symbols') `
                ($symbolPayloadPaths + @('symbols-manifest.json')))
        Write-Utf8File (Join-Path $stagingRoot 'lab\SHA256SUMS') `
            (New-ChecksumText (Join-Path $stagingRoot 'lab') $labPayloadPaths)
        [IO.Directory]::Move($stagingRoot, $outputRoot)
    } finally {
        if ($null -ne $stagingRoot -and
            (Test-Path -LiteralPath $stagingRoot -PathType Container)) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
    }
}

if (-not (Test-Path -LiteralPath $outputRoot -PathType Container)) {
    throw 'The release-candidate output is missing.'
}
$tree = Get-SafeTree $outputRoot
Assert-ExactStrings $tree.Directories $expectedDirectories 'Release directories'
Assert-ExactStrings $tree.Files $expectedFiles 'Release files'

foreach ($artifact in $publicArtifacts) {
    $path = Join-Path $outputRoot `
        ('public\' + $artifact.Target.Replace('/', '\'))
    if ((Get-Item -LiteralPath $path).Length -ne $artifact.Size -or
        (Get-Sha256 $path) -cne $artifact.Sha256) {
        throw "Public release artifact does not match its build input: $($artifact.Target)"
    }
}
foreach ($symbol in $symbolRecords) {
    $path = Join-Path $outputRoot ('symbols\' + $symbol.Target)
    if ((Get-Item -LiteralPath $path).Length -ne $symbol.Size -or
        (Get-Sha256 $path) -cne $symbol.Sha256) {
        throw "Private symbol does not match its build input: $($symbol.Target)"
    }
}
foreach ($artifact in $labArtifacts) {
    $path = Join-Path $outputRoot `
        ('lab\' + $artifact.Target.Replace('/', '\'))
    if ((Get-Item -LiteralPath $path).Length -ne $artifact.Size -or
        (Get-Sha256 $path) -cne $artifact.Sha256) {
        throw "Lab artifact does not match its build input: $($artifact.Target)"
    }
}

Assert-ExactFile (Join-Path $outputRoot 'public\release-manifest.json') `
    $releaseManifestText
Assert-ExactFile (Join-Path $outputRoot 'public\sbom.spdx.json') $spdxText
Assert-ExactFile (Join-Path $outputRoot 'symbols\symbols-manifest.json') `
    $symbolsManifestText
Assert-ExactFile (Join-Path $outputRoot 'lab\LAB-ONLY.txt') $labNotice
Assert-ExactFile (Join-Path $outputRoot 'lab\lab-manifest.json') $labManifestText
Assert-ExactFile (Join-Path $outputRoot 'public\SHA256SUMS') `
    (New-ChecksumText (Join-Path $outputRoot 'public') `
        ($publicPayloadPaths + $publicMetadataPaths))
Assert-ExactFile (Join-Path $outputRoot 'symbols\SHA256SUMS') `
    (New-ChecksumText (Join-Path $outputRoot 'symbols') `
        ($symbolPayloadPaths + @('symbols-manifest.json')))
Assert-ExactFile (Join-Path $outputRoot 'lab\SHA256SUMS') `
    (New-ChecksumText (Join-Path $outputRoot 'lab') $labPayloadPaths)

Write-Host "Release candidate validation passed for OAC $($profile.release)."
