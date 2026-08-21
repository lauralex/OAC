[CmdletBinding()]
param(
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-ExactProperties(
    [object]$Value,
    [string[]]$Names,
    [string]$Context
) {
    if ($null -eq $Value) {
        throw "$Context is missing."
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if ($actual.Count -ne $expected.Count -or
        [string]::Join("`n", $actual) -cne [string]::Join("`n", $expected)) {
        throw "$Context has unexpected properties: $($actual -join ', ')."
    }
}

function Assert-RelativeReleasePath([string]$Path, [string]$Context) {
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path -cne $Path.Trim() -or
        [IO.Path]::IsPathRooted($Path) -or
        $Path.Contains('\') -or
        $Path.Contains(':')) {
        throw "$Context is not a canonical relative path."
    }
    $parts = @($Path.Split('/'))
    if ($parts.Count -eq 0 -or
        @($parts | Where-Object {
                [string]::IsNullOrWhiteSpace($_) -or $_ -ceq '.' -or $_ -ceq '..'
            }).Count -ne 0) {
        throw "$Context contains an unsafe path segment."
    }
}

function Get-NumericMacro(
    [string]$FilePath,
    [string]$Name,
    [switch]$Hex
) {
    $text = Get-Content -LiteralPath $FilePath -Raw
    $pattern = '(?m)^\s*#define\s+' + [regex]::Escape($Name) +
        '\s+(?<value>0x[0-9A-Fa-f]+|[0-9]+)(?:[uUlL]+)?\s*$'
    $matches = [regex]::Matches($text, $pattern)
    if ($matches.Count -ne 1) {
        throw "$Name must have one direct numeric definition in $FilePath."
    }
    $literal = $matches[0].Groups['value'].Value
    if ($literal.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
        $number = [Convert]::ToUInt32($literal.Substring(2), 16)
    } else {
        $number = [Convert]::ToUInt32($literal, 10)
    }
    if ($Hex) {
        return '0x{0:X8}' -f $number
    }
    return [int64]$number
}

function Assert-ArtifactList(
    [object[]]$Actual,
    [object[]]$Expected,
    [switch]$Symbols
) {
    if ($Actual.Count -ne $Expected.Count) {
        throw "The release profile contains an unexpected artifact count."
    }
    $sourceNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $targetNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    for ($index = 0; $index -lt $Actual.Count; $index++) {
        $artifact = $Actual[$index]
        $properties = @('component', 'source', 'target')
        if ($Symbols) { $properties += 'symbol' }
        Assert-ExactProperties $artifact $properties "release artifact $index"
        Assert-RelativeReleasePath ([string]$artifact.source) `
            "release artifact $index source"
        Assert-RelativeReleasePath ([string]$artifact.target) `
            "release artifact $index target"
        if (-not $sourceNames.Add([string]$artifact.source) -or
            -not $targetNames.Add([string]$artifact.target)) {
            throw 'Release artifact paths must be unique without regard to case.'
        }

        $expectedArtifact = $Expected[$index]
        foreach ($property in $properties) {
            $actualValue = $artifact.$property
            $expectedValue = $expectedArtifact.$property
            if ($null -eq $expectedValue) {
                if ($null -ne $actualValue) {
                    throw "Release artifact $index has an unexpected $property."
                }
            } elseif ([string]$actualValue -cne [string]$expectedValue) {
                throw "Release artifact $index has an unexpected $property."
            }
        }

        if ($Symbols -and $null -ne $artifact.symbol) {
            $symbol = [string]$artifact.symbol
            Assert-RelativeReleasePath $symbol "release artifact $index symbol"
            if ([IO.Path]::GetFileName($symbol) -cne $symbol -or
                -not $symbol.EndsWith('.pdb', [StringComparison]::OrdinalIgnoreCase)) {
                throw "Release artifact $index has an invalid symbol name."
            }
        }
    }
}

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$profilePath = Join-Path $root 'config\release-profile.json'
if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
    throw 'The release profile is missing.'
}
$rawProfile = Get-Content -LiteralPath $profilePath -Raw

# The checked-in profile uses one simple property per line. Counting those
# names before parsing makes duplicate keys fail closed in Windows PowerShell,
# whose ConvertFrom-Json otherwise retains only the last duplicate.
$propertyNames = @([regex]::Matches(
        $rawProfile,
        '(?m)^\s*"(?<name>[a-z_]+)"\s*:') |
    ForEach-Object { $_.Groups['name'].Value })
$expectedPropertyCounts = [ordered]@{
    schema = 1
    release = 1
    configuration = 1
    platform = 1
    windows_sdk = 1
    driver_version = 1
    repository = 1
    compatibility = 1
    production_protocol = 1
    diagnostic_protocol = 1
    launcher_ipc = 1
    backend_protocol = 1
    manifest_schema = 1
    signed_policy_schema = 1
    game_event_schema = 1
    public_artifacts = 1
    lab_artifacts = 1
    component = 8
    source = 8
    target = 8
    symbol = 5
}
foreach ($entry in $expectedPropertyCounts.GetEnumerator()) {
    if (@($propertyNames | Where-Object { $_ -ceq $entry.Key }).Count -ne
        $entry.Value) {
        throw "The release profile has an unexpected $($entry.Key) property count."
    }
}
if (@($propertyNames | Where-Object {
            -not $expectedPropertyCounts.Contains($_)
        }).Count -ne 0) {
    throw 'The release profile contains an unknown property name.'
}

try {
    $profile = $rawProfile | ConvertFrom-Json
} catch {
    throw "The release profile is not valid JSON: $($_.Exception.Message)"
}
Assert-ExactProperties $profile @(
    'schema', 'release', 'configuration', 'platform', 'windows_sdk',
    'driver_version', 'repository', 'compatibility', 'public_artifacts',
    'lab_artifacts') 'release profile'
Assert-ExactProperties $profile.compatibility @(
    'production_protocol', 'diagnostic_protocol', 'launcher_ipc',
    'backend_protocol', 'manifest_schema', 'signed_policy_schema',
    'game_event_schema') 'release compatibility profile'

if (-not ($profile.schema -is [int] -or $profile.schema -is [long]) -or
    $profile.schema -ne 1 -or
    [string]$profile.release -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
    [string]$profile.configuration -cne 'Release' -or
    [string]$profile.platform -cne 'x64' -or
    [string]$profile.windows_sdk -cnotmatch '^10\.0\.[0-9]+\.0$' -or
    [string]$profile.driver_version -cnotmatch '^[0-9]+(?:\.[0-9]+){3}$' -or
    [string]$profile.repository -cne 'https://github.com/lauralex/OAC') {
    throw 'The release profile identity is invalid.'
}
$driverParts = ([string]$profile.driver_version).Split('.')
$expectedRelease = [string]::Join('.', $driverParts[0..2])
if ([string]$profile.release -cne $expectedRelease) {
    throw 'The release and driver versions are inconsistent.'
}
$versionHeader = Join-Path $root 'shared\oac_version.h'
$embeddedVersion = [string]::Join('.', @(
        Get-NumericMacro $versionHeader 'OAC_RELEASE_VERSION_MAJOR'
        Get-NumericMacro $versionHeader 'OAC_RELEASE_VERSION_MINOR'
        Get-NumericMacro $versionHeader 'OAC_RELEASE_VERSION_PATCH'
        Get-NumericMacro $versionHeader 'OAC_RELEASE_VERSION_BUILD'
    ))
if ($embeddedVersion -cne [string]$profile.driver_version) {
    throw 'The embedded file version does not match the release profile.'
}

$expectedPublic = @(
    [pscustomobject]@{ component='kernel-driver'; source='OAC/OAC.sys'; target='driver/OAC.sys'; symbol='OAC.pdb' },
    [pscustomobject]@{ component='driver-setup'; source='OAC/OAC.inf'; target='driver/OAC.inf'; symbol=$null },
    [pscustomobject]@{ component='driver-catalog'; source='OAC/oac.cat'; target='driver/OAC.cat'; symbol=$null },
    [pscustomobject]@{ component='control-service'; source='OAC-Service.exe'; target='OAC-Service.exe'; symbol='OAC-Service.pdb' },
    [pscustomobject]@{ component='user-launcher'; source='OAC-Launcher.exe'; target='OAC-Launcher.exe'; symbol='OAC-Launcher.pdb' }
)
$expectedLab = @(
    [pscustomobject]@{ component='diagnostic-client'; source='OAC-Client.exe'; target='OAC-Client.exe' },
    [pscustomobject]@{ component='protocol-integration-test'; source='OAC-Protocol-Test.exe'; target='OAC-Protocol-Test.exe' },
    [pscustomobject]@{ component='driver-free-unit-test'; source='OAC-Protocol-Unit.exe'; target='OAC-Protocol-Unit.exe' }
)
Assert-ArtifactList @($profile.public_artifacts) $expectedPublic -Symbols
Assert-ArtifactList @($profile.lab_artifacts) $expectedLab

$compatibility = [ordered]@{
    production_protocol = Get-NumericMacro `
        (Join-Path $root 'shared\protocol\oac_v5.h') `
        'OAC_PRODUCTION_PROTOCOL_VERSION' -Hex
    diagnostic_protocol = Get-NumericMacro `
        (Join-Path $root 'shared\oac_protocol.h') 'OAC_PROTOCOL_VERSION' -Hex
    launcher_ipc = Get-NumericMacro `
        (Join-Path $root 'shared\oac_ipc.h') 'OAC_IPC_PROTOCOL_REVISION' -Hex
    backend_protocol = Get-NumericMacro `
        (Join-Path $root 'shared\oac_backend.h') 'OAC_BACKEND_PROTOCOL_REVISION' -Hex
    manifest_schema = Get-NumericMacro `
        (Join-Path $root 'shared\oac_manifest.h') 'OAC_MANIFEST_SCHEMA'
    signed_policy_schema = Get-NumericMacro `
        (Join-Path $root 'shared\oac_signed_policy.h') 'OAC_SIGNED_POLICY_SCHEMA'
    game_event_schema = Get-NumericMacro `
        (Join-Path $root 'shared\oac_game.h') 'OAC_GAME_SCHEMA'
}
foreach ($entry in $compatibility.GetEnumerator()) {
    if ([string]$profile.compatibility.($entry.Key) -cne [string]$entry.Value) {
        throw "Release compatibility value $($entry.Key) does not match source."
    }
}

$managedBackendSources = @(
    'OAC-backend\WireProtocol.cs',
    'OAC-backend\game-adapter\GameServerClient.cs'
)
foreach ($source in $managedBackendSources) {
    $sourceText = Get-Content -LiteralPath (Join-Path $root $source) -Raw
    $matches = @([regex]::Matches(
            $sourceText,
            '(?m)^\s*private\s+const\s+uint\s+BackendRevision\s*=\s*(?<value>0x[0-9A-Fa-f]+)\s*;\s*$|^\s*public\s+const\s+uint\s+Revision\s*=\s*(?<value>0x[0-9A-Fa-f]+)\s*;\s*$'))
    if ($matches.Count -ne 1 -or
        ('0x{0:X8}' -f [Convert]::ToUInt32(
            $matches[0].Groups['value'].Value.Substring(2), 16)) -cne
            [string]$compatibility.backend_protocol) {
        throw "$source does not match the release-profile backend protocol."
    }
}

$gameAdapterProject = Get-Content -LiteralPath `
    (Join-Path $root 'OAC-backend\game-adapter\OAC.GameAdapter.csproj') -Raw
$gameAdapterVersions = @([regex]::Matches(
        $gameAdapterProject,
        '<Version>(?<version>[0-9]+\.[0-9]+\.[0-9]+)</Version>'))
if ($gameAdapterVersions.Count -ne 1 -or
    $gameAdapterVersions[0].Groups['version'].Value -cne [string]$profile.release) {
    throw 'The game-adapter package version does not match the release profile.'
}

$infText = Get-Content -LiteralPath (Join-Path $root 'OAC\OAC.inf') -Raw
$driverVersionMatch = [regex]::Match(
    $infText,
    '(?m)^DriverVer=[0-9]{2}/[0-9]{2}/[0-9]{4},(?<version>[0-9]+(?:\.[0-9]+){3})\s*$')
if (-not $driverVersionMatch.Success -or
    $driverVersionMatch.Groups['version'].Value -cne [string]$profile.driver_version) {
    throw 'The release driver version does not match OAC.inf.'
}

$projectPaths = @(
    'OAC\OAC.vcxproj',
    'OAC-Client\OAC-Client.vcxproj',
    'OAC-Service\OAC-Service.vcxproj',
    'OAC-Launcher\OAC-Launcher.vcxproj',
    'tools\OAC-Protocol-Test.vcxproj',
    'tests\unit\OAC-Protocol-Unit.vcxproj'
)
foreach ($projectPath in $projectPaths) {
    $projectText = Get-Content -LiteralPath (Join-Path $root $projectPath) -Raw
    $versions = @([regex]::Matches(
            $projectText,
            '<WindowsTargetPlatformVersion>(?<version>[^<]+)</WindowsTargetPlatformVersion>') |
        ForEach-Object { $_.Groups['version'].Value } | Sort-Object -Unique)
    if ($versions.Count -ne 1 -or
        $versions[0] -cne [string]$profile.windows_sdk) {
        throw "$projectPath does not use the release-profile Windows SDK."
    }
}

$driverProjectText = Get-Content -LiteralPath `
    (Join-Path $root 'OAC\OAC.vcxproj') -Raw
if ([regex]::Matches(
        $driverProjectText,
        '<SpecifyDriverVerDirectiveDate>false</SpecifyDriverVerDirectiveDate>').Count -ne 1 -or
    [regex]::Matches(
        $driverProjectText,
        '<SpecifyDriverVerDirectiveVersion>false</SpecifyDriverVerDirectiveVersion>').Count -ne 1) {
    throw 'The driver build must preserve the reviewed INF version and date.'
}

$directoryTargets = Get-Content -LiteralPath `
    (Join-Path $root 'Directory.Build.targets') -Raw
if ([regex]::Matches($directoryTargets, '/PDBALTPATH:%_PDB%').Count -ne 1 -or
    $directoryTargets -notmatch
        "'\$\(Configuration\)\|\$\(Platform\)'=='Release\|x64'") {
    throw 'Release binaries must record only the PDB leaf name.'
}

if ($PassThru) {
    return $profile
}
Write-Host "Release profile validation passed for OAC $($profile.release)."
