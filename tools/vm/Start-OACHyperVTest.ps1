#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$VMName = 'OAC-Win11-24H2-Test',

    [string]$WindowsIso = 'C:\OAC-VM\inputs\win11-24h2-noprompt.iso',

    [string]$SeedIso = 'C:\OAC-VM\inputs\oac-seed.iso',

    [string]$VMRoot = 'C:\OAC-VM\vm',

    [string]$ResultDirectory = 'C:\OAC-VM\results',

    [TimeSpan]$InstallTimeout = '01:00:00',

    [TimeSpan]$BaselineTimeout = '01:00:00',

    [TimeSpan]$TestTimeout = '00:45:00'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not [Environment]::Is64BitProcess) {
    throw 'Run the Hyper-V campaign from a 64-bit elevated PowerShell host.'
}
$whoami = Join-Path $env:SystemRoot 'System32\whoami.exe'
$privilegeRows = @(& $whoami /priv /fo csv /nh)
if ($LASTEXITCODE -ne 0) {
    throw 'Could not inspect the host token privileges.'
}
$hasManageVolumePrivilege = $false
foreach ($line in $privilegeRows) {
    $row = $line | ConvertFrom-Csv -Header Name, Description, State
    if ($row.Name -ceq 'SeManageVolumePrivilege') {
        $hasManageVolumePrivilege = $true
        break
    }
}
if (-not $hasManageVolumePrivilege) {
    throw ('The host token lacks SeManageVolumePrivilege. Hyper-V Administrators membership ' +
        'alone is insufficient; run the campaign from an elevated host PowerShell.')
}

$baselineZeroTests = @(
    'baseline-install',
    'baseline-remove',
    'baseline-reinstall',
    'baseline-protocol-unit',
    'baseline-protocol',
    'baseline-preflight',
    'baseline-launch',
    'baseline-client',
    'production-launcher-1',
    'production-launcher-2',
    'production-launcher-3',
    'production-launch',
    'production-launch-graceful',
    'production-direct-open-localsystem',
    'production-direct-open-limited',
    'production-direct-open-administrator')
$verifierZeroTests = @(
    'verifier-protocol-1',
    'verifier-protocol-2',
    'verifier-protocol-3',
    'verifier-preflight',
    'verifier-launch',
    'verifier-client-1',
    'verifier-client-2')
$specialTests = [ordered]@{
    'baseline-remove-repeat-expected-refusal' = 'nonzero'
    'baseline-driver-gate-create' = @(0)
    'baseline-driver-gate-trigger' = @(0)
    'baseline-driver-gate-detection' = @(1)
    'baseline-driver-gate-stop' = @(0, 1062)
    'baseline-driver-gate-delete' = @(0)
}
$summaryNames = @(
    'baseline-driver-gate-summary',
    'production-boundary-summary',
    'removal-boundary-summary',
    'baseline-provenance-summary')
$auxiliaryExitValues = [ordered]@{
    'baseline-bcd' = @(0)
    'baseline-sc-query' = @(0)
    'baseline-protocol-boundary-stop' = @(0)
    'baseline-protocol-boundary-start' = @(0)
    'baseline-driver-gate-oac-stop' = @(0)
    'baseline-driver-gate-oac-start' = @(0)
    'production-launcher-started-service' = @(0)
    'production-service-crash' = @(0)
    'production-service-graceful-stop' = @(0)
    'production-service-post-stop-start' = @(0)
    'production-legacy-driver-start' = @(0, 1056)
    'baseline-sc-stop' = @(0, 1062)
    'baseline-target-stop' = @(0)
    'production-service-pre-stop' = @(0, 1062)
    'production-driver-pre-stop' = @(0, 1062)
    'production-service-stop' = @(0, 1062)
    'production-driver-stop' = @(0, 1062)
    'verifier-pre-reset' = @(0, 2)
    'verifier-arm' = @(0, 2)
    'verifier-armed-settings' = @(0, 2)
    'verifier-bcd' = @(0)
    'verifier-active-settings' = @(0, 2)
    'verifier-sc-start' = @(0, 1056)
    'verifier-protocol-boundary-sc-stop' = @(0)
    'verifier-protocol-boundary-sc-start' = @(0)
    'verifier-inter-client-sc-stop' = @(0)
    'verifier-inter-client-sc-start' = @(0)
    'verifier-sc-stop' = @(0, 1062)
    'verifier-target-1-stop' = @(0)
    'verifier-target-2-stop' = @(0)
    'verifier-query-after-stress' = @(0, 2)
    'verifier-reset' = @(0, 2)
    'final-bcd' = @(0)
    'final-verifier-settings' = @(0, 2)
    'final-verifier-query' = @(0, 2)
    'final-sc-query' = @(0)
    'final-service-query' = @(0)
    'final-driverquery' = @(0)
    'final-system-export' = @(0)
    'final-code-integrity-export' = @(0)
    'final-oacservice-stop' = @(0, 1062)
    'final-oac-stop' = @(0, 1062)
    'final-gate-stop' = @(0, 1062)
    'final-gate-delete' = @(0, 1060, 1072)
}
$baselineAuxiliaryRequired = @(
    'baseline-bcd',
    'baseline-sc-query',
    'baseline-protocol-boundary-stop',
    'baseline-protocol-boundary-start',
    'baseline-driver-gate-oac-stop',
    'baseline-driver-gate-oac-start',
    'production-launcher-started-service',
    'production-service-crash',
    'production-service-graceful-stop',
    'production-service-post-stop-start',
    'production-legacy-driver-start',
    'baseline-sc-stop',
    'baseline-target-stop')
$baselineAuxiliaryOptional = @(
    'production-service-pre-stop',
    'production-driver-pre-stop',
    'production-service-stop',
    'production-driver-stop')
$fullAuxiliaryRequired = @($baselineAuxiliaryRequired) + @(
    'verifier-pre-reset',
    'verifier-arm',
    'verifier-armed-settings',
    'verifier-bcd',
    'verifier-active-settings',
    'verifier-sc-start',
    'verifier-protocol-boundary-sc-stop',
    'verifier-protocol-boundary-sc-start',
    'verifier-inter-client-sc-stop',
    'verifier-inter-client-sc-start',
    'verifier-sc-stop',
    'verifier-target-1-stop',
    'verifier-target-2-stop',
    'verifier-query-after-stress',
    'verifier-reset',
    'final-bcd',
    'final-verifier-settings',
    'final-verifier-query',
    'final-sc-query',
    'final-service-query',
    'final-driverquery',
    'final-system-export',
    'final-code-integrity-export')
$fullAuxiliaryOptional = @($baselineAuxiliaryOptional) + @(
    'final-oacservice-stop',
    'final-oac-stop',
    'final-gate-stop',
    'final-gate-delete')
$script:OrchestrationStartUtc = [DateTime]::UtcNow
$script:ExpectedManifestHash = $null
$script:ExpectedSourceCommit = $null
$script:GuestCampaignId = $null
$script:GuestCampaignStartUtc = [DateTime]::MinValue
$script:BaselineCompletedUtc = [DateTime]::MinValue
$script:HostRecord = $null
$script:HostRecordPath = $null
$script:HostLog = $null
$script:VhdPath = $null
$script:GuestCredential = $null
$script:VmCreated = $false

function Write-HostLog([string]$Message) {
    $line = "[$([DateTime]::UtcNow.ToString('o'))] $Message"
    Write-Host $line
    if ($script:HostLog) {
        Add-Content -LiteralPath $script:HostLog -Value $line -Encoding UTF8
    }
}

function Write-Utf8Json([string]$Path, [object]$Value) {
    $json = ConvertTo-Json -InputObject $Value -Depth 8
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function Save-HostRecord {
    if ($null -ne $script:HostRecord -and $script:HostRecordPath) {
        Write-Utf8Json $script:HostRecordPath $script:HostRecord
    }
}

function Get-RequiredValue([object]$Value, [string]$Name, [string]$Context) {
    if ($null -eq $Value) { throw "$Context is null." }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "$Context has no $Name field." }
    return $property.Value
}

function Read-JsonText([string]$Text, [string]$Context) {
    if ([string]::IsNullOrWhiteSpace($Text)) { throw "$Context is empty." }
    try {
        return $Text | ConvertFrom-Json
    } catch {
        throw "$Context is not valid JSON: $($_.Exception.Message)"
    }
}

function Read-JsonFile([string]$Path, [string]$Context) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        throw "$Context is missing: $Path"
    }
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 1MB) {
        throw "$Context has an unsafe type or size: $Path"
    }
    return Read-JsonText ([IO.File]::ReadAllText($Path)) $Context
}

function ConvertTo-UtcTime([object]$Value, [string]$Context) {
    if ($Value -is [DateTime]) {
        $date = [DateTime]$Value
        if ($date.Kind -eq [DateTimeKind]::Unspecified) {
            throw "$Context does not include a time zone."
        }
        return $date.ToUniversalTime()
    }
    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).UtcDateTime
    }
    if ($Value -isnot [string]) {
        throw "$Context is not a round-trip timestamp."
    }
    $parsed = [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact(
            $Value,
            'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed)) {
        throw "$Context is not a round-trip timestamp."
    }
    if ($parsed.Kind -eq [DateTimeKind]::Unspecified) {
        throw "$Context does not include a time zone."
    }
    return $parsed.ToUniversalTime()
}

function Assert-ExactNames(
    [string[]]$Actual,
    [string[]]$Expected,
    [string]$Context) {
    $actualNames = @($Actual | Sort-Object -CaseSensitive -Unique)
    $expectedNames = @($Expected | Sort-Object -CaseSensitive -Unique)
    $missing = @($expectedNames | Where-Object { $actualNames -cnotcontains $_ })
    $unexpected = @($actualNames | Where-Object { $expectedNames -cnotcontains $_ })
    if ($missing.Count -ne 0 -or $unexpected.Count -ne 0) {
        throw "$Context differs; missing=[$($missing -join ', ')], unexpected=[$($unexpected -join ', ')]."
    }
}

function Assert-CampaignFields(
    [object]$Value,
    [string]$Context,
    [string]$CampaignId,
    [string]$ManifestHash,
    [string]$SourceCommit) {
    if ([string](Get-RequiredValue $Value 'campaign_id' $Context) -cne $CampaignId -or
        [string](Get-RequiredValue $Value 'manifest_sha256' $Context) -cne $ManifestHash -or
        [string](Get-RequiredValue $Value 'source_commit' $Context) -cne $SourceCommit) {
        throw "$Context does not match the current campaign."
    }
}

function Assert-BoundIdentity(
    [object]$Value,
    [string]$Context,
    [string]$CampaignId,
    [string]$ManifestHash,
    [string]$SourceCommit) {
    $schema = Get-RequiredValue $Value 'schema' $Context
    if (($schema -isnot [int] -and $schema -isnot [long]) -or
        [int64]$schema -ne 1) {
        throw "$Context has an invalid schema."
    }
    Assert-CampaignFields $Value $Context $CampaignId $ManifestHash $SourceCommit
}

function Assert-Marker([string]$Text, [string]$Context) {
    $marker = Read-JsonText $Text $Context
    Assert-ExactNames @($marker.PSObject.Properties.Name) @(
        'schema', 'campaign_id', 'manifest_sha256', 'source_commit') `
        "$Context fields"
    Assert-BoundIdentity $marker $Context $script:GuestCampaignId `
        $script:ExpectedManifestHash $script:ExpectedSourceCommit
}

function Assert-Boolean([object]$Value, [string]$Name, [string]$Context) {
    $field = Get-RequiredValue $Value $Name $Context
    if ($field -isnot [bool] -or -not $field) {
        throw "$Context requires $Name=true."
    }
}

function Assert-EmptyArray([object]$Value, [string]$Name, [string]$Context) {
    if (@(Get-RequiredValue $Value $Name $Context).Count -ne 0) {
        throw "$Context requires an empty $Name array."
    }
}

function Get-VolumeRoot([object]$Volume) {
    $path = [string]$Volume.Path
    if ([string]::IsNullOrWhiteSpace($path) -and $Volume.DriveLetter) {
        $path = "$($Volume.DriveLetter):\"
    }
    if ([string]::IsNullOrWhiteSpace($path)) { return $null }
    if (-not $path.EndsWith([IO.Path]::DirectorySeparatorChar)) {
        $path += [IO.Path]::DirectorySeparatorChar
    }
    return $path
}

function Read-SeedIdentity([string]$ImagePath) {
    $image = Get-DiskImage -ImagePath $ImagePath -ErrorAction Stop
    if ($image.Attached) {
        throw "Refusing to reuse an already mounted seed ISO: $ImagePath"
    }

    $mounted = $null
    try {
        $mounted = Mount-DiskImage -ImagePath $ImagePath -Access ReadOnly `
            -NoDriveLetter -PassThru -ErrorAction Stop
        $candidates = [Collections.Generic.List[string]]::new()
        foreach ($volume in @(Get-Volume -DiskImage $mounted -ErrorAction Stop)) {
            $root = Get-VolumeRoot $volume
            if (-not $root) { continue }
            $manifestPath = [IO.Path]::Combine($root, 'package-manifest.json')
            $tagPath = [IO.Path]::Combine($root, 'OAC-VM-SEED.TAG')
            if ((Test-Path -LiteralPath $manifestPath -PathType Leaf) -and
                (Test-Path -LiteralPath $tagPath -PathType Leaf)) {
                $candidates.Add($manifestPath)
            }
        }
        if ($candidates.Count -ne 1) {
            throw "The seed ISO must contain one root package manifest; found $($candidates.Count)."
        }

        $manifestPath = $candidates[0]
        $manifest = Read-JsonFile $manifestPath 'seed package manifest'
        if ([int](Get-RequiredValue $manifest 'schema' 'seed package manifest') -ne 1 -or
            [string](Get-RequiredValue $manifest 'purpose' 'seed package manifest') -cne
                'OAC disposable-VM test package; never production') {
            throw 'The seed package manifest has an unexpected schema or purpose.'
        }
        $sourceCommit = [string](Get-RequiredValue $manifest 'source_commit' `
            'seed package manifest')
        if ($sourceCommit -cnotmatch '^[0-9a-f]{40}$') {
            throw 'The seed package manifest has no canonical source commit.'
        }
        return [pscustomobject]@{
            ManifestHash = (Get-FileHash -LiteralPath $manifestPath `
                -Algorithm SHA256).Hash
            SourceCommit = $sourceCommit
        }
    } finally {
        if ($null -ne $mounted) {
            Dismount-DiskImage -ImagePath $ImagePath -ErrorAction Stop | Out-Null
        }
    }
}

function Invoke-WithVhdRoot(
    [string]$Path,
    [bool]$ReadOnly,
    [scriptblock]$Action) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    foreach ($hostDisk in @(Get-Disk -ErrorAction Stop)) {
        $hostVhd = Get-VHD -DiskNumber $hostDisk.Number -ErrorAction SilentlyContinue
        if ($null -ne $hostVhd -and
            [IO.Path]::GetFullPath($hostVhd.Path) -ieq $fullPath) {
            throw "Refusing to reuse a host-mounted VHD: $fullPath"
        }
    }

    $mounted = $null
    try {
        $mountParameters = @{
            Path = $fullPath
            NoDriveLetter = $true
            Passthru = $true
            ErrorAction = 'Stop'
        }
        if ($ReadOnly) { $mountParameters.ReadOnly = $true }
        $mounted = Mount-VHD @mountParameters
        $disks = @($mounted | Get-Disk -ErrorAction Stop)
        if ($disks.Count -ne 1) {
            throw "Mounted VHD exposed $($disks.Count) disks; expected one."
        }
        if ($ReadOnly -and -not $disks[0].IsReadOnly) {
            throw 'The inspection mount is not read-only.'
        }

        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        $roots = @()
        do {
            $candidateRoots = [Collections.Generic.List[string]]::new()
            foreach ($partition in @(Get-Partition -DiskNumber $disks[0].Number `
                    -ErrorAction SilentlyContinue)) {
                $volume = $partition | Get-Volume -ErrorAction SilentlyContinue
                if ($null -eq $volume) { continue }
                $root = Get-VolumeRoot $volume
                if (-not $root) { continue }
                $campaignRoot = [IO.Path]::Combine($root, 'OACTest')
                $campaignItem = Get-Item -LiteralPath $campaignRoot -Force `
                    -ErrorAction SilentlyContinue
                if ($null -eq $campaignItem -or -not $campaignItem.PSIsContainer) {
                    continue
                }
                if (($campaignItem.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'The mounted OACTest directory is a reparse point.'
                }
                $candidateRoots.Add($root)
            }
            $roots = @($candidateRoots | Sort-Object -Unique)
            if ($roots.Count -eq 1) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)

        if ($roots.Count -ne 1) {
            throw "Mounted VHD exposes $($roots.Count) OAC guest volumes; expected one."
        }
        return & $Action $roots[0]
    } finally {
        if ($null -ne $mounted) {
            Dismount-VHD -Path $fullPath -ErrorAction Stop
        }
    }
}

function Get-CampaignMetadata([string]$GuestRoot) {
    $root = [IO.Path]::Combine($GuestRoot, 'OACTest')
    $rootItem = Get-Item -LiteralPath $root -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The guest OACTest path is not a direct directory.'
    }
    $requiredFiles = @{
        'campaign-id.txt' = 128
        'campaign-start-utc.txt' = 128
        'campaign-manifest-sha256.txt' = 128
        'campaign-source-commit.txt' = 128
        'package-manifest.json' = 1MB
        'phase.txt' = 64
    }
    foreach ($name in $requiredFiles.Keys) {
        $path = [IO.Path]::Combine($root, $name)
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            throw "Guest campaign metadata is missing: $name"
        }
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -le 0 -or $item.Length -gt $requiredFiles[$name]) {
            throw "Guest campaign metadata is unsafe: $name"
        }
    }

    $campaignId = ([IO.File]::ReadAllText(
            [IO.Path]::Combine($root, 'campaign-id.txt'))).Trim()
    $parsedId = [Guid]::Empty
    if (-not [Guid]::TryParseExact($campaignId, 'D', [ref]$parsedId) -or
        $parsedId -eq [Guid]::Empty -or $parsedId.ToString('D') -cne $campaignId) {
        throw 'The guest campaign ID is not a canonical nonzero GUID.'
    }
    $campaignStart = ConvertTo-UtcTime ([IO.File]::ReadAllText(
            [IO.Path]::Combine($root, 'campaign-start-utc.txt'))) `
        'guest campaign start'
    $manifestHash = ([IO.File]::ReadAllText(
            [IO.Path]::Combine($root, 'campaign-manifest-sha256.txt'))).Trim()
    $sourceCommit = ([IO.File]::ReadAllText(
            [IO.Path]::Combine($root, 'campaign-source-commit.txt'))).Trim()
    $manifestPath = [IO.Path]::Combine($root, 'package-manifest.json')
    $manifest = Read-JsonFile $manifestPath 'guest package manifest'

    if ($manifestHash -cnotmatch '^[0-9A-F]{64}$' -or
        $manifestHash -cne $script:ExpectedManifestHash -or
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne
            $script:ExpectedManifestHash) {
        throw 'The guest package manifest hash does not match the seed ISO.'
    }
    if ($sourceCommit -cne $script:ExpectedSourceCommit -or
        [string](Get-RequiredValue $manifest 'source_commit' 'guest package manifest') -cne
            $script:ExpectedSourceCommit) {
        throw 'The guest source commit does not match the seed ISO.'
    }
    $now = [DateTime]::UtcNow
    if ($campaignStart -lt $script:OrchestrationStartUtc.AddMinutes(-5) -or
        $campaignStart -gt $now.AddMinutes(5)) {
        throw 'The guest campaign start is outside the fresh orchestration window.'
    }
    return [pscustomobject]@{
        Root = $root
        CampaignId = $campaignId
        CampaignStartUtc = $campaignStart
        ManifestHash = $manifestHash
        SourceCommit = $sourceCommit
    }
}

function Get-ExpectedTestNames([bool]$BaselineOnly) {
    $names = [Collections.Generic.List[string]]::new()
    foreach ($name in $baselineZeroTests) { $names.Add($name) }
    if (-not $BaselineOnly) {
        foreach ($name in $verifierZeroTests) { $names.Add($name) }
    }
    foreach ($name in $specialTests.Keys) { $names.Add([string]$name) }
    return @($names)
}

function Assert-ExitValue([string]$Name, [int64]$Value) {
    if ($baselineZeroTests -ccontains $Name -or $verifierZeroTests -ccontains $Name) {
        if ($Value -ne 0) { throw "$Name exited with $Value; expected zero." }
        return
    }
    $expectation = $specialTests[$Name]
    if ($expectation -is [string] -and $expectation -ceq 'nonzero') {
        if ($Value -eq 0) { throw "$Name exited with zero; expected refusal." }
        return
    }
    if (@($expectation) -notcontains $Value) {
        throw "$Name exited with $Value; expected $(@($expectation) -join ' or ')."
    }
}

function Read-ExitCode([string]$Text, [string]$Name) {
    $value = [int64]0
    if (-not [int64]::TryParse(
            $Text.Trim(),
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$value)) {
        throw "$Name has a malformed exit-code file."
    }
    return $value
}

function Assert-AuxiliaryExitResults(
    [Collections.IDictionary]$ExitValues,
    [bool]$Full,
    [string]$Context) {
    $required = if ($Full) {
        @($fullAuxiliaryRequired)
    } else {
        @($baselineAuxiliaryRequired)
    }
    $optional = if ($Full) {
        @($fullAuxiliaryOptional)
    } else {
        @($baselineAuxiliaryOptional)
    }
    $allowed = @($required) + @($optional)
    $observed = @($ExitValues.Keys | ForEach-Object { [string]$_ })
    $missing = @($required | Where-Object { $observed -cnotcontains $_ })
    $unexpected = @($observed | Where-Object { $allowed -cnotcontains $_ })
    if ($missing.Count -ne 0 -or $unexpected.Count -ne 0) {
        throw ("$Context auxiliary result set is invalid; missing=[$($missing -join ', ')] " +
            "unexpected=[$($unexpected -join ', ')].")
    }
    foreach ($name in $observed) {
        $value = $ExitValues[$name]
        if (($value -isnot [int] -and $value -isnot [long]) -or
            @($auxiliaryExitValues[$name]) -notcontains $value) {
            throw "$Context has an invalid auxiliary exit value: $name=$value"
        }
    }
}

function Get-SafeTreeItems(
    [string]$Root,
    [int]$MaximumItems,
    [int64]$MaximumBytes) {
    $items = [Collections.Generic.List[object]]::new()
    $directories = [Collections.Generic.Queue[string]]::new()
    $directories.Enqueue($Root)
    [int64]$totalBytes = 0
    while ($directories.Count -ne 0) {
        $directory = $directories.Dequeue()
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $attributes = [IO.File]::GetAttributes($path)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "The baseline result tree contains a reparse point: $path"
            }
            $item = Get-Item -LiteralPath $path -Force
            $items.Add($item)
            if ($items.Count -gt $MaximumItems) {
                throw "The baseline result tree exceeds $MaximumItems items."
            }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                $directories.Enqueue($item.FullName)
                continue
            }
            if ($item.Length -gt 1GB) {
                throw "A baseline result exceeds the per-file limit: $path"
            }
            $totalBytes += $item.Length
            if ($totalBytes -gt $MaximumBytes) {
                throw 'The baseline result tree exceeds its byte limit.'
            }
        }
    }
    return @($items)
}

function Assert-IntegerValue(
    [object]$Value,
    [int64]$Expected,
    [string]$Context) {
    if (($Value -isnot [int] -and $Value -isnot [long]) -or
        [int64]$Value -ne $Expected) {
        throw "$Context is not the required integer value $Expected."
    }
}

function Assert-ProductionBoundarySummary([object]$Summary, [string]$Context) {
    Assert-Boolean $Summary 'pass' $Context
    $launcherExits = @(Get-RequiredValue $Summary 'launcher_exits' $Context)
    if ($launcherExits.Count -ne 3) {
        throw "$Context does not contain three successful status results."
    }
    $launchExits = @(Get-RequiredValue $Summary 'launch_exits' $Context)
    if ($launchExits.Count -ne 2) {
        throw "$Context does not contain two successful launch results."
    }
    for ($index = 0; $index -lt $launchExits.Count; ++$index) {
        Assert-IntegerValue $launchExits[$index] 0 `
            "$Context launch_exits[$index]"
    }
    for ($index = 0; $index -lt $launcherExits.Count; ++$index) {
        Assert-IntegerValue $launcherExits[$index] 0 `
            "$Context launcher_exits[$index]"
    }
    foreach ($name in @(
            'direct_open_localsystem_exit',
            'direct_open_limited_exit',
            'direct_open_administrator_exit')) {
        Assert-IntegerValue (Get-RequiredValue $Summary $name $Context) 0 `
            "$Context $name"
    }
    Assert-IntegerValue (Get-RequiredValue $Summary 'launch_exit' $Context) 0 `
        "$Context launch_exit"
    Assert-IntegerValue (Get-RequiredValue $Summary `
            'graceful_launch_exit' $Context) 0 `
        "$Context graceful_launch_exit"
    foreach ($name in @(
            'launch_target_process_id',
            'graceful_launch_target_process_id',
            'crash_child_process_id',
            'graceful_child_process_id')) {
        $processId = Get-RequiredValue $Summary $name $Context
        if (($processId -isnot [int] -and $processId -isnot [long]) -or
            [int64]$processId -le 0) {
            throw "$Context does not contain a valid $name."
        }
    }
    foreach ($name in @(
            'launch_binding_confirmed',
            'launch_job_assigned',
            'launch_thread_resumed',
            'graceful_launch_binding_confirmed',
            'graceful_launch_job_assigned',
            'graceful_launch_thread_resumed',
            'crash_processes_terminated',
            'graceful_processes_terminated',
            'service_crash_restarted',
            'lab_mode_restored')) {
        Assert-Boolean $Summary $name $Context
    }

    $lossSequences = @(Get-RequiredValue `
            $Summary 'session_loss_sequences' $Context)
    $lossReasons = @(Get-RequiredValue $Summary 'session_loss_reasons' $Context)
    if ($lossSequences.Count -ne 3 -or $lossReasons.Count -ne 3) {
        throw "$Context does not contain three liveness status observations."
    }
    foreach ($index in 0..2) {
        Assert-IntegerValue $lossSequences[$index] $index `
            "$Context session_loss_sequences[$index]"
    }
    Assert-IntegerValue $lossReasons[0] 0 "$Context session_loss_reasons[0]"
    if (($lossReasons[1] -isnot [int] -and $lossReasons[1] -isnot [long]) -or
        [int64]$lossReasons[1] -notin @(2, 3)) {
        throw "$Context crash loss reason is not file cleanup or service exit."
    }
    Assert-IntegerValue $lossReasons[2] 1 "$Context session_loss_reasons[2]"
}

function Assert-DriverGateSummary([object]$Summary, [string]$Context) {
    Assert-Boolean $Summary 'pass' $Context
    Assert-IntegerValue (Get-RequiredValue $Summary 'trigger_exit' $Context) 0 `
        "$Context trigger_exit"
    Assert-IntegerValue (Get-RequiredValue $Summary 'start_error' $Context) 183 `
        "$Context start_error"
    Assert-IntegerValue (Get-RequiredValue $Summary 'detection_exit' $Context) 1 `
        "$Context detection_exit"
    foreach ($name in @(
            'armed_probe_validation',
            'persistent_gate_finding',
            'callback_finding')) {
        Assert-Boolean $Summary $name $Context
    }
    $preSession = Get-RequiredValue $Summary 'pre_session_callback' $Context
    if ($preSession -isnot [bool] -or $preSession) {
        throw "$Context requires pre_session_callback=false."
    }
}

function Assert-BaselineResults([object]$Campaign) {
    $results = [IO.Path]::Combine($Campaign.Root, 'results')
    $resultsItem = Get-Item -LiteralPath $results -Force `
        -ErrorAction SilentlyContinue
    if ($null -eq $resultsItem -or -not $resultsItem.PSIsContainer) {
        throw 'The baseline results directory is missing.'
    }
    if (($resultsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The baseline results directory is a reparse point.'
    }
    $resultItems = @(Get-SafeTreeItems $results 4096 2GB)
    $failures = @($resultItems | Where-Object Name -Like '*-failure.txt')
    if ($failures.Count -ne 0) {
        throw "Baseline produced failure evidence: $($failures.Name -join ', ')"
    }
    foreach ($name in @('baseline-unexpected-reboot.txt', 'verifier-unexpected-reboot.txt')) {
        if ($resultItems.Name -ccontains $name) {
            throw "Baseline produced unexpected restart evidence: $name"
        }
    }

    $exitFiles = @($resultItems | Where-Object Name -Like '*.exitcode.txt')
    $unsafeExitFiles = @($exitFiles | Where-Object {
            $_.DirectoryName -ine $results -or
            -not $_.Name.EndsWith(
                '.exitcode.txt',
                [StringComparison]::Ordinal)
        })
    if ($unsafeExitFiles.Count -ne 0) {
        throw "Baseline produced unsafe exit-code files: $($unsafeExitFiles.Name -join ', ')"
    }
    $exitValues = [Collections.Generic.Dictionary[string, int64]]::new(
        [StringComparer]::Ordinal)
    foreach ($file in $exitFiles) {
        $name = $file.Name.Substring(0, $file.Name.Length - '.exitcode.txt'.Length)
        $exitValues.Add($name, (Read-ExitCode ([IO.File]::ReadAllText($file.FullName)) $name))
    }
    $expected = Get-ExpectedTestNames $true
    $formalObserved = @($exitValues.Keys | Where-Object { $expected -ccontains $_ })
    Assert-ExactNames $formalObserved $expected 'baseline test result set'
    foreach ($name in $expected) {
        Assert-ExitValue $name $exitValues[$name]
    }
    $auxiliaryValues = [Collections.Generic.Dictionary[string, int64]]::new(
        [StringComparer]::Ordinal)
    foreach ($name in $exitValues.Keys) {
        if ($expected -cnotcontains $name) {
            $auxiliaryValues.Add($name, $exitValues[$name])
        }
    }
    Assert-AuxiliaryExitResults $auxiliaryValues $false 'baseline results'

    $baselineSummary = Read-JsonFile `
        ([IO.Path]::Combine($results, 'baseline-summary.json')) 'baseline summary'
    Assert-CampaignFields $baselineSummary 'baseline summary' $Campaign.CampaignId `
        $Campaign.ManifestHash $Campaign.SourceCommit
    $summaryStart = ConvertTo-UtcTime `
        (Get-RequiredValue $baselineSummary 'campaign_start_utc' 'baseline summary') `
        'baseline summary campaign start'
    if ($summaryStart -ne $Campaign.CampaignStartUtc) {
        throw 'The baseline summary campaign start does not match the guest campaign.'
    }
    Assert-Boolean $baselineSummary 'pass' 'baseline summary'
    Assert-Boolean $baselineSummary 'driver_gate_pass' 'baseline summary'
    Assert-Boolean $baselineSummary 'production_boundary_pass' 'baseline summary'
    Assert-Boolean $baselineSummary 'removal_boundary_pass' 'baseline summary'
    Assert-Boolean $baselineSummary 'provenance_pass' 'baseline summary'
    Assert-EmptyArray $baselineSummary 'exit_failures' 'baseline summary'
    $baselineCompleted = ConvertTo-UtcTime `
        (Get-RequiredValue $baselineSummary 'timestamp_utc' 'baseline summary') `
        'baseline completion'
    if ($baselineCompleted -lt $Campaign.CampaignStartUtc -or
        $baselineCompleted -gt [DateTime]::UtcNow.AddMinutes(5)) {
        throw 'The baseline completion timestamp is outside the campaign window.'
    }

    foreach ($name in $summaryNames) {
        $summary = Read-JsonFile ([IO.Path]::Combine($results, "$name.json")) $name
        if ($name -ceq 'production-boundary-summary') {
            Assert-ProductionBoundarySummary $summary $name
        } elseif ($name -ceq 'baseline-driver-gate-summary') {
            Assert-DriverGateSummary $summary $name
        } else {
            Assert-Boolean $summary 'pass' $name
        }
    }
    return $baselineCompleted
}

function Read-BaselineState([string]$GuestRoot) {
    $campaign = Get-CampaignMetadata $GuestRoot
    $phase = ([IO.File]::ReadAllText(
            [IO.Path]::Combine($campaign.Root, 'phase.txt')) -replace "`0", '').Trim()
    if ($phase -ceq 'complete') {
        if (($null -ne $script:GuestCampaignId -and
                $script:GuestCampaignId -cne $campaign.CampaignId) -or
            ($script:GuestCampaignStartUtc -ne [DateTime]::MinValue -and
                $script:GuestCampaignStartUtc -ne $campaign.CampaignStartUtc)) {
            throw 'Powered-off terminal campaign identity changed after the live guest probe.'
        }
        $script:GuestCampaignId = $campaign.CampaignId
        $script:GuestCampaignStartUtc = $campaign.CampaignStartUtc
        $script:HostRecord['campaign_id'] = $campaign.CampaignId
        $script:HostRecord['campaign_start_utc'] = $campaign.CampaignStartUtc.ToString('o')
        foreach ($name in @(
                'verifier-authorized.json',
                'verifier-authorized.consumed.json')) {
            $authorizationItem = Get-Item -LiteralPath `
                ([IO.Path]::Combine($campaign.Root, $name)) -Force `
                -ErrorAction SilentlyContinue
            if ($null -ne $authorizationItem) {
                throw "Terminal baseline failure unexpectedly contains $name."
            }
        }
        $markerPath = [IO.Path]::Combine($campaign.Root, 'containment-ready.json')
        $markerItem = Get-Item -LiteralPath $markerPath -Force `
            -ErrorAction SilentlyContinue
        if ($null -ne $markerItem) {
            if ($markerItem.PSIsContainer -or
                ($markerItem.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $markerItem.Length -le 0 -or $markerItem.Length -gt 64KB) {
                throw 'Terminal baseline containment marker is unsafe.'
            }
            Assert-Marker ([IO.File]::ReadAllText($markerPath)) `
                'terminal baseline containment marker'
        }
        $failure = Save-OffFailureEvidence $campaign
        $script:HostRecord['failure_evidence_directory'] = $failure.Destination
        $script:HostRecord['failure_results_zip_sha256'] = $failure.ArchiveHash
        throw "Guest published terminal baseline failure: $($failure.Message)"
    }
    if ($phase -cne 'baseline-complete') {
        throw "Guest phase is $phase; expected baseline-complete."
    }
    foreach ($name in @(
            'verifier-authorized.json', 'containment-ready.json',
            'final-status.json', 'results.zip')) {
        $item = Get-Item -LiteralPath ([IO.Path]::Combine($campaign.Root, $name)) `
            -Force -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            throw "The safe baseline unexpectedly contains $name."
        }
    }
    $completed = Assert-BaselineResults $campaign
    return [pscustomobject]@{
        CampaignId = $campaign.CampaignId
        CampaignStartUtc = $campaign.CampaignStartUtc
        ManifestHash = $campaign.ManifestHash
        SourceCommit = $campaign.SourceCommit
        BaselineCompletedUtc = $completed
    }
}

function Assert-SafeCheckpointRoot([string]$GuestRoot) {
    $campaign = Get-CampaignMetadata $GuestRoot
    if ($campaign.CampaignId -cne $script:GuestCampaignId) {
        throw 'Checkpoint campaign identity changed.'
    }
    $phase = ([IO.File]::ReadAllText(
            [IO.Path]::Combine($campaign.Root, 'phase.txt')) -replace "`0", '').Trim()
    if ($phase -cne 'baseline-complete') {
        throw 'The checkpoint is not at baseline-complete.'
    }
    $authorization = Get-Item -LiteralPath `
        ([IO.Path]::Combine($campaign.Root, 'verifier-authorized.json')) `
        -Force -ErrorAction SilentlyContinue
    if ($null -ne $authorization) {
        throw 'The checkpoint contains a Verifier authorization marker.'
    }
}

function Write-NewUtf8File([string]$Path, [string]$Text) {
    $existing = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -ne $existing) { throw "Refusing to replace existing file: $Path" }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $temporary,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        [IO.File]::Move($temporary, $Path)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Write-VerifierAuthorization([string]$GuestRoot) {
    $campaign = Get-CampaignMetadata $GuestRoot
    if ($campaign.CampaignId -cne $script:GuestCampaignId) {
        throw 'The active child does not contain the validated campaign.'
    }
    $phase = ([IO.File]::ReadAllText(
            [IO.Path]::Combine($campaign.Root, 'phase.txt')) -replace "`0", '').Trim()
    if ($phase -cne 'baseline-complete') {
        throw 'The active child is not at baseline-complete.'
    }
    $path = [IO.Path]::Combine($campaign.Root, 'verifier-authorized.json')
    $marker = [ordered]@{
        schema = 1
        campaign_id = $script:GuestCampaignId
        manifest_sha256 = $script:ExpectedManifestHash
        source_commit = $script:ExpectedSourceCommit
    }
    Write-NewUtf8File $path (ConvertTo-Json -InputObject $marker -Compress)
}

function Assert-ActiveAuthorization([string]$GuestRoot) {
    $campaign = Get-CampaignMetadata $GuestRoot
    if ($campaign.CampaignId -cne $script:GuestCampaignId) {
        throw 'The active child campaign identity changed.'
    }
    $path = [IO.Path]::Combine($campaign.Root, 'verifier-authorized.json')
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 64KB) {
        throw 'The active child has no Verifier authorization marker.'
    }
    Assert-Marker ([IO.File]::ReadAllText($path)) 'Verifier authorization marker'
}

function Invoke-VMDirectBounded(
    [scriptblock]$ScriptBlock,
    [object[]]$ArgumentList = @(),
    [int]$TimeoutSeconds = 30) {
    $job = $null
    try {
        $parameters = @{
            VMName = $VMName
            Credential = $script:GuestCredential
            ScriptBlock = $ScriptBlock
            AsJob = $true
            ErrorAction = 'Stop'
        }
        if ($ArgumentList.Count -ne 0) { $parameters.ArgumentList = $ArgumentList }
        $job = Invoke-Command @parameters
        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if (-not $completed -or $job.State -ne 'Completed') {
            throw "PowerShell Direct did not complete within $TimeoutSeconds seconds."
        }
        return Receive-Job -Job $job -ErrorAction Stop
    } finally {
        if ($null -ne $job) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

function Wait-ForBaselineOff(
    [TimeSpan]$InstallBound,
    [TimeSpan]$BaselineBound) {
    $installDeadline = [DateTime]::UtcNow + $InstallBound
    $baselineDeadline = $null
    $nextProbe = [DateTime]::MinValue
    $nextProgress = [DateTime]::MinValue
    $baselinePhases = @(
        'post-testsigning', 'baseline-running', 'baseline-complete',
        'finalize', 'complete')
    while ($true) {
        $now = [DateTime]::UtcNow
        $vm = Get-VM -Name $VMName
        if ($vm.State -eq 'Off') {
            Write-HostLog 'VM powered off after installation and baseline tests.'
            return
        }
        $activeDeadline = if ($null -eq $baselineDeadline) {
            $installDeadline
        } else {
            $baselineDeadline
        }
        if ($now -ge $activeDeadline) {
            $stage = if ($null -eq $baselineDeadline) {
                'unattended Windows installation'
            } else {
                'baseline tests'
            }
            throw "Timed out waiting for the VM to power off after $stage."
        }
        if ($vm.State -eq 'Running' -and $now -ge $nextProbe) {
            $probe = $null
            try { $probe = Get-GuestReadyProbe } catch { }
            $now = [DateTime]::UtcNow
            $nextProbe = $now.AddSeconds(15)
            if ($null -ne $probe -and
                -not [string]::IsNullOrWhiteSpace([string]$probe.phase)) {
                Assert-LiveCampaignProbe $probe
                if ($baselinePhases -cnotcontains [string]$probe.phase) {
                    throw "Guest reported an invalid baseline phase: $($probe.phase)"
                }
                if ($null -eq $baselineDeadline) {
                    if ($script:GuestCampaignStartUtc -gt $installDeadline) {
                        throw 'Guest campaign started after the installation deadline.'
                    }
                    $baselineDeadline = `
                        $script:GuestCampaignStartUtc + $BaselineBound
                    Write-HostLog `
                        "Guest campaign entered phase $($probe.phase); baseline deadline started."
                }
                if ([string]$probe.phase -ceq 'complete') {
                    $status = Read-LiveStatus $probe 'terminal baseline status'
                    if ($null -eq $status) {
                        throw 'Guest completed before the baseline snapshot without a final status.'
                    }
                    if ([bool]$status.overall_pass) {
                        throw 'Guest reported success before the safe baseline snapshot boundary.'
                    }
                    $message = Get-LiveFailureMessage $probe $status `
                        'baseline did not reach the safe snapshot boundary'
                    Write-HostLog `
                        "Guest published terminal baseline failure; preserving powered-off evidence: $message"
                    Stop-TestVM $false
                    return
                }
            }
        }

        $vm = Get-VM -Name $VMName
        if ($vm.State -eq 'Off') {
            Write-HostLog 'VM powered off after installation and baseline tests.'
            return
        }
        $now = [DateTime]::UtcNow
        $activeDeadline = if ($null -eq $baselineDeadline) {
            $installDeadline
        } else {
            $baselineDeadline
        }
        if ($now -ge $activeDeadline) {
            $stage = if ($null -eq $baselineDeadline) {
                'unattended Windows installation'
            } else {
                'baseline tests'
            }
            throw "Timed out waiting for the VM to power off after $stage."
        }
        if ($now -ge $nextProgress) {
            $vhdSize = if ($script:VhdPath -and
                (Test-Path -LiteralPath $script:VhdPath)) {
                (Get-Item -LiteralPath $script:VhdPath).Length
            } else { 0 }
            $stage = if ($null -eq $baselineDeadline) {
                'installation'
            } else {
                'baseline tests'
            }
            Write-HostLog `
                "Waiting for $stage; state=$($vm.State), VHDX bytes=$vhdSize."
            $nextProgress = $now.AddSeconds(30)
        }
        Start-Sleep -Seconds 5
    }
}

function Get-GuestReadyProbe {
    return Invoke-VMDirectBounded -TimeoutSeconds 45 -ScriptBlock {
        $root = 'C:\OACTest'
        function Get-HashInfo([string]$Path) {
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
            $item = Get-Item -LiteralPath $Path
            if ($item.Length -gt 2GB) {
                return [pscustomobject]@{ bytes = $item.Length; sha256 = 'TOO-LARGE' }
            }
            return [pscustomobject]@{
                bytes = $item.Length
                sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
            }
        }
        function Get-SmallText([string]$Path) {
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
            $item = Get-Item -LiteralPath $Path
            if ($item.Length -gt 64KB) { throw "Probe text is too large: $Path" }
            return Get-Content -LiteralPath $Path -Raw
        }
        $phase = if (Test-Path -LiteralPath (Join-Path $root 'phase.txt')) {
            ((Get-Content -LiteralPath (Join-Path $root 'phase.txt') -Raw) `
                -replace "`0", '').Trim()
        } else { $null }
        $markerPath = Join-Path $root 'containment-ready.json'
        $marker = if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
            Get-Content -LiteralPath $markerPath -Raw
        } else { $null }
        [pscustomobject]@{
            phase = $phase
            campaign_id = Get-SmallText (Join-Path $root 'campaign-id.txt')
            campaign_start_utc = Get-SmallText `
                (Join-Path $root 'campaign-start-utc.txt')
            manifest_sha256 = Get-SmallText `
                (Join-Path $root 'campaign-manifest-sha256.txt')
            source_commit = Get-SmallText `
                (Join-Path $root 'campaign-source-commit.txt')
            baseline_failure = Get-SmallText `
                (Join-Path $root 'results\baseline-running-failure.txt')
            baseline_restart = Get-SmallText `
                (Join-Path $root 'results\baseline-unexpected-reboot.txt')
            marker = $marker
            status = Get-SmallText (Join-Path $root 'final-status.json')
            marker_info = Get-HashInfo $markerPath
            status_info = Get-HashInfo (Join-Path $root 'final-status.json')
            archive_info = Get-HashInfo (Join-Path $root 'results.zip')
            oac_tasks = @(Get-ScheduledTask -ErrorAction Stop |
                Where-Object TaskName -Like 'OAC-VM-*' |
                Select-Object -ExpandProperty TaskName -Unique)
        }
    }
}

function Assert-LiveCampaignProbe([object]$Probe) {
    $campaignId = ([string]$Probe.campaign_id).Trim()
    $parsedId = [Guid]::Empty
    if (-not [Guid]::TryParseExact($campaignId, 'D', [ref]$parsedId) -or
        $parsedId -eq [Guid]::Empty -or $parsedId.ToString('D') -cne $campaignId) {
        throw 'Live guest campaign ID is invalid.'
    }
    $manifestHash = ([string]$Probe.manifest_sha256).Trim()
    $sourceCommit = ([string]$Probe.source_commit).Trim()
    if ($manifestHash -cne $script:ExpectedManifestHash -or
        $sourceCommit -cne $script:ExpectedSourceCommit) {
        throw 'Live guest campaign identity does not match the seed.'
    }
    $campaignStart = ConvertTo-UtcTime ([string]$Probe.campaign_start_utc) `
        'live guest campaign start'
    $now = [DateTime]::UtcNow
    if ($campaignStart -lt $script:OrchestrationStartUtc.AddMinutes(-5) -or
        $campaignStart -gt $now.AddMinutes(5)) {
        throw 'Live guest campaign start is outside the orchestration window.'
    }
    if ($null -ne $script:GuestCampaignId -and
        $script:GuestCampaignId -cne $campaignId) {
        throw 'Live guest campaign ID changed during orchestration.'
    }
    if ($script:GuestCampaignStartUtc -ne [DateTime]::MinValue -and
        $script:GuestCampaignStartUtc -ne $campaignStart) {
        throw 'Live guest campaign start changed during orchestration.'
    }
    $script:GuestCampaignId = $campaignId
    $script:GuestCampaignStartUtc = $campaignStart
}

function Read-LiveStatus([object]$Probe, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace([string]$Probe.status)) { return $null }
    try {
        $status = [string]$Probe.status | ConvertFrom-Json
    } catch {
        throw "$Purpose is malformed."
    }
    Assert-BoundIdentity $status $Purpose $script:GuestCampaignId `
        $script:ExpectedManifestHash $script:ExpectedSourceCommit
    $statusStart = ConvertTo-UtcTime `
        (Get-RequiredValue $status 'campaign_start_utc' $Purpose) `
        "$Purpose campaign start"
    if ($statusStart -ne $script:GuestCampaignStartUtc) {
        throw "$Purpose has the wrong campaign start."
    }
    $overallPass = Get-RequiredValue $status 'overall_pass' $Purpose
    if ($overallPass -isnot [bool]) {
        throw "$Purpose has a non-Boolean result."
    }
    return $status
}

function Get-SafeFailureMessage([string]$Text, [string]$Fallback) {
    $message = (($Text -replace '[\x00-\x1F\x7F]+', ' ') `
        -replace '\s+', ' ').Trim()
    if ([string]::IsNullOrWhiteSpace($message)) { $message = $Fallback }
    if ($message.Length -gt 512) { $message = $message.Substring(0, 512) }
    return $message
}

function Get-LiveFailureMessage(
    [object]$Probe,
    [object]$Status,
    [string]$Fallback) {
    $failureText = if (-not [string]::IsNullOrWhiteSpace(
            [string]$Probe.baseline_failure)) {
        [string]$Probe.baseline_failure
    } elseif (-not [string]::IsNullOrWhiteSpace(
            [string]$Probe.baseline_restart)) {
        'baseline restarted unexpectedly'
    } elseif ($Status.PSObject.Properties.Name -ccontains 'fatal_message') {
        [string]$Status.fatal_message
    } else {
        $Fallback
    }
    return Get-SafeFailureMessage $failureText $Fallback
}

function Wait-ForStableResults([TimeSpan]$Timeout) {
    $deadline = [DateTime]::UtcNow + $Timeout
    $lastSignature = $null
    $stablePolls = 0
    $nextProgress = [DateTime]::MinValue
    while ([DateTime]::UtcNow -lt $deadline) {
        $vm = Get-VM -Name $VMName
        if ($vm.State -eq 'Off') {
            throw 'The guest powered off before publishing stable final evidence.'
        }
        if ($vm.State -eq 'Running') {
            $probe = $null
            try { $probe = Get-GuestReadyProbe } catch { }
            if ($null -ne $probe) {
                Assert-LiveCampaignProbe $probe
                $status = $null
                if ([string]$probe.phase -ceq 'complete') {
                    $status = Read-LiveStatus $probe 'live final status'
                }
                $artifactsReady = $probe.phase -ceq 'complete' -and
                    @($probe.oac_tasks).Count -eq 0 -and
                    $null -ne $probe.status_info -and
                    $null -ne $probe.archive_info -and
                    $probe.status_info.sha256 -cmatch '^[0-9A-F]{64}$' -and
                    $probe.archive_info.sha256 -cmatch '^[0-9A-F]{64}$'
                $ready = $artifactsReady -and
                    -not [string]::IsNullOrWhiteSpace([string]$probe.marker) -and
                    $null -ne $probe.marker_info -and
                    $probe.marker_info.sha256 -cmatch '^[0-9A-F]{64}$'
                $fatalReady = $artifactsReady -and $null -ne $status -and
                    -not [bool]$status.overall_pass -and
                    [string]::IsNullOrWhiteSpace([string]$probe.marker) -and
                    ($status.PSObject.Properties.Name -ccontains 'fatal_message')
                if ($ready -or $fatalReady) {
                    $mode = if ($fatalReady) { 'failure' } else { 'complete' }
                    $markerSignature = if ($ready) {
                        Assert-Marker ([string]$probe.marker) `
                            'containment-ready marker'
                        "$($probe.marker_info.bytes):$($probe.marker_info.sha256)"
                    } else {
                        'no-marker'
                    }
                    $signature = @(
                        $mode,
                        $probe.status_info.bytes, $probe.status_info.sha256,
                        $probe.archive_info.bytes, $probe.archive_info.sha256,
                        $markerSignature) -join ':'
                    if ($signature -ceq $lastSignature) {
                        $stablePolls++
                    } else {
                        $lastSignature = $signature
                        $stablePolls = 1
                    }
                    if ($stablePolls -ge 2) {
                        if ($fatalReady) {
                            $failureEvidencePath = Join-Path $resultPath `
                                'failed-evidence'
                            Copy-GuestEvidence $probe $failureEvidencePath $false
                            $message = Get-LiveFailureMessage $probe $status `
                                'final VM validation failed'
                            throw "Guest published terminal final failure: $message"
                        }
                        Write-HostLog 'Guest final evidence is stable across two polls.'
                        return $probe
                    }
                } else {
                    $lastSignature = $null
                    $stablePolls = 0
                }
            }
        }
        if ([DateTime]::UtcNow -ge $nextProgress) {
            Write-HostLog "Waiting for stable final evidence; state=$($vm.State)."
            $nextProgress = [DateTime]::UtcNow.AddSeconds(30)
        }
        Start-Sleep -Seconds 10
    }
    throw 'Timed out waiting for stable, campaign-bound final evidence.'
}

function Copy-GuestEvidence(
    [object]$Probe,
    [string]$Destination,
    [bool]$RequireMarker = $true) {
    if (Test-Path -LiteralPath $Destination) {
        throw "Refusing to reuse an evidence directory: $Destination"
    }
    New-Item -ItemType Directory -Path $Destination | Out-Null
    if (@(Get-ChildItem -LiteralPath $Destination -Force).Count -ne 0) {
        throw 'The new evidence directory is not empty.'
    }

    $session = $null
    try {
        # PowerShell Direct's VMName parameter set does not accept
        # SessionOption. Its VM transport supplies bounded connection and
        # operation timeouts, and this session is always removed below.
        $session = New-PSSession -VMName $VMName `
            -Credential $script:GuestCredential -ErrorAction Stop
        $copies = [ordered]@{
            'C:\OACTest\final-status.json' = 'final-status.json'
            'C:\OACTest\results.zip' = 'oac-vm-results.zip'
        }
        if ($RequireMarker) {
            $copies['C:\OACTest\containment-ready.json'] = 'containment-ready.json'
        }
        foreach ($entry in $copies.GetEnumerator()) {
            Copy-Item -FromSession $session -LiteralPath $entry.Key `
                -Destination (Join-Path $Destination $entry.Value) -ErrorAction Stop
        }
    } finally {
        if ($null -ne $session) { Remove-PSSession $session }
    }

    $statusPath = Join-Path $Destination 'final-status.json'
    $archivePath = Join-Path $Destination 'oac-vm-results.zip'
    $markerPath = Join-Path $Destination 'containment-ready.json'
    if ((Get-Item -LiteralPath $statusPath).Length -ne [int64]$Probe.status_info.bytes -or
        (Get-FileHash -LiteralPath $statusPath -Algorithm SHA256).Hash -cne
            [string]$Probe.status_info.sha256 -or
        (Get-Item -LiteralPath $archivePath).Length -ne [int64]$Probe.archive_info.bytes -or
        (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -cne
            [string]$Probe.archive_info.sha256) {
        throw 'Copied evidence does not match the stable guest artifacts.'
    }
    if ($RequireMarker) {
        if ((Get-Item -LiteralPath $markerPath).Length -ne
                [int64]$Probe.marker_info.bytes -or
            (Get-FileHash -LiteralPath $markerPath -Algorithm SHA256).Hash -cne
                [string]$Probe.marker_info.sha256) {
            throw 'Copied containment marker does not match the stable guest artifact.'
        }
        Assert-Marker ([IO.File]::ReadAllText($markerPath)) `
            'copied containment-ready marker'
    }
}

function Read-ZipEntryBytes([object]$Entry, [int64]$Limit) {
    if ($Entry.Length -gt $Limit) {
        throw "ZIP entry is too large to parse: $($Entry.FullName)"
    }
    $memory = [IO.MemoryStream]::new()
    $stream = $null
    try {
        $stream = $Entry.Open()
        $stream.CopyTo($memory)
        return $memory.ToArray()
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $memory.Dispose()
    }
}

function ConvertTo-SafeZipEntryName([string]$Name, [string]$Context) {
    if ([string]::IsNullOrWhiteSpace($Name) -or
        $Name -match '[\x00-\x1F\x7F]') {
        throw "$Context contains an unsafe entry path."
    }

    $canonical = $Name.Replace([char]0x5C, [char]0x2F)
    if ($canonical.StartsWith('/') -or $canonical.Contains(':')) {
        throw "$Context contains an unsafe entry path: $Name"
    }

    $isDirectory = $canonical.EndsWith('/')
    $path = if ($isDirectory) {
        $canonical.Substring(0, $canonical.Length - 1)
    } else {
        $canonical
    }
    if ([string]::IsNullOrWhiteSpace($path)) {
        throw "$Context contains an unsafe entry path: $Name"
    }

    foreach ($part in $path.Split([char]0x2F)) {
        if ([string]::IsNullOrWhiteSpace($part) -or
            $part -cne $part.Trim() -or
            $part -ceq '.' -or $part -ceq '..' -or
            $part.EndsWith('.')) {
            throw "$Context contains an unsafe entry path: $Name"
        }
    }
    return $canonical
}

function Convert-ZipText([byte[]]$Bytes) {
    $text = [Text.Encoding]::UTF8.GetString($Bytes)
    if ($text.Length -ne 0 -and $text[0] -eq [char]0xFEFF) {
        $text = $text.Substring(1)
    }
    return $text
}

function Clear-ReadOnlyFile([string]$Path) {
    $attributes = [IO.File]::GetAttributes($Path)
    if (($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
        [IO.File]::SetAttributes(
            $Path,
            $attributes -band (-bnot [IO.FileAttributes]::ReadOnly))
    }
}

function Write-CleanupLog([string]$Message) {
    try {
        Write-HostLog $Message
    } catch {
        try { [Console]::Error.WriteLine($Message) } catch { }
    }
}

function Test-ZipCrc([string]$ArchivePath, [string]$Context) {
    $errorPath = Join-Path $resultPath `
        ".zip-crc-$([Guid]::NewGuid().ToString('N')).txt"
    try {
        $savedErrorPreference = $ErrorActionPreference
        try {
            # Windows PowerShell surfaces native stderr as an ErrorRecord when
            # Stop is active, before the exit code can be checked.
            $ErrorActionPreference = 'Continue'
            & tar.exe -xOf $ArchivePath 1>$null 2>$errorPath
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedErrorPreference
        }
        if ($exitCode -ne 0) {
            $detail = if (Test-Path -LiteralPath $errorPath -PathType Leaf) {
                $item = Get-Item -LiteralPath $errorPath -Force
                if ($item.Length -gt 64KB) {
                    'diagnostic output exceeded 64 KiB'
                } else {
                    Get-SafeFailureMessage ([IO.File]::ReadAllText($errorPath)) `
                        'no diagnostic output'
                }
            } else {
                'no diagnostic output'
            }
            throw "$Context CRC validation failed with exit code ${exitCode}: $detail"
        }
    } finally {
        try {
            if ([IO.File]::Exists($errorPath)) {
                Clear-ReadOnlyFile $errorPath
                [IO.File]::Delete($errorPath)
            }
        } catch {
            $cleanupMessage = Get-SafeFailureMessage $_.Exception.Message `
                'unknown cleanup error'
            Write-CleanupLog "Could not remove ZIP diagnostic output: $cleanupMessage"
        }
    }
}

function Save-OffFailureEvidence([object]$Campaign) {
    $statusPath = [IO.Path]::Combine($Campaign.Root, 'final-status.json')
    $archivePath = [IO.Path]::Combine($Campaign.Root, 'results.zip')
    $rootItem = Get-Item -LiteralPath $Campaign.Root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The powered-off campaign root is a reparse point.'
    }

    $statusItem = Get-Item -LiteralPath $statusPath -Force
    $archiveItem = Get-Item -LiteralPath $archivePath -Force
    if (($statusItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $statusItem.PSIsContainer -or $archiveItem.PSIsContainer -or
        $statusItem.Length -le 0 -or $statusItem.Length -gt 1MB -or
        $archiveItem.Length -le 0 -or $archiveItem.Length -gt 2GB) {
        throw 'Powered-off failure evidence has an unsafe type or size.'
    }

    $statusBytes = [IO.File]::ReadAllBytes($statusPath)
    $status = Read-JsonText (Convert-ZipText $statusBytes) `
        'powered-off final status'
    Assert-BoundIdentity $status 'powered-off final status' $Campaign.CampaignId `
        $Campaign.ManifestHash $Campaign.SourceCommit
    $statusStart = ConvertTo-UtcTime `
        (Get-RequiredValue $status 'campaign_start_utc' 'powered-off final status') `
        'powered-off final status campaign start'
    $completed = ConvertTo-UtcTime `
        (Get-RequiredValue $status 'completed_utc' 'powered-off final status') `
        'powered-off final status completion'
    $overallPass = Get-RequiredValue $status 'overall_pass' 'powered-off final status'
    if ($overallPass -isnot [bool] -or $overallPass -or
        $statusStart -ne $Campaign.CampaignStartUtc -or
        $completed -lt $Campaign.CampaignStartUtc -or
        $completed -gt [DateTime]::UtcNow.AddMinutes(5)) {
        throw 'Powered-off final status is not a fresh terminal failure.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        if ($archive.Entries.Count -eq 0 -or $archive.Entries.Count -gt 4096) {
            throw "Failure ZIP entry count is unsafe: $($archive.Entries.Count)"
        }
        $entries = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal)
        $namesIgnoreCase = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $buffer = New-Object byte[] (1024 * 1024)
        [int64]$totalBytes = 0
        foreach ($entry in $archive.Entries) {
            $name = ConvertTo-SafeZipEntryName ([string]$entry.FullName) `
                'Failure ZIP'
            if (-not $namesIgnoreCase.Add($name)) {
                throw "Failure ZIP contains a duplicate path: $name"
            }
            if ($entry.Length -gt 1GB) {
                throw "Failure ZIP entry is unreasonably large: $name"
            }
            $totalBytes += $entry.Length
            if ($totalBytes -gt 2GB) {
                throw 'Failure ZIP expands beyond the evidence limit.'
            }
            $entries.Add($name, $entry)
            if ($name.EndsWith('/')) { continue }
            $stream = $null
            try {
                $stream = $entry.Open()
                [int64]$readTotal = 0
                do {
                    $read = $stream.Read($buffer, 0, $buffer.Length)
                    $readTotal += $read
                } while ($read -ne 0)
                if ($readTotal -ne $entry.Length) {
                    throw "Failure ZIP entry length changed while reading: $name"
                }
            } finally {
                if ($null -ne $stream) { $stream.Dispose() }
            }
        }
        if (-not $entries.ContainsKey('final-status.json')) {
            throw 'Failure ZIP has no exact final-status.json entry.'
        }
        $archivedStatus = Read-ZipEntryBytes $entries['final-status.json'] 1MB
        if ([Convert]::ToBase64String($statusBytes) -cne
            [Convert]::ToBase64String($archivedStatus)) {
            throw 'Root and archived failure status bytes differ.'
        }

        $archivedFailureMessage = $null
        if ($status.PSObject.Properties.Name -ccontains 'fatal_failure_files') {
            $fatalNames = @($status.fatal_failure_files)
            if ($fatalNames.Count -gt 32) {
                throw 'Powered-off final status names too many fatal failure files.'
            }
            foreach ($fatalNameValue in $fatalNames) {
                if ($fatalNameValue -isnot [string] -or
                    $fatalNameValue -cnotmatch
                        '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}-failure\.txt$' -or
                    -not $entries.ContainsKey($fatalNameValue)) {
                    throw 'Powered-off final status names an invalid fatal failure file.'
                }
            }
            $messageName = if ($fatalNames -ccontains
                'baseline-running-failure.txt') {
                'baseline-running-failure.txt'
            } elseif ($fatalNames.Count -ne 0) {
                [string]($fatalNames | Sort-Object -CaseSensitive | Select-Object -First 1)
            }
            if ($null -ne $messageName) {
                $archivedFailureMessage = Convert-ZipText (
                    Read-ZipEntryBytes $entries[$messageName] 64KB)
            }
        }
    } finally {
        $archive.Dispose()
    }
    Test-ZipCrc $archivePath 'Failure ZIP'

    $statusHash = (Get-FileHash -LiteralPath $statusPath -Algorithm SHA256).Hash
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    $destination = Join-Path $resultPath 'failed-evidence'
    $temporary = Join-Path $resultPath `
        ".failed-evidence-$([Guid]::NewGuid().ToString('N')).tmp"
    if (Test-Path -LiteralPath $destination) {
        throw "Refusing to reuse a failure-evidence directory: $destination"
    }
    New-Item -ItemType Directory -Path $temporary | Out-Null
    $temporaryStatus = Join-Path $temporary 'final-status.json'
    $temporaryArchive = Join-Path $temporary 'oac-vm-results.zip'
    $temporaryHash = Join-Path $temporary 'oac-vm-results.sha256'
    $published = $false
    try {
        [IO.File]::Copy($statusPath, $temporaryStatus, $false)
        Clear-ReadOnlyFile $temporaryStatus
        [IO.File]::Copy($archivePath, $temporaryArchive, $false)
        Clear-ReadOnlyFile $temporaryArchive
        if ((Get-Item -LiteralPath $temporaryStatus).Length -ne $statusItem.Length -or
            (Get-FileHash -LiteralPath $temporaryStatus -Algorithm SHA256).Hash -cne
                $statusHash -or
            (Get-Item -LiteralPath $temporaryArchive).Length -ne $archiveItem.Length -or
            (Get-FileHash -LiteralPath $temporaryArchive -Algorithm SHA256).Hash -cne
                $archiveHash) {
            throw 'Copied powered-off evidence does not match the guest artifacts.'
        }
        [IO.File]::WriteAllText(
            $temporaryHash,
            "$archiveHash  oac-vm-results.zip`r`n",
            [Text.Encoding]::ASCII)
        [IO.Directory]::Move($temporary, $destination)
        $published = $true
    } finally {
        if (-not $published -and [IO.Directory]::Exists($temporary)) {
            foreach ($path in @($temporaryStatus, $temporaryArchive, $temporaryHash)) {
                try {
                    if ([IO.File]::Exists($path)) {
                        Clear-ReadOnlyFile $path
                        [IO.File]::Delete($path)
                    }
                } catch {
                    $cleanupMessage = Get-SafeFailureMessage $_.Exception.Message `
                        'unknown cleanup error'
                    Write-CleanupLog `
                        "Could not remove temporary failure evidence: $cleanupMessage"
                }
            }
            try {
                if (@(Get-ChildItem -LiteralPath $temporary -Force).Count -eq 0) {
                    [IO.Directory]::Delete($temporary)
                }
            } catch {
                $cleanupMessage = Get-SafeFailureMessage $_.Exception.Message `
                    'unknown cleanup error'
                Write-CleanupLog `
                    "Could not remove temporary evidence directory: $cleanupMessage"
            }
        }
    }

    $statusMessage = if ($status.PSObject.Properties.Name -ccontains 'fatal_message') {
        [string]$status.fatal_message
    } else {
        $null
    }
    $rawMessage = if (-not [string]::IsNullOrWhiteSpace($statusMessage)) {
        $statusMessage
    } elseif (-not [string]::IsNullOrWhiteSpace($archivedFailureMessage)) {
        $archivedFailureMessage
    } else {
        'baseline did not reach the safe snapshot boundary'
    }
    $message = Get-SafeFailureMessage $rawMessage `
        'baseline did not reach the safe snapshot boundary'
    return [pscustomobject]@{
        ArchiveHash = $archiveHash
        Destination = $destination
        Message = $message
    }
}

function Assert-FinalStatus([object]$Status) {
    Assert-BoundIdentity $Status 'final status' $script:GuestCampaignId `
        $script:ExpectedManifestHash $script:ExpectedSourceCommit
    $campaignStart = ConvertTo-UtcTime `
        (Get-RequiredValue $Status 'campaign_start_utc' 'final status') `
        'final status campaign start'
    $completed = ConvertTo-UtcTime `
        (Get-RequiredValue $Status 'completed_utc' 'final status') `
        'final status completion'
    if ($campaignStart -ne $script:GuestCampaignStartUtc -or
        $completed -lt $script:BaselineCompletedUtc -or
        $completed -gt [DateTime]::UtcNow.AddMinutes(5)) {
        throw 'Final status freshness or campaign start is invalid.'
    }

    $expectedCount = @(Get-ExpectedTestNames $false).Count
    Assert-IntegerValue (Get-RequiredValue $Status `
        'required_test_count' 'final status') $expectedCount `
        'final status required_test_count'
    Assert-IntegerValue (Get-RequiredValue $Status `
        'protocol_test_count' 'final status') 5 `
        'final status protocol_test_count'
    Assert-IntegerValue (Get-RequiredValue $Status `
        'client_scan_count' 'final status') 12 `
        'final status client_scan_count'
    Assert-IntegerValue (Get-RequiredValue $Status `
        'minidump_count' 'final status') 0 `
        'final status minidump_count'
    Assert-IntegerValue (Get-RequiredValue $Status `
        'crash_event_count' 'final status') 0 `
        'final status crash_event_count'
    foreach ($name in @(
            'exact_result_set_pass', 'verifier_reset_pass', 'verifier_inactive',
            'system_export_success', 'system_query_success',
            'code_integrity_export_success', 'code_integrity_query_success',
            'driver_gate_pass', 'production_boundary_pass', 'removal_boundary_pass',
            'kernel_provenance_pass', 'baseline_identity_pass', 'manifest_current',
            'services_contained', 'driver_gate_contained',
            'interactive_staging_removed', 'auto_logon_cleared',
            'recovery_task_present', 'tasks_contained_except_recovery',
            'containment_ready', 'overall_pass')) {
        Assert-Boolean $Status $name 'final status'
    }
    foreach ($name in @(
            'missing_test_results', 'unexpected_test_results',
            'malformed_test_results', 'wrong_test_results',
            'missing_auxiliary_results', 'unexpected_auxiliary_results',
            'malformed_auxiliary_results', 'wrong_auxiliary_results',
            'summary_errors',
            'crash_event_ids', 'temporary_oac_tasks', 'containment_errors',
            'fatal_failure_files')) {
        Assert-EmptyArray $Status $name 'final status'
    }
    $archivedTasks = @(Get-RequiredValue $Status 'remaining_oac_tasks' 'final status')
    Assert-ExactNames @($archivedTasks | ForEach-Object { [string]$_ }) `
        @('OAC-VM-Test') 'archived recovery task set'
    foreach ($name in @('baseline_unexpected_restart', 'verifier_unexpected_restart')) {
        $value = Get-RequiredValue $Status $name 'final status'
        if ($value -isnot [bool] -or $value) {
            throw "Final status requires $name=false."
        }
    }
    $states = Get-RequiredValue $Status 'service_states' 'final status'
    if ([string](Get-RequiredValue $states 'OACService' 'service states') -cne 'Stopped' -or
        [string](Get-RequiredValue $states 'OAC' 'service states') -cne 'Stopped') {
        throw 'Final status does not contain both OAC services.'
    }
}

function Test-EvidenceArchive([string]$EvidenceDirectory, [object]$StableProbe) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $statusPath = Join-Path $EvidenceDirectory 'final-status.json'
    $archivePath = Join-Path $EvidenceDirectory 'oac-vm-results.zip'
    $rootStatusBytes = [IO.File]::ReadAllBytes($statusPath)
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        if ($archive.Entries.Count -eq 0 -or $archive.Entries.Count -gt 4096) {
            throw "ZIP entry count is unsafe: $($archive.Entries.Count)"
        }
        $entries = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal)
        $namesIgnoreCase = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $buffer = New-Object byte[] (1024 * 1024)
        [int64]$totalBytes = 0
        foreach ($entry in $archive.Entries) {
            $name = ConvertTo-SafeZipEntryName ([string]$entry.FullName) 'ZIP'
            if (-not $namesIgnoreCase.Add($name)) {
                throw "ZIP contains a duplicate path: $name"
            }
            $entries.Add($name, $entry)
            if ($entry.Length -gt 1GB) {
                throw "ZIP entry is unreasonably large: $name"
            }
            $totalBytes += $entry.Length
            if ($totalBytes -gt 2GB) { throw 'ZIP expands beyond the evidence limit.' }
            if ($name.EndsWith('/')) { continue }
            $stream = $null
            try {
                $stream = $entry.Open()
                [int64]$readTotal = 0
                do {
                    $read = $stream.Read($buffer, 0, $buffer.Length)
                    $readTotal += $read
                } while ($read -ne 0)
                if ($readTotal -ne $entry.Length) {
                    throw "ZIP entry length changed while reading: $name"
                }
            } finally {
                if ($null -ne $stream) { $stream.Dispose() }
            }
        }

        if (-not $entries.ContainsKey('final-status.json')) {
            throw 'The ZIP has no archived final-status.json.'
        }
        $archivedStatusBytes = Read-ZipEntryBytes $entries['final-status.json'] 1MB
        if ([Convert]::ToBase64String($rootStatusBytes) -cne
            [Convert]::ToBase64String($archivedStatusBytes)) {
            throw 'Root and archived final status bytes differ.'
        }
        $status = Read-JsonText (Convert-ZipText $rootStatusBytes) 'final status'
        Assert-FinalStatus $status

        $expected = Get-ExpectedTestNames $false
        $exitEntries = @($entries.Keys | Where-Object {
                $_.EndsWith(
                    '.exitcode.txt',
                    [StringComparison]::OrdinalIgnoreCase)
            })
        $unsafeExitEntries = @($exitEntries | Where-Object {
                $_ -match '/' -or
                -not $_.EndsWith(
                    '.exitcode.txt',
                    [StringComparison]::Ordinal)
            })
        if ($unsafeExitEntries.Count -ne 0) {
            throw "The ZIP contains unsafe exit-code entries: $($unsafeExitEntries -join ', ')"
        }
        $exitValues = [Collections.Generic.Dictionary[string, int64]]::new(
            [StringComparer]::Ordinal)
        foreach ($entryName in $exitEntries) {
            $name = $entryName.Substring(0, $entryName.Length - '.exitcode.txt'.Length)
            $text = Convert-ZipText (Read-ZipEntryBytes $entries[$entryName] 128)
            $exitValues.Add($name, (Read-ExitCode $text $name))
        }
        $formalObserved = @($exitValues.Keys | Where-Object { $expected -ccontains $_ })
        Assert-ExactNames $formalObserved $expected 'archived test result set'
        foreach ($name in $expected) {
            Assert-ExitValue $name $exitValues[$name]
        }
        $auxiliaryValues = [Collections.Generic.Dictionary[string, int64]]::new(
            [StringComparer]::Ordinal)
        foreach ($name in $exitValues.Keys) {
            if ($expected -cnotcontains $name) {
                $auxiliaryValues.Add($name, $exitValues[$name])
            }
        }
        Assert-AuxiliaryExitResults $auxiliaryValues $true 'archived results'

        foreach ($name in $summaryNames) {
            $entryName = "$name.json"
            if (-not $entries.ContainsKey($entryName)) {
                throw "The ZIP has no $entryName."
            }
            $summary = Read-JsonText `
                (Convert-ZipText (Read-ZipEntryBytes $entries[$entryName] 1MB)) $name
            if ($name -ceq 'production-boundary-summary') {
                Assert-ProductionBoundarySummary $summary $name
            } elseif ($name -ceq 'baseline-driver-gate-summary') {
                Assert-DriverGateSummary $summary $name
            } else {
                Assert-Boolean $summary 'pass' $name
            }
        }
        if (-not $entries.ContainsKey('baseline-summary.json')) {
            throw 'The ZIP has no baseline-summary.json.'
        }
        $baselineSummary = Read-JsonText (Convert-ZipText `
            (Read-ZipEntryBytes $entries['baseline-summary.json'] 1MB)) `
            'archived baseline summary'
        Assert-CampaignFields $baselineSummary 'archived baseline summary' `
            $script:GuestCampaignId $script:ExpectedManifestHash `
            $script:ExpectedSourceCommit
        Assert-Boolean $baselineSummary 'pass' 'archived baseline summary'
        Assert-EmptyArray $baselineSummary 'exit_failures' 'archived baseline summary'
        $failureEntries = @($entries.Keys | Where-Object {
                [IO.Path]::GetFileName($_) -like '*-failure.txt'
            })
        if ($failureEntries.Count -ne 0) {
            throw "The ZIP contains failure evidence: $($failureEntries -join ', ')"
        }
    } finally {
        $archive.Dispose()
    }

    Test-ZipCrc $archivePath 'ZIP'

    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    if ($archiveHash -cne [string]$StableProbe.archive_info.sha256) {
        throw 'The validated ZIP hash changed after retrieval.'
    }
    [IO.File]::WriteAllText(
        (Join-Path $EvidenceDirectory 'oac-vm-results.sha256'),
        "$archiveHash  oac-vm-results.zip`r`n",
        [Text.Encoding]::ASCII)
    return [pscustomobject]@{
        Status = Read-JsonText ([IO.File]::ReadAllText($statusPath)) 'final status'
        ArchiveHash = $archiveHash
    }
}

function Assert-LiveContainment([object]$StableProbe) {
    $probe = Invoke-VMDirectBounded -TimeoutSeconds 45 -ScriptBlock {
        $root = 'C:\OACTest'
        $verifierText = & verifier.exe /querysettings 2>&1 | Out-String
        $verifierExit = $LASTEXITCODE
        $states = [ordered]@{}
        foreach ($name in @('OACService', 'OAC')) {
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            $states[$name] = if ($null -eq $service) { 'missing' } else {
                [string]$service.Status
            }
        }
        [pscustomobject]@{
            phase = ((Get-Content -LiteralPath (Join-Path $root 'phase.txt') -Raw) `
                -replace "`0", '').Trim()
            marker = Get-Content -LiteralPath `
                (Join-Path $root 'containment-ready.json') -Raw
            authorization_present = Test-Path -LiteralPath `
                (Join-Path $root 'verifier-authorized.json')
            tasks = @(Get-ScheduledTask -ErrorAction Stop |
                Where-Object TaskName -Like 'OAC-VM-*' |
                Select-Object -ExpandProperty TaskName -Unique)
            service_states = $states
            gate_service_present = $null -ne `
                (Get-Service -Name 'OACGateProbe' -ErrorAction SilentlyContinue)
            gate_image_present = Test-Path -LiteralPath `
                (Join-Path $root 'OAC-Gate-Probe.sys')
            verifier_exit = $verifierExit
            verifier_text = $verifierText
            status_sha256 = (Get-FileHash -LiteralPath `
                (Join-Path $root 'final-status.json') -Algorithm SHA256).Hash
            archive_sha256 = (Get-FileHash -LiteralPath `
                (Join-Path $root 'results.zip') -Algorithm SHA256).Hash
        }
    }

    Assert-Marker ([string]$probe.marker) 'live containment-ready marker'
    if ($probe.phase -cne 'complete' -or $probe.authorization_present -or
        @($probe.tasks).Count -ne 0 -or $probe.gate_service_present -or
        $probe.gate_image_present -or
        [string]$probe.service_states.OACService -cne 'Stopped' -or
        [string]$probe.service_states.OAC -cne 'Stopped' -or
        [int]$probe.verifier_exit -notin @(0, 2) -or
        [string]$probe.status_sha256 -cne [string]$StableProbe.status_info.sha256 -or
        [string]$probe.archive_sha256 -cne [string]$StableProbe.archive_info.sha256) {
        throw 'The live guest failed its final containment contract.'
    }
    $targets = @([regex]::Matches(
            [string]$probe.verifier_text,
            '(?im)^\s*([^\s]+\.sys)\s*$') |
        ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } |
        Sort-Object -Unique)
    if ($targets.Count -ne 0) {
        throw "Driver Verifier still names drivers: $($targets -join ', ')"
    }
}

function Assert-ZeroNetworkAdapters {
    $adapters = @(Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop)
    if ($adapters.Count -ne 0) {
        throw "The disposable VM has $($adapters.Count) network adapters; expected zero."
    }
}

function Stop-TestVM([bool]$AllowTurnOff) {
    $vm = Get-VM -Name $VMName -ErrorAction Stop
    if ($vm.State -eq 'Off') { return }
    if ($vm.State -eq 'Running') {
        try {
            Invoke-VMDirectBounded -TimeoutSeconds 15 -ScriptBlock {
                & shutdown.exe /s /t 0 /f | Out-Null
            } | Out-Null
        } catch { }
        $deadline = [DateTime]::UtcNow.AddMinutes(5)
        while ((Get-VM -Name $VMName).State -ne 'Off' -and
            [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 5
        }
    }
    if ((Get-VM -Name $VMName).State -ne 'Off' -and $AllowTurnOff) {
        Stop-VM -Name $VMName -TurnOff -Force -Confirm:$false
    }
    if ((Get-VM -Name $VMName).State -ne 'Off') {
        throw 'The disposable VM could not be left powered off.'
    }
}

if ([string]::IsNullOrWhiteSpace($VMName) -or
    [IO.Path]::GetFileName($VMName) -cne $VMName -or
    $VMName.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
    throw 'VMName must be a nonempty file-safe leaf name.'
}
if ($InstallTimeout -le [TimeSpan]::Zero -or
    $BaselineTimeout -le [TimeSpan]::Zero -or
    $TestTimeout -le [TimeSpan]::Zero) {
    throw 'InstallTimeout, BaselineTimeout, and TestTimeout must be positive.'
}
foreach ($path in @($WindowsIso, $SeedIso)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required ISO does not exist: $path"
    }
    if ([IO.Path]::GetExtension($path) -cne '.iso') {
        throw "Expected an .iso image: $path"
    }
}
$requiredCommands = @(
    'New-VM', 'Get-VMHost', 'Get-VHD', 'Mount-VHD', 'Dismount-VHD',
    'Get-Disk', 'Get-Partition', 'Get-Volume', 'Get-DiskImage',
    'Mount-DiskImage', 'Dismount-DiskImage', 'Checkpoint-VM', 'tar.exe')
foreach ($name in $requiredCommands) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "Required Windows virtualization command is unavailable: $name"
    }
}
try { $null = Get-VMHost } catch {
    throw 'This account cannot manage Hyper-V. Run elevated as a Hyper-V administrator.'
}
if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
    throw "Refusing to replace an existing VM: $VMName"
}

$windowsIsoPath = [IO.Path]::GetFullPath($WindowsIso)
$seedIsoPath = [IO.Path]::GetFullPath($SeedIso)
$vmRootPath = [IO.Path]::GetFullPath($VMRoot)
$resultPath = [IO.Path]::GetFullPath($ResultDirectory)
$script:VhdPath = [IO.Path]::Combine($vmRootPath, "$VMName.vhdx")
if (Test-Path -LiteralPath $script:VhdPath) {
    throw "Refusing to overwrite an existing VHDX: $script:VhdPath"
}
if (Test-Path -LiteralPath $resultPath) {
    throw "ResultDirectory must be new; refusing existing path: $resultPath"
}
if ($resultPath.TrimEnd('\') -ieq $vmRootPath.TrimEnd('\')) {
    throw 'ResultDirectory and VMRoot must be different directories.'
}

$seedIdentity = Read-SeedIdentity $seedIsoPath
$script:ExpectedManifestHash = $seedIdentity.ManifestHash
$script:ExpectedSourceCommit = $seedIdentity.SourceCommit

New-Item -ItemType Directory -Path $vmRootPath -Force | Out-Null
New-Item -ItemType Directory -Path $resultPath | Out-Null
if (@(Get-ChildItem -LiteralPath $resultPath -Force).Count -ne 0) {
    throw 'The newly created result directory is not empty.'
}
$script:HostLog = Join-Path $resultPath 'hyperv-orchestrator.log'
$script:HostRecordPath = Join-Path $resultPath 'hyperv-vm-manifest.json'
$script:HostRecord = [ordered]@{
    schema = 2
    orchestration_started_utc = $script:OrchestrationStartUtc.ToString('o')
    state = 'preflight-complete'
    vm_name = $VMName
    windows_iso = $windowsIsoPath
    windows_iso_sha256 = (Get-FileHash -LiteralPath $windowsIsoPath `
        -Algorithm SHA256).Hash
    seed_iso = $seedIsoPath
    seed_iso_sha256 = (Get-FileHash -LiteralPath $seedIsoPath -Algorithm SHA256).Hash
    expected_manifest_sha256 = $script:ExpectedManifestHash
    expected_source_commit = $script:ExpectedSourceCommit
    vhdx = $script:VhdPath
}
Save-HostRecord

$guestPassword = ConvertTo-SecureString 'OacTest!2026' -AsPlainText -Force
$script:GuestCredential = [Management.Automation.PSCredential]::new(
    'OAC-HV\OACAdmin', $guestPassword)

try {
    Write-HostLog 'Creating isolated Generation 2 Hyper-V VM.'
    $vm = New-VM -Name $VMName -Generation 2 -Path $vmRootPath `
        -MemoryStartupBytes 8GB -NewVHDPath $script:VhdPath `
        -NewVHDSizeBytes 80GB
    $script:VmCreated = $true
    Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -CheckpointType Standard `
        -AutomaticStartAction Nothing -AutomaticStopAction TurnOff
    Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false -StartupBytes 8GB
    Set-VMProcessor -VMName $VMName -Count 2 -ExposeVirtualizationExtensions $false
    Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue |
        Remove-VMNetworkAdapter -Confirm:$false
    Assert-ZeroNetworkAdapters

    $windowsDvd = Add-VMDvdDrive -VMName $VMName -Path $windowsIsoPath -Passthru
    $seedDvd = Add-VMDvdDrive -VMName $VMName -Path $seedIsoPath -Passthru
    $hardDrives = @(Get-VMHardDiskDrive -VMName $VMName)
    if ($hardDrives.Count -ne 1) { throw 'The fresh VM must have exactly one VHD.' }
    Set-VMFirmware -VMName $VMName -EnableSecureBoot Off `
        -BootOrder @($hardDrives[0], $windowsDvd, $seedDvd)
    if (@(Get-VMSnapshot -VMName $VMName -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'The fresh VM unexpectedly has a checkpoint.'
    }
    $script:HostRecord['state'] = 'vm-created'
    $script:HostRecord['vm_created_utc'] = [DateTime]::UtcNow.ToString('o')
    $script:HostRecord['generation'] = 2
    $script:HostRecord['processors'] = 2
    $script:HostRecord['memory_bytes'] = 8GB
    $script:HostRecord['network_adapters'] = 0
    $script:HostRecord['secure_boot'] = $false
    Save-HostRecord

    Write-HostLog 'Starting unattended Windows installation and baseline tests.'
    Start-VM -Name $VMName | Out-Null
    Wait-ForBaselineOff -InstallBound $InstallTimeout `
        -BaselineBound $BaselineTimeout
    Assert-ZeroNetworkAdapters
    $vhd = Get-VHD -Path $script:VhdPath
    if ($vhd.FileSize -lt 5GB) {
        throw "Windows installation is implausibly small: $($vhd.FileSize) bytes."
    }

    Write-HostLog 'Validating the powered-off baseline through a read-only VHD mount.'
    $liveCampaignId = $script:GuestCampaignId
    $liveCampaignStartUtc = $script:GuestCampaignStartUtc
    $baseline = Invoke-WithVhdRoot $script:VhdPath $true ${function:Read-BaselineState}
    if (($null -ne $liveCampaignId -and
            $liveCampaignId -cne $baseline.CampaignId) -or
        ($liveCampaignStartUtc -ne [DateTime]::MinValue -and
            $liveCampaignStartUtc -ne $baseline.CampaignStartUtc)) {
        throw 'Powered-off baseline identity changed after the live guest probe.'
    }
    $script:GuestCampaignId = $baseline.CampaignId
    $script:GuestCampaignStartUtc = $baseline.CampaignStartUtc
    $script:BaselineCompletedUtc = $baseline.BaselineCompletedUtc
    $script:HostRecord['campaign_id'] = $script:GuestCampaignId
    $script:HostRecord['campaign_start_utc'] = `
        $script:GuestCampaignStartUtc.ToString('o')
    $script:HostRecord['baseline_completed_utc'] = `
        $script:BaselineCompletedUtc.ToString('o')
    $script:HostRecord['baseline_result_count'] = `
        @(Get-ExpectedTestNames $true).Count
    $script:HostRecord['state'] = 'baseline-validated'
    Save-HostRecord

    Write-HostLog 'Creating the safe pre-Verifier checkpoint.'
    $checkpointName = 'OAC-Baseline-Pre-Verifier'
    $checkpoint = Checkpoint-VM -Name $VMName -SnapshotName $checkpointName -Passthru
    $checkpoints = @(Get-VMSnapshot -VMName $VMName)
    if ($checkpoints.Count -ne 1 -or $checkpoint.Id -ne $checkpoints[0].Id) {
        throw 'The VM checkpoint set is not the expected single safe baseline.'
    }
    $safeDrives = @(Get-VMHardDiskDrive -VMSnapshot $checkpoint)
    $activeDrives = @(Get-VMHardDiskDrive -VMName $VMName)
    if ($safeDrives.Count -ne 1 -or $activeDrives.Count -ne 1) {
        throw 'Checkpoint disk topology is not one safe parent and one active child.'
    }
    $safePath = [IO.Path]::GetFullPath($safeDrives[0].Path)
    $activePath = [IO.Path]::GetFullPath($activeDrives[0].Path)
    if ($safePath -ieq $activePath) {
        throw 'Checkpoint creation did not produce a distinct active child disk.'
    }
    $activeVhd = Get-VHD -Path $activePath
    if ([string]$activeVhd.VhdType -cne 'Differencing' -or
        [IO.Path]::GetFullPath($activeVhd.ParentPath) -ine $safePath) {
        throw 'The active VHD is not a child of the safe baseline checkpoint.'
    }
    Invoke-WithVhdRoot $safePath $true ${function:Assert-SafeCheckpointRoot}

    Write-HostLog 'Writing one-use Verifier authorization only to the active child.'
    Invoke-WithVhdRoot $activePath $false ${function:Write-VerifierAuthorization}
    Invoke-WithVhdRoot $activePath $true ${function:Assert-ActiveAuthorization}
    Invoke-WithVhdRoot $safePath $true ${function:Assert-SafeCheckpointRoot}
    $script:HostRecord['checkpoint_name'] = $checkpointName
    $script:HostRecord['checkpoint_id'] = [string]$checkpoint.Id
    $script:HostRecord['checkpoint_vhd'] = $safePath
    $script:HostRecord['active_child_vhd'] = $activePath
    $script:HostRecord['verifier_authorized_utc'] = [DateTime]::UtcNow.ToString('o')
    $script:HostRecord['state'] = 'verifier-authorized'
    Save-HostRecord

    Write-HostLog 'Starting the bounded Driver Verifier campaign.'
    Start-VM -Name $VMName | Out-Null
    $stableProbe = Wait-ForStableResults $TestTimeout
    $evidencePath = Join-Path $resultPath 'evidence'
    Copy-GuestEvidence $stableProbe $evidencePath
    $validated = Test-EvidenceArchive $evidencePath $stableProbe
    Assert-LiveContainment $stableProbe
    Assert-ZeroNetworkAdapters

    Write-HostLog 'Final containment validated; shutting down the guest.'
    Stop-TestVM $false
    Assert-ZeroNetworkAdapters
    if ((Get-VM -Name $VMName).State -ne 'Off') {
        throw 'The completed disposable VM is not powered off.'
    }
    $script:HostRecord['state'] = 'complete'
    $script:HostRecord['completed_utc'] = [DateTime]::UtcNow.ToString('o')
    $script:HostRecord['evidence_directory'] = $evidencePath
    $script:HostRecord['results_zip_sha256'] = $validated.ArchiveHash
    $script:HostRecord['overall_pass'] = $true
    $script:HostRecord['final_vm_state'] = 'Off'
    $script:HostRecord['final_network_adapters'] = 0
    Save-HostRecord
    Write-HostLog 'Hyper-V campaign completed; evidence is validated and the VM is off.'
    $validated.Status | ConvertTo-Json -Depth 8
} catch {
    $failure = $_
    Write-CleanupLog "Campaign failed: $($failure.Exception.Message)"
    if ($script:VmCreated) {
        try { Stop-TestVM $true } catch {
            Write-CleanupLog "Containment shutdown also failed: $($_.Exception.Message)"
        }
        try {
            Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop |
                Remove-VMNetworkAdapter -Confirm:$false
        } catch {
            Write-CleanupLog "Network-adapter removal also failed: $($_.Exception.Message)"
        }
        try { Assert-ZeroNetworkAdapters } catch {
            Write-CleanupLog "Final network containment failed: $($_.Exception.Message)"
        }
    }
    $script:HostRecord['state'] = 'failed'
    $script:HostRecord['failed_utc'] = [DateTime]::UtcNow.ToString('o')
    $script:HostRecord['failure'] = $failure.Exception.Message
    try { Save-HostRecord } catch { }
    throw
}
