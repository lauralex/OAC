[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = 'C:\OACTest'
$results = Join-Path $root 'results'
$phasePath = Join-Path $root 'phase.txt'
$phaseBackupPath = Join-Path $root 'phase.previous.txt'
$verifierAuthorizationPath = Join-Path $root 'verifier-authorized.json'
$containmentReadyPath = Join-Path $root 'containment-ready.json'
$runLog = Join-Path $results 'orchestrator.log'
$workerLatencyLimitMicroseconds = 500000
$threadSuspensionLimitMicroseconds = 50000
$validPhases = @(
    'post-testsigning', 'baseline-running', 'baseline-complete',
    'verifier-authorized', 'verifier-armed', 'verifier-running',
    'finalize', 'complete')
$requiredZeroTests = @(
    'baseline-install',
    'baseline-remove',
    'baseline-reinstall',
    'baseline-protocol-unit',
    'baseline-protocol',
    'baseline-preflight',
    'baseline-launch',
    'baseline-client',
    'production-launcher-1',
    'production-launcher-scan',
    'production-launcher-2',
    'production-launcher-3',
    'production-launch',
    'production-launch-graceful',
    'production-direct-open-localsystem',
    'production-direct-open-limited',
    'production-direct-open-administrator',
    'verifier-protocol-1',
    'verifier-protocol-2',
    'verifier-protocol-3',
    'verifier-preflight',
    'verifier-launch',
    'verifier-client-1',
    'verifier-client-2')
$baselineZeroTests = @($requiredZeroTests | Where-Object {
        $_ -notlike 'verifier-*'
    })
$baselineSpecialTests = @(
    'baseline-remove-repeat-expected-refusal',
    'production-manifest-modified',
    'production-manifest-wrong-build',
    'production-manifest-expired',
    'production-manifest-rollback',
    'production-policy-wrong-signature',
    'production-policy-wrong-scope',
    'production-policy-expired',
    'production-policy-rollback',
    'production-policy-authorized-rollback',
    'production-policy-emergency-revoke',
    'production-backend-replay',
    'baseline-driver-gate-create',
    'baseline-driver-gate-trigger',
    'baseline-driver-gate-detection',
    'baseline-driver-gate-stop',
    'baseline-driver-gate-delete')
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
    'production-backend-recovery-disable' = @(0)
    'production-backend-recovery-restore' = @(0)
    'production-backend-ack-start' = @(0)
    'production-backend-ack-launch' = @(0)
    'production-backend-ack-recovered' = @(0)
    'production-backend-lease-start' = @(0)
    'production-backend-lease-launch' = @(0)
    'production-backend-lease-recovered' = @(0)
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
    'production-backend-recovery-disable',
    'production-backend-recovery-restore',
    'production-backend-ack-start',
    'production-backend-ack-launch',
    'production-backend-ack-recovered',
    'production-backend-lease-start',
    'production-backend-lease-launch',
    'production-backend-lease-recovered',
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
$script:CampaignId = $null
$script:CampaignStartUtc = [DateTime]::MinValue
$script:ManifestHash = $null
$script:SourceCommit = $null
$script:InteractiveTaskRoot = $null
New-Item -ItemType Directory -Path $results -Force | Out-Null

function Write-SerialLine([string]$Message) {
    try {
        $port = [IO.Ports.SerialPort]::new('COM1', 115200, 'None', 8, 'One')
        $port.WriteTimeout = 1000
        $port.Open()
        $port.WriteLine("[$([DateTime]::UtcNow.ToString('o'))] $Message")
        $port.Close()
        $port.Dispose()
    } catch { }
}

function Write-RunLog([string]$Message) {
    $line = "[$([DateTime]::UtcNow.ToString('o'))] $Message"
    Add-Content -LiteralPath $runLog -Value $line -Encoding UTF8
    Write-SerialLine "TEST $Message"
}

function Write-DurableAsciiFile(
    [string]$Path,
    [string]$Value,
    [AllowNull()][string]$BackupPath = $null) {
    $temporaryPath = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $automaticBackupPath = $null
    $bytes = [Text.Encoding]::ASCII.GetBytes("$Value`r`n")
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        if ([IO.File]::Exists($Path)) {
            if ([string]::IsNullOrWhiteSpace($BackupPath)) {
                $automaticBackupPath = "$Path.$([Guid]::NewGuid().ToString('N')).bak"
                [IO.File]::Replace(
                    $temporaryPath,
                    $Path,
                    $automaticBackupPath,
                    $true)
                [IO.File]::Delete($automaticBackupPath)
                $automaticBackupPath = $null
            } else {
                [IO.File]::Replace($temporaryPath, $Path, $BackupPath, $true)
            }
        } else {
            [IO.File]::Move($temporaryPath, $Path)
        }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
        if ($null -ne $automaticBackupPath -and
            [IO.File]::Exists($automaticBackupPath)) {
            [IO.File]::Delete($automaticBackupPath)
        }
    }
}

function Read-ValidPhase([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { return $null }
    try {
        $value = ([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Path)) `
            -replace "`0", '').Trim()
        if ($validPhases -contains $value) { return $value }
    } catch { }
    return $null
}

function Get-TestPhase {
    $current = Read-ValidPhase $phasePath
    if ($current) { return $current }

    # File.Replace preserves the previous durable phase.  If a bugcheck lands
    # exactly on a transition, classify the interrupted successor
    # conservatively so the containment branch runs instead of repeating the
    # risky test forever.
    $previous = Read-ValidPhase $phaseBackupPath
    switch ($previous) {
        'post-testsigning' { return 'baseline-running' }
        'baseline-running' { return 'baseline-running' }
        'baseline-complete' { return 'verifier-authorized' }
        'verifier-authorized' { return 'verifier-running' }
        'verifier-armed' { return 'verifier-running' }
        'verifier-running' { return 'finalize' }
        'finalize' { return 'complete' }
        default { return 'missing' }
    }
}

function Set-Phase([string]$Phase) {
    if ($validPhases -notcontains $Phase) { throw "Invalid test phase: $Phase" }
    Write-DurableAsciiFile $phasePath $Phase $phaseBackupPath
    $script:CurrentPhase = $Phase
    Write-RunLog "Phase set to $Phase"
}

function Invoke-NativeCapture(
    [string]$Name,
    [string]$FilePath,
    [string[]]$Arguments = @(),
    [TimeSpan]$Timeout = '00:05:00') {
    if ($Timeout.TotalMilliseconds -lt 1 -or
        $Timeout.TotalMilliseconds -gt [int]::MaxValue) {
        throw "Invalid timeout for ${Name}: $Timeout"
    }
    $stdout = Join-Path $results "$Name.stdout.txt"
    $stderr = Join-Path $results "$Name.stderr.txt"
    Write-RunLog "Starting $Name"
    $startParameters = @{
        FilePath = $FilePath
        WindowStyle = 'Hidden'
        PassThru = $true
        RedirectStandardOutput = $stdout
        RedirectStandardError = $stderr
    }
    if ($Arguments.Count -ne 0) { $startParameters.ArgumentList = $Arguments }
    $process = Start-Process @startParameters
    try {
        # Keep the native handle alive. Windows PowerShell can otherwise expose
        # a null ExitCode after a short-lived redirected process exits.
        $processHandle = $process.Handle
        if ($processHandle -eq [IntPtr]::Zero) {
            try { $process.Kill() } catch { }
            throw "$Name did not expose a valid process handle."
        }
        if (-not $process.WaitForExit([int]$Timeout.TotalMilliseconds)) {
            Write-DurableAsciiFile (Join-Path $results "$Name.timeout.txt") `
                ([DateTime]::UtcNow.ToString('o'))
            try {
                $killer = Start-Process -FilePath 'taskkill.exe' `
                    -ArgumentList @('/PID', [string]$process.Id, '/T', '/F') `
                    -WindowStyle Hidden -PassThru
                if (-not $killer.WaitForExit(10000)) { $killer.Kill() }
                $killer.Dispose()
            } catch {
                try { $process.Kill() } catch { }
            }
            if (-not $process.HasExited) {
                try { $process.Kill() } catch { }
            }
            throw "$Name exceeded its bounded timeout of $Timeout."
        }
        # A second wait drains asynchronous redirected-stream completion.
        $process.WaitForExit()
        $rawExitCode = $process.ExitCode
        if ($null -eq $rawExitCode) {
            throw "$Name completed without a readable exit code."
        }
        $exitCode = [int]$rawExitCode
        Write-DurableAsciiFile (Join-Path $results "$Name.exitcode.txt") `
            ([string]$exitCode)
        Write-RunLog "$Name exited with $exitCode"
        return $exitCode
    } finally {
        $process.Dispose()
    }
}

function Invoke-ConsoleCapture(
    [string]$Name,
    [string]$FilePath,
    [string[]]$Arguments = @(),
    [TimeSpan]$Timeout = '00:05:00') {
    $exitCode = Invoke-NativeCapture $Name $FilePath $Arguments $Timeout
    $parts = [Collections.Generic.List[string]]::new()
    foreach ($path in @(
            (Join-Path $results "$Name.stdout.txt"),
            (Join-Path $results "$Name.stderr.txt"))) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $parts.Add((Get-Content -LiteralPath $path -Raw))
        }
    }
    [IO.File]::WriteAllText(
        (Join-Path $results "$Name.txt"),
        ($parts -join [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
    return $exitCode
}

function Read-CapturedExit([string]$Name) {
    $path = Join-Path $results "$Name.exitcode.txt"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required exit result is missing: $Name"
    }
    $text = (Get-Content -LiteralPath $path -Raw).Trim()
    $value = [int64]0
    if (-not [int64]::TryParse(
            $text,
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$value)) {
        throw "Exit result is malformed for ${Name}: $text"
    }
    return $value
}

function Get-AuxiliaryExitValidation(
    [string[]]$FormalNames,
    [bool]$Full) {
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
    $observed = [Collections.Generic.List[string]]::new()
    $unexpected = [Collections.Generic.List[string]]::new()
    $malformed = [Collections.Generic.List[string]]::new()
    $wrong = [Collections.Generic.List[string]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $results `
            -Filter '*.exitcode.txt' -File)) {
        if (-not $file.Name.EndsWith(
                '.exitcode.txt',
                [StringComparison]::Ordinal)) {
            $unexpected.Add($file.Name)
            continue
        }
        $name = $file.Name.Substring(0, $file.Name.Length - '.exitcode.txt'.Length)
        if ($FormalNames -ccontains $name) { continue }
        $observed.Add($name)
        if ($allowed -cnotcontains $name) {
            $unexpected.Add($name)
            continue
        }
        try {
            $value = Read-CapturedExit $name
            if (@($auxiliaryExitValues[$name]) -notcontains $value) {
                $wrong.Add("$name=$value")
            }
        } catch {
            $malformed.Add($name)
        }
    }
    $missing = @($required | Where-Object { $observed -cnotcontains $_ })
    return [pscustomobject]@{
        Missing = $missing
        Unexpected = @($unexpected)
        Malformed = @($malformed)
        Wrong = @($wrong)
    }
}

function Assert-VerifierTargets([string]$CaptureName, [bool]$ExpectOac) {
    $exitCode = Read-CapturedExit $CaptureName
    if ($exitCode -notin @(0, 2)) {
        throw "Verifier query failed for $CaptureName with exit code $exitCode."
    }
    $path = Join-Path $results "$CaptureName.txt"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Verifier query output is missing: $CaptureName"
    }
    $text = Get-Content -LiteralPath $path -Raw
    $targets = @([regex]::Matches(
            $text,
            '(?im)^\s*([^\s]+\.sys)\s*$') |
        ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } |
        Sort-Object -Unique)
    if ($ExpectOac) {
        if ($targets.Count -ne 1 -or $targets[0] -cne 'oac.sys') {
            throw "Verifier is not scoped exclusively to OAC.sys: $($targets -join ', ')"
        }
    } elseif ($targets.Count -ne 0) {
        throw "Verifier still names one or more drivers: $($targets -join ', ')"
    }
}

function Write-DurableUtf8File([string]$Path, [string]$Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Create,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None,
        4096,
        [IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Flush-FileData([string]$Path) {
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None,
        4096,
        [IO.FileOptions]::WriteThrough)
    try { $stream.Flush($true) } finally { $stream.Dispose() }
}

function Publish-FinalResult([object]$Status) {
    $statusPath = Join-Path $root 'final-status.json'
    $resultStatusPath = Join-Path $results 'final-status.json'
    $archivePath = Join-Path $root 'results.zip'
    $archiveTemporary = Join-Path $root `
        "results.$([Guid]::NewGuid().ToString('N')).tmp.zip"
    $statusTemporary = Join-Path $root `
        "final-status.$([Guid]::NewGuid().ToString('N')).tmp.json"
    Write-RunLog 'Serializing the archived final status with the direct UTF-8 writer.'
    $json = ConvertTo-Json -InputObject $Status -Depth 4
    Write-DurableUtf8File $resultStatusPath $json

    try {
        if ([IO.File]::Exists($archivePath) -or [IO.File]::Exists($statusPath)) {
            if ((Get-TestPhase) -eq 'complete') {
                throw 'Refusing to replace an already completed campaign result.'
            }
            # A root artifact without phase=complete was never accepted by the
            # host. Remove only these two campaign-local publication files so
            # an interrupted finalization can publish a coherent replacement.
            [IO.File]::Delete($statusPath)
            [IO.File]::Delete($archivePath)
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        Write-RunLog 'Creating the result archive with System.IO.Compression.ZipFile.'
        [IO.Compression.ZipFile]::CreateFromDirectory(
            $results,
            $archiveTemporary,
            [IO.Compression.CompressionLevel]::Optimal,
            $false)
        Flush-FileData $archiveTemporary
        [IO.File]::Move($archiveTemporary, $archivePath)

        # The root status is the readiness marker. Publish it only after the
        # archive is complete and visible at its final path.
        Write-DurableUtf8File $statusTemporary $json
        [IO.File]::Move($statusTemporary, $statusPath)
    } finally {
        foreach ($temporary in @($archiveTemporary, $statusTemporary)) {
            if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        }
    }
}

function Start-ScanTarget {
    $process = Start-Process -FilePath "$env:SystemRoot\System32\ping.exe" `
        -ArgumentList @('-t', '127.0.0.1') -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 2
    if ($process.HasExited) {
        $process.Dispose()
        throw 'The disposable scan target exited prematurely.'
    }
    Write-RunLog "Started scan target PID $($process.Id)"
    return $process
}

function Stop-ScanTarget(
    [Diagnostics.Process]$Process,
    [string]$CaptureName) {
    if ($null -eq $Process) { throw 'The scan target handle is missing.' }
    try {
        if ($Process.HasExited) {
            throw 'The disposable scan target exited before cleanup.'
        }
        $Process.Kill()
        if (-not $Process.WaitForExit(10000)) {
            throw "Scan target PID $($Process.Id) did not exit within the bounded wait."
        }
        $detail = "pid=$($Process.Id)`nprocess_exit_code=$($Process.ExitCode)`nreaped=true`n"
        Write-DurableUtf8File (Join-Path $results "$CaptureName.txt") $detail
        Write-DurableAsciiFile (Join-Path $results "$CaptureName.exitcode.txt") '0'
        Write-RunLog "$CaptureName exited with 0"
    } finally {
        $Process.Dispose()
    }
}

function Assert-ProtectedLaunchReport([string]$Directory, [string]$Context) {
    $path = Join-Path $Directory 'oac-report.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$Context did not publish oac-report.txt."
    }
    $lines = @(Get-Content -LiteralPath $path)
    $thresholdLines = @($lines | Where-Object {
            $_ -clike 'failure_threshold=*'
        })
    if ($thresholdLines.Count -ne 1 -or
        $thresholdLines[0] -cne 'failure_threshold=HIGH') {
        throw "$Context has the wrong failure threshold."
    }
    $targetExitLines = @($lines | Where-Object {
            $_ -match ' \[INFO\]\[monitor\] Protected target exited; exit-code='
        })
    if ($targetExitLines.Count -ne 1 -or
        $targetExitLines[0] -notmatch (
            '^seq=[1-9][0-9]* timestamp_100ns=[1-9][0-9]* ' +
            'chain=[0-9A-F]{64} \[INFO\]\[monitor\] ' +
            'Protected target exited; exit-code=0 pid=[1-9][0-9]*$')) {
        throw "$Context did not record one successful protected-target exit."
    }
    $unexpected = @($lines | Where-Object {
            $_ -match '^seq=[0-9]+ .+ \[(MEDIUM|HIGH|CRITICAL)\]\[' -and
            $_ -notmatch ('^seq=[1-9][0-9]* timestamp_100ns=[1-9][0-9]* ' +
                'chain=[0-9A-F]{64} \[MEDIUM\]\[kernel/handle\] ' +
                'Stripped protected-object mutation access: ' +
                'requested=0x[0-9A-F]{8} granted=0x[0-9A-F]{8} ' +
                'origin_seq=[1-9][0-9]* ' +
                'origin_timestamp_100ns=[1-9][0-9]* ' +
                'pid=[1-9][0-9]* tid=[1-9][0-9]* ' +
                'address=0x[0-9A-F]+$')
        })
    if ($unexpected.Count -ne 0) {
        throw "$Context contains unexpected actionable findings: $($unexpected -join '; ')"
    }
}

function Save-PlatformState([string]$Prefix) {
    Get-CimInstance Win32_OperatingSystem |
        Format-List * | Out-File -LiteralPath (Join-Path $results "$Prefix-os.txt") -Encoding utf8
    Get-CimInstance Win32_ComputerSystem |
        Format-List * | Out-File -LiteralPath (Join-Path $results "$Prefix-system.txt") -Encoding utf8
    Get-CimInstance Win32_Processor |
        Format-List * | Out-File -LiteralPath (Join-Path $results "$Prefix-cpu.txt") -Encoding utf8
    $bcdExit = Invoke-ConsoleCapture "$Prefix-bcd" 'bcdedit.exe' @('/enum', 'all')
    if ($bcdExit -ne 0) { throw "BCDEdit collection failed; exit code $bcdExit." }
    try {
        Confirm-SecureBootUEFI |
            Out-File -LiteralPath (Join-Path $results "$Prefix-secureboot.txt") -Encoding utf8
    } catch {
        $_ | Out-String | Out-File -LiteralPath `
            (Join-Path $results "$Prefix-secureboot.txt") -Encoding utf8
    }
}

function Initialize-CampaignContext {
    $campaignIdPath = Join-Path $root 'campaign-id.txt'
    $campaignStartPath = Join-Path $root 'campaign-start-utc.txt'
    $manifestHashPath = Join-Path $root 'campaign-manifest-sha256.txt'
    $sourceCommitPath = Join-Path $root 'campaign-source-commit.txt'
    $manifestPath = Join-Path $root 'package-manifest.json'
    foreach ($path in @(
            $campaignIdPath, $campaignStartPath, $manifestHashPath,
            $sourceCommitPath, $manifestPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Campaign metadata is missing: $path"
        }
    }

    $campaignId = (Get-Content -LiteralPath $campaignIdPath -Raw).Trim()
    $parsedId = [Guid]::Empty
    if (-not [Guid]::TryParseExact($campaignId, 'D', [ref]$parsedId) -or
        $parsedId -eq [Guid]::Empty) {
        throw 'The campaign ID is not a nonzero canonical GUID.'
    }
    $campaignStart = [DateTime]::MinValue
    if (-not [DateTime]::TryParse(
            (Get-Content -LiteralPath $campaignStartPath -Raw).Trim(),
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$campaignStart)) {
        throw 'The campaign start timestamp is invalid.'
    }
    $manifestHash = (Get-Content -LiteralPath $manifestHashPath -Raw).Trim()
    if ($manifestHash -notmatch '^[0-9A-F]{64}$' -or
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne
            $manifestHash) {
        throw 'The campaign manifest hash is invalid or stale.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $sourceCommit = (Get-Content -LiteralPath $sourceCommitPath -Raw).Trim()
    if ($sourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.source_commit -cne $sourceCommit) {
        throw 'The campaign source commit is invalid or does not match the manifest.'
    }

    $script:CampaignId = $parsedId.ToString('D')
    $script:CampaignStartUtc = $campaignStart.ToUniversalTime()
    $script:ManifestHash = $manifestHash
    $script:SourceCommit = $sourceCommit
    Write-RunLog `
        "Validated campaign $($script:CampaignId), manifest $manifestHash, and source $sourceCommit."
}

function Get-CampaignMarkerJson {
    return [ordered]@{
        schema = 1
        campaign_id = $script:CampaignId
        manifest_sha256 = $script:ManifestHash
        source_commit = $script:SourceCommit
    } | ConvertTo-Json -Compress
}

function Assert-CampaignMarker([string]$Path, [string]$Purpose) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Purpose marker is missing."
    }
    try {
        $marker = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        throw "$Purpose marker is not valid JSON."
    }
    $properties = @($marker.PSObject.Properties.Name)
    $expected = @('schema', 'campaign_id', 'manifest_sha256', 'source_commit')
    $markerId = [Guid]::Empty
    if ($properties.Count -ne $expected.Count -or
        @($properties | Where-Object { $_ -notin $expected }).Count -ne 0 -or
        ($marker.schema -isnot [int] -and $marker.schema -isnot [long]) -or
        [int64]$marker.schema -ne 1 -or
        $marker.campaign_id -isnot [string] -or
        -not [Guid]::TryParseExact(
            [string]$marker.campaign_id, 'D', [ref]$markerId) -or
        $markerId -eq [Guid]::Empty -or
        $marker.manifest_sha256 -isnot [string] -or
        $marker.source_commit -isnot [string] -or
        [string]$marker.campaign_id -cne $script:CampaignId -or
        [string]$marker.manifest_sha256 -cne $script:ManifestHash -or
        [string]$marker.source_commit -cne $script:SourceCommit) {
        throw "$Purpose marker does not match the current campaign."
    }
}

function Write-CampaignMarker([string]$Path) {
    $temporaryPath = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$Path.$([Guid]::NewGuid().ToString('N')).bak"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((Get-CampaignMarkerJson))
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        if ([IO.File]::Exists($Path)) {
            [IO.File]::Replace($temporaryPath, $Path, $backupPath, $true)
            [IO.File]::Delete($backupPath)
        } else {
            [IO.File]::Move($temporaryPath, $Path)
        }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        foreach ($temporary in @($temporaryPath, $backupPath)) {
            if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        }
    }
    Assert-CampaignMarker $Path 'Written campaign'
}

function Clear-LabAutoLogon {
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($name in @(
        'AutoAdminLogon', 'DefaultUserName', 'DefaultDomainName',
        'DefaultPassword', 'AutoLogonCount')) {
        Remove-ItemProperty -Path $winlogon -Name $name `
            -ErrorAction SilentlyContinue
    }
    Write-RunLog 'Removed the one-use lab auto-logon values.'
}

function Wait-ForInteractiveTestUser {
    $expectedUser = "$env:COMPUTERNAME\OACAdmin"
    $deadline = [DateTime]::UtcNow.AddMinutes(2)
    do {
        $explorers = @(Get-Process -Name explorer -IncludeUserName `
            -ErrorAction SilentlyContinue)
        $match = $explorers | Where-Object {
            $_.SessionId -gt 0 -and $_.UserName -ieq $expectedUser
        } | Select-Object -First 1
        if ($match) {
            $script:InteractiveUser = $expectedUser
            $script:InteractiveSessionId = $match.SessionId
            Write-RunLog "Interactive test user ready in session $($match.SessionId)."
            return
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'The bounded wait for the OACAdmin interactive session expired.'
}

function Get-InteractiveProfilePath {
    $userName = "$env:COMPUTERNAME\OACAdmin"
    $account = [Security.Principal.NTAccount]::new($userName)
    $userSid = $account.Translate([Security.Principal.SecurityIdentifier])
    $profiles = @(Get-CimInstance Win32_UserProfile | Where-Object {
            $_.SID -eq $userSid.Value -and $_.LocalPath
        })
    if ($profiles.Count -ne 1) {
        throw 'The interactive test user does not have one verifiable local profile.'
    }
    return [IO.Path]::GetFullPath([string]$profiles[0].LocalPath)
}

function Get-InteractiveTaskRootPath {
    return Join-Path (Get-InteractiveProfilePath) `
        ("AppData\Local\OAC-VM-Tasks\{0}" -f $script:CampaignId)
}

function Initialize-InteractiveTaskRoot {
    $account = [Security.Principal.NTAccount]::new($script:InteractiveUser)
    $userSid = $account.Translate([Security.Principal.SecurityIdentifier])
    $taskRoot = Get-InteractiveTaskRootPath
    if (Test-Path -LiteralPath $taskRoot) {
        throw "Interactive task staging already exists: $taskRoot"
    }
    New-Item -ItemType Directory -Path $taskRoot -Force | Out-Null

    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new(
                [Security.Principal.WellKnownSidType]::LocalSystemSid, $null),
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $userSid,
            [Security.AccessControl.FileSystemRights]::Modify,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $taskRoot -AclObject $acl
    $script:InteractiveTaskRoot = $taskRoot
    Write-RunLog "Created restricted interactive staging at $taskRoot."
}

function New-InteractiveTaskWorkspace([string]$Name) {
    if ([string]::IsNullOrWhiteSpace($script:InteractiveTaskRoot) -or
        -not (Test-Path -LiteralPath $script:InteractiveTaskRoot -PathType Container)) {
        throw 'Interactive task staging has not been initialized.'
    }
    if ($Name -notmatch '^[a-z0-9-]+$') {
        throw "Invalid interactive task name: $Name"
    }
    $path = [IO.Path]::GetFullPath((Join-Path $script:InteractiveTaskRoot $Name))
    $prefix = [IO.Path]::GetFullPath($script:InteractiveTaskRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Test-Path -LiteralPath $path)) {
        throw "Interactive task workspace is unsafe or already exists: $path"
    }
    New-Item -ItemType Directory -Path $path | Out-Null
    return $path
}

function Remove-InteractiveTaskWorkspace([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($script:InteractiveTaskRoot)) { return }
    $resolved = [IO.Path]::GetFullPath($Path)
    $prefix = [IO.Path]::GetFullPath($script:InteractiveTaskRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove an interactive workspace outside staging: $resolved"
    }
    if (Test-Path -LiteralPath $resolved) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

function Invoke-InteractiveTask(
    [string]$Name,
    [string]$Workspace,
    [ValidateSet('Limited', 'Highest')]
    [string]$RunLevel
) {
    $taskName = "OAC-VM-$Name"
    $scriptPath = Join-Path $Workspace 'task.ps1'
    $resultPath = Join-Path $Workspace 'result.txt'
    $outputPath = Join-Path $Workspace 'stdout.txt'
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Interactive task script is missing: $scriptPath"
    }
    Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false `
        -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument `
        "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId $script:InteractiveUser `
        -LogonType Interactive -RunLevel $RunLevel
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName -Action $action `
        -Principal $principal -Settings $settings -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTime]::UtcNow.AddSeconds(45)
        while (-not (Test-Path -LiteralPath $resultPath -PathType Leaf) -and
            [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 500
        }
        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            throw "Interactive task $Name exceeded its bounded wait."
        }
        $exitCode = [int64](Get-Content -LiteralPath $resultPath -Raw)
        $completionDeadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            if ($task.State -ne 'Running') { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $completionDeadline)
        if ($task.State -eq 'Running') {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            throw "Interactive task $Name produced a result but did not exit."
        }
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        if ([uint32]$taskInfo.LastTaskResult -ne [uint32]$exitCode) {
            throw "Interactive task $Name reported exit $exitCode but Task Scheduler recorded $($taskInfo.LastTaskResult)."
        }
        if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
            Copy-Item -LiteralPath $outputPath -Destination `
                (Join-Path $results "$Name.stdout.txt") -Force
        } else {
            throw "Interactive task $Name did not produce its output file."
        }
        Write-DurableAsciiFile (Join-Path $results "$Name.exitcode.txt") `
            ([string]$exitCode)
        Write-RunLog "$Name exited with $exitCode"
        return $exitCode
    } finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false `
            -ErrorAction SilentlyContinue
        Remove-InteractiveTaskWorkspace $Workspace
    }
}

function Wait-TestServiceState(
    [string]$Name,
    [ServiceProcess.ServiceControllerStatus]$State
) {
    $waitSeconds = if ($Name -ceq 'OACService' -and
        $State -eq [ServiceProcess.ServiceControllerStatus]::Running) {
        60
    } else {
        20
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($waitSeconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -eq $State) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Service $Name did not reach $State within the bounded wait."
}

function Stop-TestService([string]$CaptureName, [string]$ServiceName) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service -or $service.Status -eq 'Stopped') { return }
    $exitCode = Invoke-ConsoleCapture $CaptureName 'sc.exe' @('stop', $ServiceName)
    if ($exitCode -ne 0 -and $exitCode -ne 1062) {
        throw "Could not stop $ServiceName; sc.exe exit code $exitCode."
    }
    Wait-TestServiceState $ServiceName `
        ([ServiceProcess.ServiceControllerStatus]::Stopped)
}

function Start-TestService([string]$CaptureName, [string]$ServiceName) {
    $exitCode = Invoke-ConsoleCapture $CaptureName 'sc.exe' @('start', $ServiceName)
    if ($exitCode -ne 0 -and $exitCode -ne 1056) {
        throw "Could not start $ServiceName; sc.exe exit code $exitCode."
    }
    Wait-TestServiceState $ServiceName `
        ([ServiceProcess.ServiceControllerStatus]::Running)
}

function Set-DriverLabMode([ValidateSet(0, 1)][int]$Value) {
    $driver = Get-Service -Name OAC -ErrorAction Stop
    if ($driver.Status -ne 'Stopped') {
        throw 'LabMode may only be changed while the OAC driver is stopped.'
    }
    $parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\OAC\Parameters'
    New-Item -Path $parameters -Force | Out-Null
    New-ItemProperty -LiteralPath $parameters -Name LabMode -PropertyType DWord `
        -Value $Value -Force | Out-Null
    $actual = [int](Get-ItemProperty -LiteralPath $parameters -Name LabMode).LabMode
    if ($actual -ne $Value) { throw "Could not verify OAC LabMode=$Value." }
    Write-RunLog "OAC LabMode set to $Value while stopped."
}

function Write-TaskScript([string]$Path, [string]$Content) {
    [IO.File]::WriteAllText(
        $Path,
        $Content,
        [Text.UnicodeEncoding]::new($false, $true))
}

function Remove-RegularTestFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove an unsafe test file: $Path"
    }
    if ($item.IsReadOnly) { $item.IsReadOnly = $false }
    Remove-Item -LiteralPath $Path -Force
}

function Invoke-ProductionStatus([string]$Launcher, [string]$Name) {
    $workspace = New-InteractiveTaskWorkspace $Name
    $scriptPath = Join-Path $workspace 'task.ps1'
    $resultPath = Join-Path $workspace 'result.txt'
    $outputPath = Join-Path $workspace 'stdout.txt'
    $scriptText = @"
`$output = & '$Launcher' --status 2>&1
`$code = `$LASTEXITCODE
`$outputLines = @(`$output | ForEach-Object { `$_.ToString() })
[IO.File]::WriteAllLines(
    '$outputPath',
    [string[]]`$outputLines,
    [Text.UTF8Encoding]::new(`$false))
[IO.File]::WriteAllText('$resultPath', [string]`$code, [Text.Encoding]::ASCII)
exit `$code
"@
    Write-TaskScript $scriptPath $scriptText
    $exitCode = [int64](Invoke-InteractiveTask $Name $workspace 'Limited')
    $output = Get-Content -LiteralPath (Join-Path $results "$Name.stdout.txt") -Raw
    $matches = [regex]::Matches(
        $output,
        ('(?m)^OACService status; service-pid=([1-9][0-9]*); ' +
        'client-session=([0-9]+); driver-protocol=0x[0-9a-f]+; ' +
        'capabilities=0x[0-9a-f]+; flags=0x[0-9a-f]+; ' +
        'session-loss-sequence=([0-9]+); last-session-loss=([0-9]+); ' +
        'endpoint-config=0x([0-9a-f]+); driver-gate-trips=([0-9]+); ' +
        'endpoint-scan-id=([1-9][0-9]*); backend-lease=([0-9]+); ' +
        'backend-flags=0x([0-9a-f]+); ' +
        'backend-lease-sequence=([0-9]+); backend-acknowledged=([0-9]+); ' +
        'backend-pending=([0-9]+); backend-error=([0-9]+); ' +
        'scan-state=([0-9]+); scan-queued=([0-9]+); ' +
        'scan-completed=([0-9]+); scan-coalesced=([0-9]+); ' +
        'scan-cancelled=([0-9]+); scan-failed=([0-9]+); ' +
        'scan-sweeps=([0-9]+); scan-regions=([0-9]+); ' +
        'scan-bytes=([0-9]+); scan-threads=([0-9]+); ' +
        'scan-skipped=([0-9]+); health-iterations=([0-9]+); ' +
        'health-max-us=([0-9]+); scan-max-us=([0-9]+); ' +
        'suspend-max-us=([0-9]+)\r?$'))
    if ($exitCode -ne 0 -or $matches.Count -ne 1) {
        throw "$Name did not return one valid service status."
    }

    [int64]$serviceProcessId = 0
    [int64]$clientSessionId = -1
    [int64]$lossSequence = -1
    [int64]$lossReason = -1
    [uint64]$endpointConfiguration = 0
    [uint64]$driverGateTrips = 0
    [uint64]$endpointScanId = 0
    [uint64]$backendLease = 0
    [uint64]$backendFlags = 0
    [uint64]$backendLeaseSequence = 0
    [uint64]$backendAcknowledged = 0
    [uint64]$backendPending = 0
    [uint64]$backendError = 0
    $scanValues = [Collections.Generic.List[uint64]]::new()
    if (-not [int64]::TryParse($matches[0].Groups[1].Value, [ref]$serviceProcessId) -or
        -not [int64]::TryParse($matches[0].Groups[2].Value, [ref]$clientSessionId) -or
        -not [int64]::TryParse($matches[0].Groups[3].Value, [ref]$lossSequence) -or
        -not [int64]::TryParse($matches[0].Groups[4].Value, [ref]$lossReason) -or
        -not [uint64]::TryParse(
            $matches[0].Groups[5].Value,
            [Globalization.NumberStyles]::AllowHexSpecifier,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$endpointConfiguration) -or
        -not [uint64]::TryParse(
            $matches[0].Groups[6].Value, [ref]$driverGateTrips) -or
        -not [uint64]::TryParse(
            $matches[0].Groups[7].Value, [ref]$endpointScanId) -or
        -not [uint64]::TryParse(
            $matches[0].Groups[8].Value, [ref]$backendLease) -or
        -not [uint64]::TryParse(
            $matches[0].Groups[9].Value,
            [Globalization.NumberStyles]::AllowHexSpecifier,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$backendFlags) -or
        -not [uint64]::TryParse(
            $matches[0].Groups[10].Value, [ref]$backendLeaseSequence) -or
        -not [uint64]::TryParse(
            $matches[0].Groups[11].Value, [ref]$backendAcknowledged) -or
        -not [uint64]::TryParse(
            $matches[0].Groups[12].Value, [ref]$backendPending) -or
        -not [uint64]::TryParse(
            $matches[0].Groups[13].Value, [ref]$backendError) -or
        $serviceProcessId -le 0 -or $clientSessionId -lt 0 -or
        $lossSequence -lt 0 -or $lossReason -lt 0 -or
        $endpointConfiguration -ne 3 -or $driverGateTrips -ne 0 -or
        $endpointScanId -eq 0 -or
        $backendLease -ne 1 -or $backendFlags -ne 3 -or
        $backendLeaseSequence -eq 0 -or $backendError -ne 0) {
        throw "$Name returned malformed numeric status fields."
    }
    foreach ($groupIndex in 14..28) {
        [uint64]$scanValue = 0
        if (-not [uint64]::TryParse(
                $matches[0].Groups[$groupIndex].Value,
                [ref]$scanValue)) {
            throw "$Name returned a malformed scanner metric."
        }
        $scanValues.Add($scanValue)
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        ServiceProcessId = $serviceProcessId
        LossSequence = $lossSequence
        LossReason = $lossReason
        EndpointConfiguration = $endpointConfiguration
        DriverGateTrips = $driverGateTrips
        EndpointScanId = $endpointScanId
        BackendLease = $backendLease
        BackendFlags = $backendFlags
        BackendLeaseSequence = $backendLeaseSequence
        BackendAcknowledged = $backendAcknowledged
        BackendPending = $backendPending
        BackendError = $backendError
        ScanState = $scanValues[0]
        ScanQueued = $scanValues[1]
        ScanCompleted = $scanValues[2]
        ScanCoalesced = $scanValues[3]
        ScanCancelled = $scanValues[4]
        ScanFailed = $scanValues[5]
        ScanSweeps = $scanValues[6]
        ScanRegions = $scanValues[7]
        ScanBytes = $scanValues[8]
        ScanThreads = $scanValues[9]
        ScanSkipped = $scanValues[10]
        HealthIterations = $scanValues[11]
        HealthMaximumMicroseconds = $scanValues[12]
        ScanMaximumMicroseconds = $scanValues[13]
        SuspensionMaximumMicroseconds = $scanValues[14]
    }
}

function Invoke-ProductionLaunch(
    [string]$Launcher,
    [string]$Target,
    [string]$Name
) {
    $workspace = New-InteractiveTaskWorkspace $Name
    $scriptPath = Join-Path $workspace 'task.ps1'
    $resultPath = Join-Path $workspace 'result.txt'
    $outputPath = Join-Path $workspace 'stdout.txt'
    $scriptText = @"
`$output = & '$Launcher' --launch '$Target' 2>&1
`$code = `$LASTEXITCODE
`$output | Out-File -LiteralPath '$outputPath' -Encoding utf8
[IO.File]::WriteAllText('$resultPath', [string]`$code, [Text.Encoding]::ASCII)
exit `$code
"@
    Write-TaskScript $scriptPath $scriptText
    $exitCode = [int64](Invoke-InteractiveTask $Name $workspace 'Limited')
    $output = Get-Content -LiteralPath (Join-Path $results "$Name.stdout.txt") -Raw
    $matches = [regex]::Matches(
        $output,
        '(?m)^OACService launched target; target-pid=([1-9][0-9]*); binding=confirmed; job=assigned; thread=resumed\r?$')
    [int64]$targetProcessId = 0
    if ($exitCode -ne 0 -or $matches.Count -ne 1 -or
        -not [int64]::TryParse(
            $matches[0].Groups[1].Value,
            [ref]$targetProcessId) -or
        $targetProcessId -le 0) {
        throw "$Name did not return one valid target-launch result."
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        TargetProcessId = $targetProcessId
    }
}

function Invoke-RejectedLaunchAuthorization(
    [string]$Launcher,
    [string]$Target,
    [string]$Name,
    [string]$ExpectedDetail
) {
    $workspace = New-InteractiveTaskWorkspace $Name
    $scriptPath = Join-Path $workspace 'task.ps1'
    $resultPath = Join-Path $workspace 'result.txt'
    $outputPath = Join-Path $workspace 'stdout.txt'
    $scriptText = @"
`$output = & '$Launcher' --launch '$Target' 2>&1
`$code = `$LASTEXITCODE
`$outputLines = @(`$output | ForEach-Object { `$_.ToString() })
[IO.File]::WriteAllLines(
    '$outputPath',
    [string[]]`$outputLines,
    [Text.UTF8Encoding]::new(`$false))
[IO.File]::WriteAllText('$resultPath', [string]`$code, [Text.Encoding]::ASCII)
exit `$code
"@
    Write-TaskScript $scriptPath $scriptText
    $exitCode = [int64](Invoke-InteractiveTask $Name $workspace 'Limited')
    $output = Get-Content -LiteralPath (Join-Path $results "$Name.stdout.txt") -Raw
    $escapedDetail = [regex]::Escape($ExpectedDetail)
    $matches = [regex]::Matches(
        $output,
        "(?m)^OACService rejected the launch during manifest verification \($escapedDetail\): .+\r?$" )
    if ($exitCode -ne 5 -or $matches.Count -ne 1 -or
        $output -match '(?m)^OACService launched target;') {
        throw "$Name did not return the exact launch-authorization rejection."
    }
    return $exitCode
}

function Set-ProductionSignedRecordFiles(
    [string]$RecordSource,
    [string]$SignatureSource,
    [string]$RecordDestination,
    [string]$SignatureDestination,
    [int64]$ExpectedSize
) {
    $recordItem = Get-Item -LiteralPath $RecordSource -Force
    $signatureItem = Get-Item -LiteralPath $SignatureSource -Force
    if ($ExpectedSize -le 0 -or
        $recordItem.PSIsContainer -or $recordItem.Length -ne $ExpectedSize -or
        $signatureItem.PSIsContainer -or $signatureItem.Length -le 0 -or
        $signatureItem.Length -gt 65536 -or
        ($recordItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($signatureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'A production signed-record fixture is unsafe.'
    }
    foreach ($destination in @($RecordDestination, $SignatureDestination)) {
        $item = Get-Item -LiteralPath $destination -Force
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "An installed production signed-record file is unsafe: $destination"
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
            [IO.File]::SetAttributes(
                $destination,
                $item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly))
        }
    }
    [IO.File]::WriteAllBytes(
        $RecordDestination,
        [IO.File]::ReadAllBytes($RecordSource))
    [IO.File]::WriteAllBytes(
        $SignatureDestination,
        [IO.File]::ReadAllBytes($SignatureSource))
    if ((Get-FileHash -LiteralPath $RecordDestination -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $RecordSource -Algorithm SHA256).Hash -or
        (Get-FileHash -LiteralPath $SignatureDestination -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $SignatureSource -Algorithm SHA256).Hash) {
        throw 'The installed production signed-record fixture changed while copying.'
    }
}

function Invoke-RejectedServiceStart(
    [string]$Launcher,
    [string]$Name,
    [string]$ExpectedStage = 'bootstrap'
) {
    $workspace = New-InteractiveTaskWorkspace $Name
    $scriptPath = Join-Path $workspace 'task.ps1'
    $resultPath = Join-Path $workspace 'result.txt'
    $outputPath = Join-Path $workspace 'stdout.txt'
    $scriptText = @"
`$output = @(& '$Launcher' --status 2>&1 | ForEach-Object { `$_.ToString() })
`$code = `$LASTEXITCODE
`$output | Out-File -LiteralPath '$outputPath' -Encoding utf8
[IO.File]::WriteAllText('$resultPath', [string]`$code, [Text.Encoding]::ASCII)
exit `$code
"@
    Write-TaskScript $scriptPath $scriptText
    $exitCode = [int64](Invoke-InteractiveTask $Name $workspace 'Limited')
    $output = Get-Content -LiteralPath (Join-Path $results "$Name.stdout.txt") -Raw
    $stagePattern = [regex]::Escape($ExpectedStage)
    $matches = [regex]::Matches(
        $output,
        "(?m)^OACService connection failed during $stagePattern`: .+\r?$")
    if ($exitCode -ne 3 -or $matches.Count -ne 1 -or
        $output -match '(?m)^OACService status;') {
        throw "$Name did not return the expected service-start rejection."
    }
    return $exitCode
}

function Set-BackendScenario([ValidateSet(0, 1, 2, 3, 4)][int]$Value) {
    $service = Get-Service -Name OACService -ErrorAction Stop
    if ($service.Status -ne 'Stopped') {
        throw 'The backend scenario may only be changed while OACService is stopped.'
    }
    $rootPath = 'HKLM:\SOFTWARE\OAC'
    Set-ItemProperty -LiteralPath $rootPath -Name BackendScenario -Type DWord `
        -Value $Value
    $observed = [int](Get-ItemProperty -LiteralPath $rootPath `
            -Name BackendScenario).BackendScenario
    if ($observed -ne $Value) {
        throw "Could not verify backend scenario $Value."
    }
}

function Invoke-BackendTerminationCase(
    [ValidateSet(1, 2)][int]$Scenario,
    [string]$Name,
    [string]$Launcher,
    [string]$Target,
    [string]$Child
) {
    Set-BackendScenario $Scenario
    $startExit = Invoke-ConsoleCapture `
        "$Name-start" 'sc.exe' @('start', 'OACService')
    if ($startExit -ne 0) {
        throw "Could not start OACService for $Name; exit=$startExit."
    }
    Wait-TestServiceState OACService `
        ([ServiceProcess.ServiceControllerStatus]::Running)
    $launch = Invoke-ProductionLaunch $Launcher $Target "$Name-launch"
    $processes = Wait-LivenessProcesses `
        $Target $Child $launch.TargetProcessId
    Wait-TestServiceState OACService `
        ([ServiceProcess.ServiceControllerStatus]::Stopped)
    Set-BackendScenario 0
    Wait-ProcessesExited `
        @($processes.ParentProcessId, $processes.ChildProcessId) `
        "$Name backend failure"
    Start-Service -Name OACService -ErrorAction Stop
    Wait-TestServiceState OACService `
        ([ServiceProcess.ServiceControllerStatus]::Running)
    $recovered = Invoke-ProductionStatus $Launcher "$Name-recovered"
    return [pscustomobject]@{
        ParentProcessId = $processes.ParentProcessId
        ChildProcessId = $processes.ChildProcessId
        ProcessTreeTerminated = $true
        Recovered = $recovered.BackendLease -eq 1 -and
            $recovered.BackendFlags -eq 3 -and
            $recovered.BackendLeaseSequence -gt 0 -and
            $recovered.BackendError -eq 0
    }
}

function Test-BackendBoundary(
    [string]$Launcher,
    [string]$Target,
    [string]$Child
) {
    Write-RunLog 'Beginning replay, acknowledgement-loss, and lease-loss tests.'
    $replayRejected = $false
    $acknowledgementResult = $null
    $leaseResult = $null
    $testError = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        Stop-Service -Name OACService -Force -ErrorAction Stop
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Stopped)
        $disableRecovery = Invoke-ConsoleCapture `
            'production-backend-recovery-disable' `
            'sc.exe' @('failureflag', 'OACService', '0')
        if ($disableRecovery -ne 0) {
            throw "Could not disable non-crash recovery; exit=$disableRecovery."
        }

        Set-BackendScenario 3
        [void](Invoke-RejectedServiceStart `
            $Launcher 'production-backend-replay' `
            'backend session initialization')
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Stopped)
        $replayRejected = $true
        Set-BackendScenario 0

        $acknowledgementResult = Invoke-BackendTerminationCase `
            1 'production-backend-ack' $Launcher $Target $Child
        Stop-Service -Name OACService -Force -ErrorAction Stop
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Stopped)
        $leaseResult = Invoke-BackendTerminationCase `
            2 'production-backend-lease' $Launcher $Target $Child
    } catch {
        $testError = $_.Exception.Message
    } finally {
        try {
            Stop-Service -Name OACService -Force -ErrorAction SilentlyContinue
            Wait-TestServiceState OACService `
                ([ServiceProcess.ServiceControllerStatus]::Stopped)
        } catch {
            $cleanupErrors.Add("Stop service: $($_.Exception.Message)")
        }
        try {
            Set-BackendScenario 0
        } catch {
            $cleanupErrors.Add("Restore backend scenario: $($_.Exception.Message)")
        }
        try {
            $restoreRecovery = Invoke-ConsoleCapture `
                'production-backend-recovery-restore' `
                'sc.exe' @('failureflag', 'OACService', '1')
            if ($restoreRecovery -ne 0) {
                throw "sc.exe exited with $restoreRecovery"
            }
        } catch {
            $cleanupErrors.Add("Restore service recovery: $($_.Exception.Message)")
        }
        try {
            Start-Service -Name OACService -ErrorAction Stop
            Wait-TestServiceState OACService `
                ([ServiceProcess.ServiceControllerStatus]::Running)
        } catch {
            $cleanupErrors.Add("Restore service: $($_.Exception.Message)")
        }
    }

    $cleanupError = if ($cleanupErrors.Count -eq 0) {
        $null
    } else {
        $cleanupErrors -join '; '
    }
    $passed = $null -eq $testError -and $null -eq $cleanupError -and
        $replayRejected -and $null -ne $acknowledgementResult -and
        $acknowledgementResult.ProcessTreeTerminated -and
        $acknowledgementResult.Recovered -and $null -ne $leaseResult -and
        $leaseResult.ProcessTreeTerminated -and $leaseResult.Recovered
    [ordered]@{
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        replay_rejected = $replayRejected
        acknowledgement_loss_terminated_tree =
            $null -ne $acknowledgementResult -and
            $acknowledgementResult.ProcessTreeTerminated
        acknowledgement_loss_recovered =
            $null -ne $acknowledgementResult -and
            $acknowledgementResult.Recovered
        lease_loss_terminated_tree =
            $null -ne $leaseResult -and $leaseResult.ProcessTreeTerminated
        lease_loss_recovered =
            $null -ne $leaseResult -and $leaseResult.Recovered
        test_error = $testError
        cleanup_error = $cleanupError
        pass = $passed
    } | ConvertTo-Json | Out-File -LiteralPath `
        (Join-Path $results 'backend-boundary-summary.json') -Encoding utf8
    if (-not $passed) {
        throw "Backend boundary failed; test='$testError' cleanup='$cleanupError'."
    }
    Write-RunLog 'Backend replay was rejected; acknowledgement and lease loss each stopped the service and terminated its target job.'
}

function Wait-LivenessProcesses(
    [string]$ParentExecutablePath,
    [string]$ChildExecutablePath,
    [int64]$ExpectedParentProcessId
) {
    if ($ExpectedParentProcessId -le 0) {
        throw 'The liveness parent process ID is invalid.'
    }
    $expectedParentName = [IO.Path]::GetFileName($ParentExecutablePath)
    if ([string]::IsNullOrWhiteSpace($expectedParentName)) {
        throw 'The liveness parent executable name is invalid.'
    }
    $expectedChildPath = [IO.Path]::GetFullPath($ChildExecutablePath)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $parents = @(Get-CimInstance Win32_Process `
                -Filter "ProcessId=$ExpectedParentProcessId")
        if ($parents.Count -gt 1) {
            throw 'The liveness parent process identity is ambiguous.'
        }
        if ($parents.Count -eq 1) {
            # The protected target intentionally denies WMI enough access to
            # read ExecutablePath. Its PID and path are already bound by the
            # launch ticket, so identify the live process by exact image name.
            if ([string]$parents[0].Name -ine $expectedParentName) {
                throw 'The liveness parent has the wrong executable identity.'
            }
            $children = @(Get-CimInstance Win32_Process `
                    -Filter "ParentProcessId=$ExpectedParentProcessId")
            $livenessChildren = @($children | Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -and
                    [IO.Path]::GetFullPath([string]$_.ExecutablePath) -ieq
                        $expectedChildPath
                })
            if ($livenessChildren.Count -gt 1) {
                throw 'The liveness parent created more than one liveness child.'
            }
            if ($livenessChildren.Count -eq 1) {
                $child = $livenessChildren[0]
                $expectedChildCommandLine = '"' +
                    [string]$child.ExecutablePath + '" -t 127.0.0.1'
                if ([int64]$child.ProcessId -le 0 -or
                    [int64]$child.ProcessId -eq $ExpectedParentProcessId -or
                    [string]$child.CommandLine -ine $expectedChildCommandLine) {
                    throw 'The liveness child has the wrong process identity or role.'
                }
                return [pscustomobject]@{
                    ParentProcessId = $ExpectedParentProcessId
                    ChildProcessId = [int64]$child.ProcessId
                }
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'The liveness parent did not expose exactly one verified child process.'
}

function Wait-ProcessesExited([int64[]]$ProcessIds, [string]$Context) {
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $active = @($ProcessIds | Where-Object {
                $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue)
            })
        if ($active.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "$Context left liveness processes running: $($active -join ', ')"
}

function Wait-ServiceRestart([int64]$PreviousProcessId) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $services = @(Get-CimInstance Win32_Service -Filter "Name='OACService'")
        if ($services.Count -eq 1 -and $services[0].State -ceq 'Running' -and
            [int64]$services[0].ProcessId -gt 0 -and
            [int64]$services[0].ProcessId -ne $PreviousProcessId) {
            return [int64]$services[0].ProcessId
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'OACService did not complete its bounded recovery restart.'
}

function Test-CurrentDeviceOpenDenied([string]$Name) {
    $probe = @'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class OacSystemDeviceProbe
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr templateFile);

    public static SafeFileHandle Open()
    {
        return CreateFileW(@"\\.\OAC", 0xC0000000, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
    }
}
"@

    $handle = [OacSystemDeviceProbe]::Open()
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $opened = -not $handle.IsInvalid
    $handle.Dispose()
    $exitCode = 0
    if ($opened) {
        $exitCode = 41
    } elseif ($errorCode -ne 5) {
        $exitCode = 42
    }
    [Console]::Out.WriteLine("win32_error=$errorCode pass=$($exitCode -eq 0)")
    exit $exitCode
'@
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($probe))
    $powershell = Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\PowerShell.exe'
    return Invoke-NativeCapture $Name $powershell @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) `
        ([TimeSpan]::FromSeconds(30))
}

function Test-ProductionBoundary {
    Write-RunLog 'Beginning bounded production service, launch, and liveness tests.'
    $installDirectory = Join-Path $env:ProgramFiles 'OAC-Test'
    $launcher = Join-Path $installDirectory 'OAC-Launcher.exe'
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
        throw "Installed launcher is missing: $launcher"
    }

    $launcherExits = [Collections.Generic.List[int64]]::new()
    $launchExits = [Collections.Generic.List[int64]]::new()
    $lossSequences = [Collections.Generic.List[int64]]::new()
    $lossReasons = [Collections.Generic.List[int64]]::new()
    $probeExits = [ordered]@{
        localsystem = [int64]-1
        limited = [int64]-1
        administrator = [int64]-1
    }
    $crashParentProcessId = [int64]0
    $crashChildProcessId = [int64]0
    $gracefulParentProcessId = [int64]0
    $gracefulChildProcessId = [int64]0
    $crashProcessesTerminated = $false
    $gracefulProcessesTerminated = $false
    $serviceCrashRestarted = $false
    $scanWorkerResponsive = $false
    $scanThreadResumePass = $false
    $scanStatus = $null
    $launchBindingConfirmed = $false
    $launchJobAssigned = $false
    $launchThreadResumed = $false
    $gracefulLaunchBindingConfirmed = $false
    $gracefulLaunchJobAssigned = $false
    $gracefulLaunchThreadResumed = $false
    $modifiedManifestRejected = $false
    $wrongBuildManifestRejected = $false
    $expiredManifestRejected = $false
    $rollbackManifestRejected = $false
    $wrongSignaturePolicyRejected = $false
    $wrongScopePolicyRejected = $false
    $expiredPolicyRejected = $false
    $rollbackPolicyRejected = $false
    $authorizedRollbackPolicyAccepted = $false
    $emergencyPolicyRejected = $false
    $backendBoundaryPassed = $false
    $testError = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    $livenessSource = $launcher
    $livenessTarget = Join-Path $installDirectory 'OAC-Liveness-Target.exe'
    $manifestDestination = "$livenessTarget.oac-manifest"
    $signatureDestination = "$manifestDestination.p7s"
    $validManifestSource =
        Join-Path $root 'package\OAC-Liveness-Target.exe.oac-manifest'
    $validSignatureSource = "$validManifestSource.p7s"
    $policyDestination = Join-Path $installDirectory 'OAC.policy'
    $policySignatureDestination = "$policyDestination.p7s"
    $validPolicySource = Join-Path $root 'package\OAC.policy'
    $validPolicySignatureSource = "$validPolicySource.p7s"
    $modifiedManifestSource = Join-Path $root 'OAC-Game-Manifest-Modified.bin'
    $livenessChild = Join-Path $env:SystemRoot 'System32\PING.EXE'
    $livenessAliasCreated = $false
    try {
        Stop-TestService 'production-service-pre-stop' 'OACService'
        Stop-TestService 'production-driver-pre-stop' 'OAC'
        Set-DriverLabMode 0
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Stopped)

        if ($null -ne (Get-Item -LiteralPath $livenessTarget -Force `
                    -ErrorAction SilentlyContinue)) {
            throw "The liveness test alias already exists: $livenessTarget"
        }
        Copy-Item -LiteralPath $livenessSource -Destination $livenessTarget
        $livenessAliasCreated = $true
        if ((Get-FileHash -LiteralPath $livenessSource -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $livenessTarget -Algorithm SHA256).Hash) {
            throw 'The liveness target alias does not match the installed launcher.'
        }
        if (-not (Test-Path -LiteralPath $livenessChild -PathType Leaf)) {
            throw "The liveness child executable is missing: $livenessChild"
        }

        $initialStatus = Invoke-ProductionStatus $launcher 'production-launcher-1'
        $launcherExits.Add($initialStatus.ExitCode)
        $lossSequences.Add($initialStatus.LossSequence)
        $lossReasons.Add($initialStatus.LossReason)
        if ($initialStatus.LossSequence -ne 0 -or $initialStatus.LossReason -ne 0) {
            throw 'The fresh production driver lifetime reported prior session loss.'
        }
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Running)
        Invoke-ConsoleCapture 'production-launcher-started-service' `
            'sc.exe' @('query', 'OACService') | Out-Null

        $probeExits.localsystem = Test-CurrentDeviceOpenDenied `
            'production-direct-open-localsystem'

        foreach ($probe in @(
            @('limited', 'Limited'),
            @('administrator', 'Highest'))) {
            $identity = [string]$probe[0]
            $runLevel = [string]$probe[1]
            $probeName = "production-direct-open-$identity"
            $probeWorkspace = New-InteractiveTaskWorkspace $probeName
            $probeScriptPath = Join-Path $probeWorkspace 'task.ps1'
            $probeResultPath = Join-Path $probeWorkspace 'result.txt'
            $probeOutputPath = Join-Path $probeWorkspace 'stdout.txt'
            $probeScript = @'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class OacDeviceProbe
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr templateFile);

    public static SafeFileHandle Open()
    {
        return CreateFileW(@"\\.\OAC", 0xC0000000, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
    }
}
"@

$handle = [OacDeviceProbe]::Open()
$errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
$code = 0
if (-not $handle.IsInvalid) {
    $handle.Dispose()
    $code = 41
} elseif ($errorCode -ne 5) {
    $code = 42
}
"win32_error=$errorCode pass=$($code -eq 0)" |
    Out-File -LiteralPath '__OUTPUT__' -Encoding utf8
[IO.File]::WriteAllText('__RESULT__', [string]$code, [Text.Encoding]::ASCII)
exit $code
'@
            $probeScript = $probeScript.Replace('__OUTPUT__', $probeOutputPath)
            $probeScript = $probeScript.Replace('__RESULT__', $probeResultPath)
            Write-TaskScript $probeScriptPath $probeScript
            $probeExits[$identity] = Invoke-InteractiveTask `
                $probeName $probeWorkspace $runLevel
            Wait-TestServiceState OACService `
                ([ServiceProcess.ServiceControllerStatus]::Running)
        }

        $modifiedBytes = [IO.File]::ReadAllBytes($validManifestSource)
        if ($modifiedBytes.Length -ne 960 -or
            (Test-Path -LiteralPath $modifiedManifestSource)) {
            throw 'The modified-manifest fixture cannot be created safely.'
        }
        $modifiedBytes[24] = $modifiedBytes[24] -bxor 1
        [IO.File]::WriteAllBytes($modifiedManifestSource, $modifiedBytes)
        Set-ProductionSignedRecordFiles `
            $modifiedManifestSource $validSignatureSource `
            $manifestDestination $signatureDestination 960
        [void](Invoke-RejectedLaunchAuthorization `
            $launcher $livenessTarget 'production-manifest-modified' `
            'game manifest signature is invalid')
        $modifiedManifestRejected = $true

        $wrongBuildSource = Join-Path $root 'OAC-Game-Manifest-Wrong-Build.bin'
        Set-ProductionSignedRecordFiles `
            $wrongBuildSource "$wrongBuildSource.p7s" `
            $manifestDestination $signatureDestination 960
        [void](Invoke-RejectedLaunchAuthorization `
            $launcher $livenessTarget 'production-manifest-wrong-build' `
            'executable identity does not match the game manifest')
        $wrongBuildManifestRejected = $true

        $expiredSource = Join-Path $root 'OAC-Game-Manifest-Expired.bin'
        Set-ProductionSignedRecordFiles `
            $expiredSource "$expiredSource.p7s" `
            $manifestDestination $signatureDestination 960
        [void](Invoke-RejectedLaunchAuthorization `
            $launcher $livenessTarget 'production-manifest-expired' `
            'game manifest is outside its validity period')
        $expiredManifestRejected = $true

        Set-ProductionSignedRecordFiles `
            $validManifestSource $validSignatureSource `
            $manifestDestination $signatureDestination 960

        $crashLaunch = Invoke-ProductionLaunch `
            $launcher $livenessTarget 'production-launch'
        $launchExits.Add($crashLaunch.ExitCode)
        $crashProcesses = Wait-LivenessProcesses `
            $livenessTarget $livenessChild $crashLaunch.TargetProcessId
        $crashParentProcessId = $crashProcesses.ParentProcessId
        $crashChildProcessId = $crashProcesses.ChildProcessId
        $launchBindingConfirmed = $true
        $launchJobAssigned = $true
        $launchThreadResumed = $true

        Start-Sleep -Seconds 2
        $scanStatus = Invoke-ProductionStatus $launcher 'production-launcher-scan'
        $launcherExits.Add($scanStatus.ExitCode)
        if ($scanStatus.ServiceProcessId -ne $initialStatus.ServiceProcessId -or
            $scanStatus.LossSequence -ne 0 -or $scanStatus.LossReason -ne 0 -or
            $scanStatus.ScanState -notin @(1, 2) -or
            $scanStatus.ScanQueued -lt 2 -or $scanStatus.ScanCompleted -lt 1 -or
            $scanStatus.ScanCompleted -gt $scanStatus.ScanQueued -or
            $scanStatus.ScanCancelled -ne 0 -or $scanStatus.ScanFailed -ne 0 -or
            $scanStatus.ScanSweeps -lt 1 -or $scanStatus.ScanRegions -lt 1 -or
            $scanStatus.ScanThreads -lt 1 -or
            $scanStatus.HealthIterations -lt 1 -or
            $scanStatus.HealthMaximumMicroseconds -gt $workerLatencyLimitMicroseconds -or
            # Cooperative scan work uses a 20 ms deadline. Wall time also includes
            # scheduler delay and bounded native calls on the two-processor test VM.
            $scanStatus.ScanMaximumMicroseconds -gt $workerLatencyLimitMicroseconds -or
            $scanStatus.SuspensionMaximumMicroseconds -le 0 -or
            $scanStatus.SuspensionMaximumMicroseconds -gt $threadSuspensionLimitMicroseconds) {
            throw 'The bounded scan worker did not meet its health, coverage, or suspension budget.'
        }
        $scanWorkerResponsive = $true
        $scanThreadResumePass = $true

        $runningServices = @(Get-CimInstance Win32_Service -Filter "Name='OACService'")
        if ($runningServices.Count -ne 1 -or
            $runningServices[0].State -cne 'Running' -or
            [int64]$runningServices[0].ProcessId -ne
                $initialStatus.ServiceProcessId) {
            throw 'OACService process identity changed before the crash test.'
        }
        $crashExit = Invoke-ConsoleCapture 'production-service-crash' `
            'taskkill.exe' @('/PID', [string]$initialStatus.ServiceProcessId, '/F') `
            ([TimeSpan]::FromSeconds(20))
        if ($crashExit -ne 0) {
            throw "Could not terminate OACService for the crash test; exit=$crashExit."
        }
        Wait-ProcessesExited `
            @($crashParentProcessId, $crashChildProcessId) `
            'OACService crash'
        $crashProcessesTerminated = $true
        $restartedServiceProcessId = Wait-ServiceRestart `
            $initialStatus.ServiceProcessId
        $serviceCrashRestarted = $true

        $recoveredStatus = Invoke-ProductionStatus $launcher 'production-launcher-2'
        $launcherExits.Add($recoveredStatus.ExitCode)
        $lossSequences.Add($recoveredStatus.LossSequence)
        $lossReasons.Add($recoveredStatus.LossReason)
        if ($recoveredStatus.ServiceProcessId -ne $restartedServiceProcessId -or
            $recoveredStatus.LossSequence -ne 1 -or
            $recoveredStatus.LossReason -notin @(2, 3)) {
            throw 'The recovered service did not report exactly one prior session loss.'
        }

        $rollbackSource = Join-Path $root 'OAC-Game-Manifest-Rollback.bin'
        Set-ProductionSignedRecordFiles `
            $rollbackSource "$rollbackSource.p7s" `
            $manifestDestination $signatureDestination 960
        [void](Invoke-RejectedLaunchAuthorization `
            $launcher $livenessTarget 'production-manifest-rollback' `
            'game manifest was superseded or changed without a new sequence')
        $rollbackManifestRejected = $true
        Set-ProductionSignedRecordFiles `
            $validManifestSource $validSignatureSource `
            $manifestDestination $signatureDestination 960

        $gracefulLaunch = Invoke-ProductionLaunch `
            $launcher $livenessTarget 'production-launch-graceful'
        $launchExits.Add($gracefulLaunch.ExitCode)
        $gracefulProcesses = Wait-LivenessProcesses `
            $livenessTarget $livenessChild $gracefulLaunch.TargetProcessId
        $gracefulParentProcessId = $gracefulProcesses.ParentProcessId
        $gracefulChildProcessId = $gracefulProcesses.ChildProcessId
        $gracefulLaunchBindingConfirmed = $true
        $gracefulLaunchJobAssigned = $true
        $gracefulLaunchThreadResumed = $true

        $gracefulStopExit = Invoke-ConsoleCapture `
            'production-service-graceful-stop' 'sc.exe' @('stop', 'OACService')
        if ($gracefulStopExit -ne 0) {
            throw "Could not stop OACService gracefully; exit=$gracefulStopExit."
        }
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Stopped)
        Wait-ProcessesExited `
            @($gracefulParentProcessId, $gracefulChildProcessId) `
            'OACService graceful stop'
        $gracefulProcessesTerminated = $true

        $postStopStartExit = Invoke-ConsoleCapture `
            'production-service-post-stop-start' 'sc.exe' @('start', 'OACService')
        if ($postStopStartExit -ne 0) {
            throw "Could not restart OACService after its graceful stop; exit=$postStopStartExit."
        }
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Running)
        $postStopStatus = Invoke-ProductionStatus $launcher 'production-launcher-3'
        $launcherExits.Add($postStopStatus.ExitCode)
        $lossSequences.Add($postStopStatus.LossSequence)
        $lossReasons.Add($postStopStatus.LossReason)
        if ($postStopStatus.LossSequence -ne 2 -or
            $postStopStatus.LossReason -ne 1) {
            throw 'The graceful stop did not publish one explicit session revocation.'
        }

        Test-BackendBoundary $launcher $livenessTarget $livenessChild
        $backendBoundaryPassed = $true

        Stop-Service -Name OACService -Force -ErrorAction Stop
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Stopped)

        $wrongSignaturePolicySource =
            Join-Path $root 'OAC-Policy-Wrong-Signature.bin'
        Set-ProductionSignedRecordFiles `
            $wrongSignaturePolicySource "$wrongSignaturePolicySource.p7s" `
            $policyDestination $policySignatureDestination 2480
        [void](Invoke-RejectedServiceStart `
            $launcher 'production-policy-wrong-signature')
        $wrongSignaturePolicyRejected = $true

        $expiredPolicySource = Join-Path $root 'OAC-Policy-Expired.bin'
        Set-ProductionSignedRecordFiles `
            $expiredPolicySource "$expiredPolicySource.p7s" `
            $policyDestination $policySignatureDestination 2480
        [void](Invoke-RejectedServiceStart `
            $launcher 'production-policy-expired')
        $expiredPolicyRejected = $true

        $wrongScopePolicySource = Join-Path $root 'OAC-Policy-Wrong-Scope.bin'
        Set-ProductionSignedRecordFiles `
            $wrongScopePolicySource "$wrongScopePolicySource.p7s" `
            $policyDestination $policySignatureDestination 2480
        Start-Service -Name OACService -ErrorAction Stop
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Running)
        [void](Invoke-RejectedLaunchAuthorization `
            $launcher $livenessTarget 'production-policy-wrong-scope' `
            'signed policy denied the launch')
        $wrongScopePolicyRejected = $true
        Stop-Service -Name OACService -Force -ErrorAction Stop
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Stopped)

        $rollbackPolicySource = Join-Path $root 'OAC-Policy-Rollback.bin'
        Set-ProductionSignedRecordFiles `
            $rollbackPolicySource "$rollbackPolicySource.p7s" `
            $policyDestination $policySignatureDestination 2480
        [void](Invoke-RejectedServiceStart `
            $launcher 'production-policy-rollback')
        $rollbackPolicyRejected = $true

        $authorizedRollbackPolicySource =
            Join-Path $root 'OAC-Policy-Authorized-Rollback.bin'
        Set-ProductionSignedRecordFiles `
            $authorizedRollbackPolicySource `
            "$authorizedRollbackPolicySource.p7s" `
            $policyDestination $policySignatureDestination 2480
        $authorizedRollbackStatus = Invoke-ProductionStatus `
            $launcher 'production-policy-authorized-rollback'
        $authorizedRollbackPolicyAccepted =
            $authorizedRollbackStatus.ExitCode -eq 0
        Stop-Service -Name OACService -Force -ErrorAction Stop
        Wait-TestServiceState OACService `
            ([ServiceProcess.ServiceControllerStatus]::Stopped)

        $emergencyPolicySource =
            Join-Path $root 'OAC-Policy-Emergency-Revoke.bin'
        Set-ProductionSignedRecordFiles `
            $emergencyPolicySource "$emergencyPolicySource.p7s" `
            $policyDestination $policySignatureDestination 2480
        [void](Invoke-RejectedServiceStart `
            $launcher 'production-policy-emergency-revoke')
        $emergencyPolicyRejected = $true

        if (@($launcherExits | Where-Object { $_ -ne 0 }).Count -ne 0 -or
            @($launchExits | Where-Object { $_ -ne 0 }).Count -ne 0 -or
            @($probeExits.Values | Where-Object { $_ -ne 0 }).Count -ne 0 -or
            -not $crashProcessesTerminated -or
            -not $gracefulProcessesTerminated -or
            -not $serviceCrashRestarted -or
            -not $modifiedManifestRejected -or
            -not $wrongBuildManifestRejected -or
            -not $expiredManifestRejected -or
            -not $rollbackManifestRejected -or
            -not $wrongSignaturePolicyRejected -or
            -not $wrongScopePolicyRejected -or
            -not $expiredPolicyRejected -or
            -not $rollbackPolicyRejected -or
            -not $authorizedRollbackPolicyAccepted -or
            -not $emergencyPolicyRejected -or
            -not $backendBoundaryPassed) {
            throw 'The production service, launch, and liveness boundary did not pass.'
        }
    } catch {
        $testError = $_.Exception.Message
    } finally {
        try {
            Set-ProductionSignedRecordFiles `
                $validManifestSource $validSignatureSource `
                $manifestDestination $signatureDestination 960
        } catch {
            $cleanupErrors.Add("Restore production manifest: $($_.Exception.Message)")
        }
        try {
            Set-ProductionSignedRecordFiles `
                $validPolicySource $validPolicySignatureSource `
                $policyDestination $policySignatureDestination 2480
        } catch {
            $cleanupErrors.Add("Restore signed policy: $($_.Exception.Message)")
        }
        try {
            if (Test-Path -LiteralPath $modifiedManifestSource) {
                Remove-RegularTestFile $modifiedManifestSource
            }
        } catch {
            $cleanupErrors.Add("Remove modified manifest fixture: $($_.Exception.Message)")
        }
        try {
            Stop-TestService 'production-service-stop' 'OACService'
        } catch {
            $cleanupErrors.Add("Stop OACService: $($_.Exception.Message)")
        }
        try {
            Stop-TestService 'production-driver-stop' 'OAC'
        } catch {
            $cleanupErrors.Add("Stop OAC: $($_.Exception.Message)")
        }
        try {
            Set-DriverLabMode 1
        } catch {
            $cleanupErrors.Add("Restore LabMode: $($_.Exception.Message)")
        }
        try {
            Start-TestService 'production-legacy-driver-start' 'OAC'
        } catch {
            $cleanupErrors.Add("Start OAC: $($_.Exception.Message)")
        }
        if ($livenessAliasCreated) {
            try {
                Remove-RegularTestFile $livenessTarget
            } catch {
                $cleanupErrors.Add("Remove liveness target alias: $($_.Exception.Message)")
            }
        }
    }

    $cleanupError = if ($cleanupErrors.Count -eq 0) {
        $null
    } else {
        $cleanupErrors -join '; '
    }
    $passed = $null -eq $testError -and $null -eq $cleanupError -and
        $launcherExits.Count -eq 4 -and $launchExits.Count -eq 2 -and
        @($launcherExits | Where-Object { $_ -ne 0 }).Count -eq 0 -and
        @($launchExits | Where-Object { $_ -ne 0 }).Count -eq 0 -and
        @($probeExits.Values | Where-Object { $_ -ne 0 }).Count -eq 0 -and
        $crashParentProcessId -gt 0 -and $crashChildProcessId -gt 0 -and
        $gracefulParentProcessId -gt 0 -and $gracefulChildProcessId -gt 0 -and
        $launchBindingConfirmed -and $launchJobAssigned -and
        $launchThreadResumed -and $gracefulLaunchBindingConfirmed -and
        $gracefulLaunchJobAssigned -and $gracefulLaunchThreadResumed -and
        $crashProcessesTerminated -and $gracefulProcessesTerminated -and
        $serviceCrashRestarted -and
        $modifiedManifestRejected -and $wrongBuildManifestRejected -and
        $expiredManifestRejected -and $rollbackManifestRejected -and
        $wrongSignaturePolicyRejected -and $wrongScopePolicyRejected -and
        $expiredPolicyRejected -and $rollbackPolicyRejected -and
        $authorizedRollbackPolicyAccepted -and
        $emergencyPolicyRejected -and
        $backendBoundaryPassed -and
        $scanWorkerResponsive -and $scanThreadResumePass -and
        $lossSequences.Count -eq 3 -and $lossSequences[0] -eq 0 -and
        $lossSequences[1] -eq 1 -and $lossSequences[2] -eq 2 -and
        $lossReasons.Count -eq 3 -and $lossReasons[0] -eq 0 -and
        $lossReasons[1] -in @(2, 3) -and $lossReasons[2] -eq 1
    [ordered]@{
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        launcher_exits = @($launcherExits)
        launch_exits = @($launchExits)
        direct_open_localsystem_exit = $probeExits.localsystem
        direct_open_limited_exit = $probeExits.limited
        direct_open_administrator_exit = $probeExits.administrator
        launch_exit = if ($launchExits.Count -gt 0) { $launchExits[0] } else { -1 }
        launch_target_process_id = $crashParentProcessId
        launch_binding_confirmed = $launchBindingConfirmed
        launch_job_assigned = $launchJobAssigned
        launch_thread_resumed = $launchThreadResumed
        graceful_launch_exit = if ($launchExits.Count -gt 1) { $launchExits[1] } else { -1 }
        graceful_launch_target_process_id = $gracefulParentProcessId
        graceful_launch_binding_confirmed = $gracefulLaunchBindingConfirmed
        graceful_launch_job_assigned = $gracefulLaunchJobAssigned
        graceful_launch_thread_resumed = $gracefulLaunchThreadResumed
        crash_child_process_id = $crashChildProcessId
        graceful_child_process_id = $gracefulChildProcessId
        crash_processes_terminated = $crashProcessesTerminated
        graceful_processes_terminated = $gracefulProcessesTerminated
        service_crash_restarted = $serviceCrashRestarted
        modified_manifest_rejected = $modifiedManifestRejected
        wrong_build_manifest_rejected = $wrongBuildManifestRejected
        expired_manifest_rejected = $expiredManifestRejected
        rollback_manifest_rejected = $rollbackManifestRejected
        wrong_signature_policy_rejected = $wrongSignaturePolicyRejected
        wrong_scope_policy_rejected = $wrongScopePolicyRejected
        expired_policy_rejected = $expiredPolicyRejected
        rollback_policy_rejected = $rollbackPolicyRejected
        authorized_rollback_policy_accepted = $authorizedRollbackPolicyAccepted
        emergency_policy_rejected = $emergencyPolicyRejected
        backend_boundary_passed = $backendBoundaryPassed
        session_loss_sequences = @($lossSequences)
        session_loss_reasons = @($lossReasons)
        scan_state = if ($null -ne $scanStatus) { $scanStatus.ScanState } else { -1 }
        scan_slices_queued = if ($null -ne $scanStatus) { $scanStatus.ScanQueued } else { -1 }
        scan_slices_completed = if ($null -ne $scanStatus) { $scanStatus.ScanCompleted } else { -1 }
        scan_slices_coalesced = if ($null -ne $scanStatus) { $scanStatus.ScanCoalesced } else { -1 }
        scan_slices_cancelled = if ($null -ne $scanStatus) { $scanStatus.ScanCancelled } else { -1 }
        scan_slices_failed = if ($null -ne $scanStatus) { $scanStatus.ScanFailed } else { -1 }
        scan_sweeps_completed = if ($null -ne $scanStatus) { $scanStatus.ScanSweeps } else { -1 }
        scan_memory_regions = if ($null -ne $scanStatus) { $scanStatus.ScanRegions } else { -1 }
        scan_memory_bytes = if ($null -ne $scanStatus) { $scanStatus.ScanBytes } else { -1 }
        scan_threads = if ($null -ne $scanStatus) { $scanStatus.ScanThreads } else { -1 }
        scan_threads_skipped = if ($null -ne $scanStatus) { $scanStatus.ScanSkipped } else { -1 }
        health_iterations = if ($null -ne $scanStatus) { $scanStatus.HealthIterations } else { -1 }
        maximum_health_delay_us = if ($null -ne $scanStatus) { $scanStatus.HealthMaximumMicroseconds } else { -1 }
        maximum_scan_slice_us = if ($null -ne $scanStatus) { $scanStatus.ScanMaximumMicroseconds } else { -1 }
        maximum_thread_suspension_us = if ($null -ne $scanStatus) { $scanStatus.SuspensionMaximumMicroseconds } else { -1 }
        scan_worker_responsive = $scanWorkerResponsive
        scan_thread_resume_pass = $scanThreadResumePass
        test_error = $testError
        cleanup_error = $cleanupError
        lab_mode_restored = $null -eq $cleanupError
        pass = $passed
    } | ConvertTo-Json | Out-File -LiteralPath `
        (Join-Path $results 'production-boundary-summary.json') -Encoding utf8
    if (-not $passed) {
        throw "Production boundary failed; test='$testError' cleanup='$cleanupError'."
    }
    Write-RunLog 'Production boundary passed: the bounded scan worker preserved health latency and resumed sampled threads; direct opens were denied; both launches were job-owned; crash and graceful stop terminated each process tree; and session loss was reported exactly once per service lifetime.'
}

function Assert-KernelFindingProvenance([string]$ReportPath) {
    $found = $false
    if (Test-Path -LiteralPath $ReportPath -PathType Leaf) {
        $report = Get-Content -LiteralPath $ReportPath -Raw
        $found = $report -match `
            '(?im)^.*\[[^]\r\n]+\]\[kernel/[^]\r\n]+\].*\borigin_seq=[1-9][0-9]*\b.*\borigin_timestamp_100ns=[1-9][0-9]*\b'
    }
    [ordered]@{
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        report = $ReportPath
        nonzero_kernel_provenance = $found
        pass = $found
    } | ConvertTo-Json | Out-File -LiteralPath `
        (Join-Path $results 'baseline-provenance-summary.json') -Encoding utf8
    if (-not $found) {
        throw 'No drained kernel finding carried nonzero origin sequence and timestamp provenance.'
    }
    Write-RunLog 'Verified nonzero sequence and timestamp provenance on a drained kernel finding.'
}

function Test-RemovalBoundary {
    Write-RunLog 'Beginning exact OAC test-stack removal and refusal tests.'
    $installer = Join-Path $root 'Install-OACTestDriver.ps1'
    $manifest = Get-Content -LiteralPath `
        (Join-Path $root 'package-manifest.json') -Raw | ConvertFrom-Json
    $certificateThumbprint = [string]$manifest.certificate_thumbprint
    if ([string]::IsNullOrWhiteSpace($certificateThumbprint)) {
        throw 'The package manifest has no test certificate thumbprint.'
    }
    $sentinel = Join-Path $results 'removal-unrelated-sentinel.txt'
    Write-DurableAsciiFile $sentinel 'OAC removal must not touch this file.'
    $sentinelHash = (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash
    $removeExit = [int]-1
    $repeatExit = [int]-1
    $reinstallExit = [int]-1
    $testError = $null
    $recoveryError = $null
    try {
        $removeExit = Invoke-NativeCapture 'baseline-remove' 'PowerShell.exe' @(
            '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installer,
            '-PackageDirectory', (Join-Path $root 'package'),
            '-ConfirmDisposableVm', '-Remove')
        if ($removeExit -ne 0) {
            throw "Exact OAC stack removal failed with exit code $removeExit."
        }
        if ((Get-Service -Name OACService -ErrorAction SilentlyContinue) -or
            (Get-Service -Name OAC -ErrorAction SilentlyContinue) -or
            (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'OAC-Test')) -or
            (Test-Path -LiteralPath 'HKLM:\SOFTWARE\OAC')) {
            throw 'OAC services, application files, or manifest state remained after removal.'
        }
        foreach ($storeName in @('Root', 'TrustedPublisher')) {
            if (@(Get-ChildItem -LiteralPath "Cert:\LocalMachine\$storeName" |
                    Where-Object Thumbprint -EQ $certificateThumbprint).Count -ne 0) {
                throw "The OAC test certificate remained in LocalMachine\$storeName."
            }
        }

        $repeatExit = Invoke-NativeCapture `
            'baseline-remove-repeat-expected-refusal' 'PowerShell.exe' @(
                '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', $installer,
                '-PackageDirectory', (Join-Path $root 'package'),
                '-ConfirmDisposableVm', '-Remove')
        if ($repeatExit -eq 0) {
            throw 'A second removal unexpectedly accepted an absent installation.'
        }
        if ((Get-Service -Name OACService -ErrorAction SilentlyContinue) -or
            (Get-Service -Name OAC -ErrorAction SilentlyContinue) -or
            (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'OAC-Test')) -or
            (Test-Path -LiteralPath 'HKLM:\SOFTWARE\OAC')) {
            throw 'The refused removal recreated or changed the absent OAC stack.'
        }
        if (-not (Test-Path -LiteralPath $sentinel -PathType Leaf) -or
            (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash -ne
                $sentinelHash) {
            throw 'The refused removal changed an unrelated sentinel.'
        }
    } catch {
        $testError = $_.Exception.Message
    } finally {
        try {
            $reinstallExit = Invoke-NativeCapture `
                'baseline-reinstall' 'PowerShell.exe' @(
                    '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                    '-File', $installer,
                    '-PackageDirectory', (Join-Path $root 'package'),
                    '-ConfirmDisposableVm', '-LegacyV4LabMode')
            if ($reinstallExit -ne 0) {
                throw "OAC stack recovery failed with exit code $reinstallExit."
            }
            $labMode = [int](Get-ItemProperty -LiteralPath `
                'HKLM:\SYSTEM\CurrentControlSet\Services\OAC\Parameters' `
                -Name LabMode).LabMode
            if ((Get-Service -Name OAC).Status -ne 'Running' -or
                (Get-Service -Name OACService).Status -ne 'Stopped' -or
                $labMode -ne 1) {
                throw 'The reinstalled legacy test stack is not in its expected state.'
            }
        } catch {
            $recoveryError = $_.Exception.Message
        }
    }

    $sentinelUnchanged =
        (Test-Path -LiteralPath $sentinel -PathType Leaf) -and
        (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash -eq
            $sentinelHash
    $passed = $null -eq $testError -and $null -eq $recoveryError -and
        $removeExit -eq 0 -and $repeatExit -ne 0 -and $reinstallExit -eq 0 -and
        $sentinelUnchanged
    [ordered]@{
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        remove_exit = $removeExit
        repeat_remove_exit = $repeatExit
        repeat_refused = $repeatExit -ne 0
        unrelated_sentinel_unchanged = $sentinelUnchanged
        reinstall_exit = $reinstallExit
        test_error = $testError
        recovery_error = $recoveryError
        pass = $passed
    } | ConvertTo-Json | Out-File -LiteralPath `
        (Join-Path $results 'removal-boundary-summary.json') -Encoding utf8
    if (-not $passed) {
        throw "Removal boundary failed; test='$testError' recovery='$recoveryError'."
    }
    Write-RunLog 'Exact removal, absent-stack refusal, and legacy reinstall passed.'
}

function Test-DriverGate {
    $serviceName = 'OACGateProbe'
    $probePath = Join-Path $root 'OAC-Gate-Probe.sys'
    $reportDirectory = Join-Path $results 'baseline-driver-gate-report'
    $reportPath = Join-Path $reportDirectory 'oac-report.txt'
    $summaryPath = Join-Path $results 'baseline-driver-gate-summary.json'
    $startExit = -1
    $detectionExit = -1
    $gateFinding = $false
    $callbackFinding = $false
    $preSessionFinding = $false
    $summary = $null
    $primaryError = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        Copy-Item -LiteralPath (Join-Path $root 'package\OAC.sys') `
            -Destination $probePath -Force
        $createExit = Invoke-ConsoleCapture `
            'baseline-driver-gate-create' 'sc.exe' @(
                'create', $serviceName, 'type=', 'kernel', 'start=', 'demand',
                'binPath=', $probePath)
        if ($createExit -ne 0) {
            throw "Could not create the transient gate probe; exit code $createExit."
        }

        # Reset OAC immediately before the controlled load. Any intervening
        # kernel image makes the helper's exact 0/0 precondition fail closed.
        $boundaryStop = Invoke-ConsoleCapture `
            'baseline-driver-gate-oac-stop' 'sc.exe' @('stop', 'OAC')
        if ($boundaryStop -ne 0) {
            throw "Could not establish the gate lifetime boundary; stop exit=$boundaryStop."
        }
        Wait-TestServiceState OAC `
            ([ServiceProcess.ServiceControllerStatus]::Stopped)
        $boundaryStart = Invoke-ConsoleCapture `
            'baseline-driver-gate-oac-start' 'sc.exe' @('start', 'OAC')
        if ($boundaryStart -ne 0) {
            throw "Could not establish the gate lifetime boundary; start exit=$boundaryStart."
        }
        Wait-TestServiceState OAC `
            ([ServiceProcess.ServiceControllerStatus]::Running)

        # A purpose-built targetless protocol holder configures the gate, keeps
        # that exact file session alive across the SCM start, and verifies the
        # immutable 0/0 to 1/1 counter transition before closing it. With no
        # target binding, cleanup retires the session without a tombstone.
        $startExit = Invoke-ConsoleCapture 'baseline-driver-gate-trigger' `
            (Join-Path $root 'OAC-Protocol-Test.exe') @('--driver-gate-probe')
        $triggerPath = Join-Path $results 'baseline-driver-gate-trigger.txt'
        $triggerLines = @(
            if (Test-Path -LiteralPath $triggerPath -PathType Leaf) {
                Get-Content -LiteralPath $triggerPath | Where-Object {
                    $_ -clike 'DRIVER_GATE_PROBE *'
                }
            }
        )
        $triggerValidated = $startExit -eq 0 -and
            $triggerLines.Count -eq 1 -and
            $triggerLines[0] -ceq (
                'DRIVER_GATE_PROBE validated=1 start_error=183 ' +
                'before_post_start=0 before_gate_trips=0 ' +
                'after_post_start=1 after_gate_trips=1')
        $startError = if ($triggerValidated) { 183 } else { -1 }

        $detectionExit = Invoke-NativeCapture 'baseline-driver-gate-detection' `
            (Join-Path $root 'package\OAC-Client.exe') @(
                '--preflight', '--mode', 'test', '--fail-on', 'medium',
                '--output', $reportDirectory)
        if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
            $report = Get-Content -LiteralPath $reportPath -Raw
            $gateMatches = [regex]::Matches(
                $report,
                '(?im)^.*Fail-closed post-start driver-load latch is set:.*$')
            $gateFinding = $gateMatches.Count -eq 1 -and
                $gateMatches[0].Value -match (
                    '(?i)\[critical\]\[driver/load-gate\].*' +
                    'observed=1, gate-trips=1')
            $callbackMatches = [regex]::Matches(
                $report,
                '(?im)^.*Driver-load gate tripped.*$')
            $callbackFinding = $callbackMatches.Count -eq 1 -and
                $callbackMatches[0].Value -match (
                    '(?i)\[critical\]\[kernel/driver\].*' +
                    'OAC-Gate-Probe\.sys')
            $preSessionFinding = [regex]::Matches(
                $report,
                ('(?im)Kernel driver image loaded after OAC started and before ' +
                'session configuration:.*OAC-Gate-Probe\.sys')
            ).Count -ne 0
        }

        $passed = $triggerValidated -and $detectionExit -eq 1 -and
            $gateFinding -and $callbackFinding -and -not $preSessionFinding
        $summary = [ordered]@{
            timestamp_utc = [DateTime]::UtcNow.ToString('o')
            trigger_exit = $startExit
            start_error = $startError
            armed_probe_validation = $triggerValidated
            detection_exit = $detectionExit
            persistent_gate_finding = $gateFinding
            callback_finding = $callbackFinding
            pre_session_callback = $preSessionFinding
            pass = $passed
        }
        $summary | ConvertTo-Json | Out-File -LiteralPath $summaryPath -Encoding utf8
        if (-not $passed) {
            throw "Post-start driver gate probe failed; see $summaryPath."
        }
    } catch {
        $primaryError = $_
        throw
    } finally {
        try {
            $stopExit = Invoke-ConsoleCapture `
                'baseline-driver-gate-stop' 'sc.exe' @('stop', $serviceName)
            if ($stopExit -notin @(0, 1062)) {
                throw "stop exit=$stopExit"
            }
        } catch {
            $cleanupErrors.Add("gate stop: $($_.Exception.Message)")
        }
        try {
            $deleteExit = Invoke-ConsoleCapture `
                'baseline-driver-gate-delete' 'sc.exe' @('delete', $serviceName)
            if ($deleteExit -ne 0) {
                throw "delete exit=$deleteExit"
            }
        } catch {
            $cleanupErrors.Add("gate delete: $($_.Exception.Message)")
        }
        try {
            $deadline = [DateTime]::UtcNow.AddSeconds(20)
            while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -and
                [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 250
            }
            if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
                throw 'service remained present after bounded wait'
            }
        } catch {
            $cleanupErrors.Add("gate retirement: $($_.Exception.Message)")
        }
        try {
            Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $probePath) {
                throw 'image remained present after removal'
            }
        } catch {
            $cleanupErrors.Add("gate image: $($_.Exception.Message)")
        }
        foreach ($cleanupError in $cleanupErrors) {
            try { Write-RunLog "Driver-gate cleanup error: $cleanupError" } catch { }
        }
        if ($null -eq $primaryError -and $cleanupErrors.Count -ne 0) {
            throw "Driver-gate cleanup failed: $($cleanupErrors -join '; ')"
        }
    }
    Write-RunLog 'Transient renamed-driver load was retained by the fail-closed gate.'
    return [pscustomobject]$summary
}

function Install-And-RunBaseline {
    Set-Phase 'baseline-running'
    Write-RunLog 'Beginning signed-load and baseline protocol tests.'
    try {
        Wait-ForInteractiveTestUser
        Initialize-InteractiveTaskRoot
    } finally {
        Clear-LabAutoLogon
    }

    Save-PlatformState 'baseline'
    $bcd = Get-Content -LiteralPath (Join-Path $results 'baseline-bcd.txt') -Raw
    if ($bcd -notmatch '(?im)^testsigning\s+Yes\s*$') {
        throw 'The guest did not reboot with TESTSIGNING enabled.'
    }
    try {
        if (Confirm-SecureBootUEFI) { throw 'Secure Boot is unexpectedly enabled in the VM.' }
    } catch [Microsoft.SecureBoot.Commands.PlatformNotSupportedException] { }

    $installer = Join-Path $root 'Install-OACTestDriver.ps1'
    $installExit = Invoke-NativeCapture 'baseline-install' 'PowerShell.exe' @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installer,
        '-PackageDirectory', (Join-Path $root 'package'),
        '-ConfirmDisposableVm', '-LegacyV4LabMode')
    if ($installExit -ne 0) { throw "Driver installation failed with exit code $installExit." }

    Get-AuthenticodeSignature -FilePath (Join-Path $root 'package\OAC.sys') |
        Format-List * | Out-File -LiteralPath (Join-Path $results 'baseline-driver-signature.txt') -Encoding utf8
    Invoke-ConsoleCapture 'baseline-sc-query' 'sc.exe' @('query', 'OAC') | Out-Null
    $unitExit = Invoke-NativeCapture 'baseline-protocol-unit' `
        (Join-Path $root 'OAC-Protocol-Unit.exe')
    Test-ProductionBoundary
    Test-RemovalBoundary
    $protocolExit = Invoke-NativeCapture 'baseline-protocol' `
        (Join-Path $root 'OAC-Protocol-Test.exe')
    # The protocol lifecycle test intentionally exercises target cleanup after
    # its last finding drain. Start the independent scanner test with a fresh
    # driver lifetime so late lifecycle telemetry cannot cross test boundaries.
    $protocolBoundaryStop = Invoke-ConsoleCapture `
        'baseline-protocol-boundary-stop' 'sc.exe' @('stop', 'OAC')
    if ($protocolBoundaryStop -ne 0) {
        throw "Could not end the protocol-test driver lifetime; exit=$protocolBoundaryStop."
    }
    Wait-TestServiceState OAC `
        ([ServiceProcess.ServiceControllerStatus]::Stopped)
    $protocolBoundaryStart = Invoke-ConsoleCapture `
        'baseline-protocol-boundary-start' 'sc.exe' @('start', 'OAC')
    if ($protocolBoundaryStart -ne 0) {
        throw "Could not start the scanner-test driver lifetime; exit=$protocolBoundaryStart."
    }
    Wait-TestServiceState OAC `
        ([ServiceProcess.ServiceControllerStatus]::Running)
    $preflightExit = Invoke-NativeCapture 'baseline-preflight' `
        (Join-Path $root 'package\OAC-Client.exe') @(
            '--preflight', '--mode', 'test', '--fail-on', 'medium',
            '--output', (Join-Path $results 'baseline-preflight-report'))
    Assert-KernelFindingProvenance `
        (Join-Path $results 'baseline-preflight-report\oac-report.txt')
    $launchExit = Invoke-NativeCapture 'baseline-launch' `
        (Join-Path $root 'package\OAC-Client.exe') @(
            '--launch', "$env:SystemRoot\System32\cmd.exe",
            '--launch-args', '"/d /c \"ping.exe -n 6 127.0.0.1 >nul\""',
            '--mode', 'test', '--fail-on', 'high', '--monitor-interval-ms', '500',
            '--output', (Join-Path $results 'baseline-launch-report'))
    Assert-ProtectedLaunchReport (Join-Path $results 'baseline-launch-report') `
        'Baseline protected launch report'

    $target = Start-ScanTarget
    $gateSummary = $null
    try {
        # Controller cleanup retains a live-target tombstone. Observe target
        # exit before the gate probe opens a new controller session.
        try {
            $clientExit = Invoke-NativeCapture 'baseline-client' `
                (Join-Path $root 'package\OAC-Client.exe') @(
                    '--pid', ([string]$target.Id), '--mode', 'test', '--fail-on', 'medium',
                    '--output', (Join-Path $results 'baseline-client-report'))
        } finally {
            Stop-ScanTarget $target 'baseline-target-stop'
        }
        $gateSummary = Test-DriverGate
    } finally {
        Invoke-ConsoleCapture 'baseline-sc-stop' 'sc.exe' @('stop', 'OAC') | Out-Null
    }

    $baselineExitFailures = [Collections.Generic.List[string]]::new()
    foreach ($name in $baselineZeroTests) {
        $value = Read-CapturedExit $name
        if ($value -ne 0) { $baselineExitFailures.Add("$name=$value") }
    }
    $repeatRemoveExit = Read-CapturedExit 'baseline-remove-repeat-expected-refusal'
    if ($repeatRemoveExit -eq 0) {
        $baselineExitFailures.Add('baseline-remove-repeat-expected-refusal=0')
    }
    if ((Read-CapturedExit 'baseline-driver-gate-create') -ne 0) {
        $baselineExitFailures.Add('baseline-driver-gate-create')
    }
    if ((Read-CapturedExit 'baseline-driver-gate-trigger') -ne 0) {
        $baselineExitFailures.Add('baseline-driver-gate-trigger')
    }
    if ((Read-CapturedExit 'baseline-driver-gate-detection') -ne 1) {
        $baselineExitFailures.Add('baseline-driver-gate-detection')
    }
    if ((Read-CapturedExit 'baseline-driver-gate-stop') -notin @(0, 1062)) {
        $baselineExitFailures.Add('baseline-driver-gate-stop')
    }
    if ((Read-CapturedExit 'baseline-driver-gate-delete') -ne 0) {
        $baselineExitFailures.Add('baseline-driver-gate-delete')
    }
    $baselineFormalNames = @($baselineZeroTests) + @($baselineSpecialTests)
    $auxiliary = Get-AuxiliaryExitValidation $baselineFormalNames $false
    foreach ($name in $auxiliary.Missing) {
        $baselineExitFailures.Add("auxiliary-missing:$name")
    }
    foreach ($name in $auxiliary.Unexpected) {
        $baselineExitFailures.Add("auxiliary-unexpected:$name")
    }
    foreach ($name in $auxiliary.Malformed) {
        $baselineExitFailures.Add("auxiliary-malformed:$name")
    }
    foreach ($name in $auxiliary.Wrong) {
        $baselineExitFailures.Add("auxiliary-wrong:$name")
    }
    $productionPass = [bool]((Get-Content -LiteralPath `
            (Join-Path $results 'production-boundary-summary.json') -Raw |
        ConvertFrom-Json).pass)
    $removalPass = [bool]((Get-Content -LiteralPath `
            (Join-Path $results 'removal-boundary-summary.json') -Raw |
        ConvertFrom-Json).pass)
    $provenancePass = [bool]((Get-Content -LiteralPath `
            (Join-Path $results 'baseline-provenance-summary.json') -Raw |
        ConvertFrom-Json).pass)
    $baselinePass = $baselineExitFailures.Count -eq 0 -and
        [bool]$gateSummary.pass -and $productionPass -and $removalPass -and
        $provenancePass

    [ordered]@{
        campaign_id = $script:CampaignId
        campaign_start_utc = $script:CampaignStartUtc.ToString('o')
        manifest_sha256 = $script:ManifestHash
        source_commit = $script:SourceCommit
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        install_exit = $installExit
        protocol_unit_exit = $unitExit
        protocol_exit = $protocolExit
        preflight_exit = $preflightExit
        launch_exit = $launchExit
        client_exit = $clientExit
        driver_gate_exit = $gateSummary.detection_exit
        driver_gate_pass = $gateSummary.pass
        production_boundary_pass = $productionPass
        removal_boundary_pass = $removalPass
        provenance_pass = $provenancePass
        exit_failures = @($baselineExitFailures)
        pass = $baselinePass
    } | ConvertTo-Json | Out-File -LiteralPath `
        (Join-Path $results 'baseline-summary.json') -Encoding utf8

    if (-not $baselinePass) {
        throw "Baseline result contract failed: $($baselineExitFailures -join ', ')"
    }

    Set-Phase 'baseline-complete'
    Write-RunLog 'Baseline complete. Shutting down for a host-side clean snapshot.'
    Start-Sleep -Seconds 3
    Stop-Computer -Force
}

function Arm-DriverVerifier {
    if (-not (Test-Path -LiteralPath $verifierAuthorizationPath -PathType Leaf)) {
        Write-RunLog 'Verifier authorization is absent; preserving the safe baseline and shutting down.'
        Start-Sleep -Seconds 3
        Stop-Computer -Force
        return
    }
    Assert-CampaignMarker $verifierAuthorizationPath 'Verifier authorization'
    $consumedAuthorizationPath = Join-Path $root `
        'verifier-authorized.consumed.json'
    if ([IO.File]::Exists($consumedAuthorizationPath)) {
        throw 'A stale consumed Verifier authorization is present.'
    }
    [IO.File]::Move($verifierAuthorizationPath, $consumedAuthorizationPath)
    Assert-CampaignMarker $consumedAuthorizationPath 'Consumed Verifier authorization'
    [IO.File]::Delete($consumedAuthorizationPath)
    if ([IO.File]::Exists($verifierAuthorizationPath) -or
        [IO.File]::Exists($consumedAuthorizationPath)) {
        throw 'The one-use Verifier authorization could not be consumed.'
    }
    Set-Phase 'verifier-authorized'
    Write-RunLog 'Arming standard Driver Verifier checks for OAC.sys.'
    $preResetExit = Invoke-ConsoleCapture 'verifier-pre-reset' 'verifier.exe' @('/reset')
    if ($preResetExit -notin @(0, 2)) {
        throw "The preflight Driver Verifier reset failed; exit code $preResetExit."
    }
    $armExit = Invoke-ConsoleCapture 'verifier-arm' 'verifier.exe' `
        @('/standard', '/driver', 'OAC.sys')
    Invoke-ConsoleCapture 'verifier-armed-settings' 'verifier.exe' @('/querysettings') | Out-Null
    if ($armExit -notin @(0, 2)) {
        throw "Driver Verifier could not be armed for OAC.sys; exit code $armExit."
    }
    Assert-VerifierTargets 'verifier-armed-settings' $true
    Set-Phase 'verifier-armed'
    Write-RunLog 'Driver Verifier armed. Rebooting before exercising the driver.'
    Start-Sleep -Seconds 3
    Restart-Computer -Force
}

function Run-UnderDriverVerifier {
    Set-Phase 'verifier-running'
    Write-RunLog 'Booted with Driver Verifier armed; beginning stress tests.'
    Save-PlatformState 'verifier'
    $labMode = [int](Get-ItemProperty -LiteralPath `
        'HKLM:\SYSTEM\CurrentControlSet\Services\OAC\Parameters' `
        -Name LabMode).LabMode
    if ($labMode -ne 1) {
        throw 'Legacy v4 Verifier tests require the explicit LabMode=1 setting.'
    }
    Invoke-ConsoleCapture 'verifier-active-settings' 'verifier.exe' @('/querysettings') | Out-Null
    Assert-VerifierTargets 'verifier-active-settings' $true
    $startExit = Invoke-ConsoleCapture 'verifier-sc-start' 'sc.exe' @('start', 'OAC')
    if ($startExit -ne 0 -and $startExit -ne 1056) {
        throw "The verified driver failed to start; sc.exe exit code $startExit."
    }

    for ($iteration = 1; $iteration -le 3; ++$iteration) {
        Invoke-NativeCapture "verifier-protocol-$iteration" `
            (Join-Path $root 'OAC-Protocol-Test.exe') | Out-Null
    }

    # Protocol cleanup can emit findings after the test's final drain. Reload
    # the verified driver before the independent medium-threshold scan.
    $protocolBoundaryStop = Invoke-ConsoleCapture `
        'verifier-protocol-boundary-sc-stop' 'sc.exe' @('stop', 'OAC')
    if ($protocolBoundaryStop -ne 0) {
        throw "Could not end the verified protocol lifetime; exit=$protocolBoundaryStop."
    }
    Wait-TestServiceState OAC `
        ([ServiceProcess.ServiceControllerStatus]::Stopped)
    $protocolBoundaryStart = Invoke-ConsoleCapture `
        'verifier-protocol-boundary-sc-start' 'sc.exe' @('start', 'OAC')
    if ($protocolBoundaryStart -ne 0) {
        throw "Could not start the verified scanner lifetime; exit=$protocolBoundaryStart."
    }
    Wait-TestServiceState OAC `
        ([ServiceProcess.ServiceControllerStatus]::Running)

    Invoke-NativeCapture 'verifier-preflight' `
        (Join-Path $root 'package\OAC-Client.exe') @(
            '--preflight', '--mode', 'test', '--fail-on', 'medium',
            '--output', (Join-Path $results 'verifier-preflight-report')) | Out-Null
    Invoke-NativeCapture 'verifier-launch' `
        (Join-Path $root 'package\OAC-Client.exe') @(
            '--launch', "$env:SystemRoot\System32\cmd.exe",
            '--launch-args', '"/d /c \"ping.exe -n 6 127.0.0.1 >nul\""',
            '--mode', 'test', '--fail-on', 'high', '--monitor-interval-ms', '500',
            '--output', (Join-Path $results 'verifier-launch-report')) | Out-Null
    Assert-ProtectedLaunchReport (Join-Path $results 'verifier-launch-report') `
        'Verifier protected launch report'

    try {
        # Each diagnostic controller needs a target whose prior tombstone has
        # already retired, so use and reap one target per iteration.
        for ($iteration = 1; $iteration -le 2; ++$iteration) {
            $target = Start-ScanTarget
            try {
                Invoke-NativeCapture "verifier-client-$iteration" `
                    (Join-Path $root 'package\OAC-Client.exe') @(
                        '--pid', ([string]$target.Id), '--mode', 'test',
                        '--fail-on', 'medium',
                        '--output', (Join-Path $results "verifier-client-$iteration-report")) |
                    Out-Null
            } finally {
                Stop-ScanTarget $target "verifier-target-$iteration-stop"
            }
            if ($iteration -eq 1) {
                # Findings can arrive after the client's final drain while its
                # target is still protected. Establish a fresh driver lifetime
                # so the second client cannot inherit target-one telemetry.
                $stopExit = Invoke-ConsoleCapture `
                    'verifier-inter-client-sc-stop' 'sc.exe' @('stop', 'OAC')
                if ($stopExit -ne 0) {
                    throw "Could not stop OAC between Verifier clients; exit code $stopExit."
                }
                Wait-TestServiceState 'OAC' `
                    ([ServiceProcess.ServiceControllerStatus]::Stopped)
                $startExit = Invoke-ConsoleCapture `
                    'verifier-inter-client-sc-start' 'sc.exe' @('start', 'OAC')
                if ($startExit -ne 0) {
                    throw "Could not restart OAC between Verifier clients; exit code $startExit."
                }
                Wait-TestServiceState 'OAC' `
                    ([ServiceProcess.ServiceControllerStatus]::Running)
            }
        }
    } finally {
        Invoke-ConsoleCapture 'verifier-sc-stop' 'sc.exe' @('stop', 'OAC') | Out-Null
    }

    $queryExit = Invoke-ConsoleCapture 'verifier-query-after-stress' `
        'verifier.exe' @('/query')
    if ($queryExit -notin @(0, 2)) {
        throw "The post-stress Driver Verifier query failed; exit code $queryExit."
    }
    $resetExit = Invoke-ConsoleCapture 'verifier-reset' 'verifier.exe' @('/reset')
    if ($resetExit -notin @(0, 2)) {
        throw "Driver Verifier reset failed; exit code $resetExit."
    }
    Set-Phase 'finalize'
    Write-RunLog 'Verifier stress completed without an intervening reboot; rebooting to clear settings.'
    Start-Sleep -Seconds 3
    Restart-Computer -Force
}

function Recover-FromVerifierRestart {
    Write-RunLog 'Detected an unexpected reboot while the driver was under verification.'
    Set-Content -LiteralPath (Join-Path $results 'verifier-unexpected-reboot.txt') `
        -Value ([DateTime]::UtcNow.ToString('o')) -Encoding ascii
    $resetExit = Invoke-ConsoleCapture 'verifier-emergency-reset' `
        'verifier.exe' @('/reset')
    if ($resetExit -notin @(0, 2)) {
        throw "Emergency Driver Verifier reset failed; exit code $resetExit."
    }
    Set-Phase 'finalize'
    Write-RunLog 'Verifier was reset after the unexpected reboot; rebooting to finalize safely.'
    Start-Sleep -Seconds 3
    Restart-Computer -Force
}

function Recover-FromBaselineRestart {
    Write-RunLog 'Detected an unexpected reboot during baseline driver testing.'
    Set-Content -LiteralPath (Join-Path $results 'baseline-unexpected-reboot.txt') `
        -Value ([DateTime]::UtcNow.ToString('o')) -Encoding ascii
    $resetExit = Invoke-ConsoleCapture 'baseline-emergency-verifier-reset' `
        'verifier.exe' @('/reset')
    if ($resetExit -notin @(0, 2)) {
        throw "Baseline recovery could not reset Driver Verifier; exit code $resetExit."
    }
    Set-Phase 'finalize'
    Write-RunLog 'Rebooting to collect crash evidence without loading the demand-start driver.'
    Start-Sleep -Seconds 3
    Restart-Computer -Force
}

function Remove-MainRecoveryTask {
    $mainTask = Get-ScheduledTask -TaskName 'OAC-VM-Test' `
        -ErrorAction SilentlyContinue
    if ($null -ne $mainTask) {
        Unregister-ScheduledTask -TaskName 'OAC-VM-Test' -Confirm:$false `
            -ErrorAction Stop
    }
    $remaining = @(Get-ScheduledTask -ErrorAction Stop |
        Where-Object TaskName -Like 'OAC-VM-*' |
        Select-Object -ExpandProperty TaskName -Unique)
    if ($remaining.Count -ne 0) {
        throw "OAC scheduled tasks remain after final cleanup: $($remaining -join ', ')"
    }
}

function Test-BaselineFailureEvidence {
    return (Test-Path -LiteralPath `
            (Join-Path $results 'baseline-running-failure.txt') -PathType Leaf) -or
        (Test-Path -LiteralPath `
            (Join-Path $results 'baseline-unexpected-reboot.txt') -PathType Leaf)
}

function Collect-FinalResults {
    Write-RunLog 'Collecting final VM, verifier, crash, signature, and event-log evidence.'
    Save-PlatformState 'final'
    Invoke-ConsoleCapture 'final-verifier-settings' 'verifier.exe' @('/querysettings') | Out-Null
    Assert-VerifierTargets 'final-verifier-settings' $false
    $finalVerifierQueryExit = Invoke-ConsoleCapture 'final-verifier-query' `
        'verifier.exe' @('/query')
    if ($finalVerifierQueryExit -notin @(0, 2)) {
        throw "The final Driver Verifier query failed; exit code $finalVerifierQueryExit."
    }

    $containmentErrors = [Collections.Generic.List[string]]::new()
    foreach ($serviceName in @('OACService', 'OAC')) {
        try {
            Stop-TestService "final-$($serviceName.ToLowerInvariant())-stop" $serviceName
        } catch {
            $containmentErrors.Add("$serviceName stop: $($_.Exception.Message)")
        }
    }
    Invoke-ConsoleCapture 'final-sc-query' 'sc.exe' @('query', 'OAC') | Out-Null
    Invoke-ConsoleCapture 'final-service-query' 'sc.exe' @('query', 'OACService') | Out-Null
    Invoke-ConsoleCapture 'final-driverquery' 'driverquery.exe' @('/v', '/fo', 'csv') | Out-Null

    $systemExportSuccess = $false
    $systemExportError = $null
    try {
        $systemExportExit = Invoke-ConsoleCapture 'final-system-export' `
            'wevtutil.exe' @(
                'epl', 'System', (Join-Path $results 'System.evtx'), '/ow:true')
        $systemExportSuccess = $systemExportExit -eq 0 -and
            (Test-Path -LiteralPath (Join-Path $results 'System.evtx') -PathType Leaf)
        if (-not $systemExportSuccess) {
            throw "System event-log export exited with $systemExportExit."
        }
    } catch { $systemExportError = $_.Exception.Message }

    $integrityExportSuccess = $false
    $integrityExportError = $null
    try {
        $integrityExportExit = Invoke-ConsoleCapture 'final-code-integrity-export' `
            'wevtutil.exe' @(
                'epl', 'Microsoft-Windows-CodeIntegrity/Operational',
                (Join-Path $results 'CodeIntegrity-Operational.evtx'), '/ow:true')
        $integrityExportSuccess = $integrityExportExit -eq 0 -and
            (Test-Path -LiteralPath `
                (Join-Path $results 'CodeIntegrity-Operational.evtx') -PathType Leaf)
        if (-not $integrityExportSuccess) {
            throw "Code Integrity event-log export exited with $integrityExportExit."
        }
    } catch { $integrityExportError = $_.Exception.Message }

    $since = $script:CampaignStartUtc
    $sinceUtc = $since.ToUniversalTime()
    $systemQuerySuccess = $false
    $systemQueryError = $null
    $crashEvents = @()
    try {
        $systemCandidates = @(Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                StartTime = $since.ToLocalTime()
                Id = 41, 1001, 6008
            } -ErrorAction Stop)
        $systemQuerySuccess = $true
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            $systemCandidates = @()
            $systemQuerySuccess = $true
        } else {
            $systemCandidates = @()
            $systemQueryError = $_.Exception.Message
        }
    }
    $crashEvents = @($systemCandidates | Where-Object {
            $_.TimeCreated.ToUniversalTime() -ge $sinceUtc -and (
                ($_.Id -eq 41 -and
                    $_.ProviderName -ieq 'Microsoft-Windows-Kernel-Power') -or
                ($_.Id -eq 1001 -and
                    $_.ProviderName -ieq 'Microsoft-Windows-WER-SystemErrorReporting') -or
                ($_.Id -eq 6008 -and $_.ProviderName -ieq 'EventLog'))
        })
    $crashEvents | Format-List TimeCreated, Id, ProviderName, LevelDisplayName, Message |
        Out-File -LiteralPath (Join-Path $results 'crash-events.txt') -Encoding utf8
    $integrityQuerySuccess = $false
    $integrityQueryError = $null
    $integrityEvents = @()
    try {
        $integrityEvents = @(Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
                StartTime = $since.ToLocalTime()
            } -ErrorAction Stop | Where-Object {
                $_.TimeCreated.ToUniversalTime() -ge $sinceUtc
            })
        $integrityQuerySuccess = $true
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            $integrityEvents = @()
            $integrityQuerySuccess = $true
        } else {
            $integrityQueryError = $_.Exception.Message
        }
    }
    $integrityEvents | Format-List TimeCreated, Id, LevelDisplayName, Message |
        Out-File -LiteralPath (Join-Path $results 'code-integrity-events.txt') -Encoding utf8

    $dumpDirectory = Join-Path $env:SystemRoot 'Minidump'
    $dumps = @()
    if (Test-Path -LiteralPath $dumpDirectory) {
        $dumps = @(Get-ChildItem -LiteralPath $dumpDirectory -Filter '*.dmp' -File |
            Where-Object LastWriteTimeUtc -GE $since.ToUniversalTime())
        $dumpOutput = Join-Path $results 'minidumps'
        New-Item -ItemType Directory -Path $dumpOutput -Force | Out-Null
        foreach ($dump in $dumps) { Copy-Item -LiteralPath $dump.FullName -Destination $dumpOutput -Force }
    }

    $specialResults = @($baselineSpecialTests)
    $expectedResultNames = @($requiredZeroTests) + $specialResults
    $observedTestResultNames = @(Get-ChildItem -LiteralPath $results `
            -Filter '*.exitcode.txt' -File | ForEach-Object {
                $name = $_.Name.Substring(
                    0, $_.Name.Length - '.exitcode.txt'.Length)
                if ($expectedResultNames -ccontains $name) {
                    $name
                }
            } | Sort-Object -Unique)
    $missingResultNames = @($expectedResultNames | Where-Object {
            $observedTestResultNames -cnotcontains $_
        })
    $unexpectedResultNames = @($observedTestResultNames | Where-Object {
            $expectedResultNames -cnotcontains $_
        })
    $malformedResultNames = [Collections.Generic.List[string]]::new()
    $exitValues = @{}
    foreach ($name in $expectedResultNames) {
        $path = Join-Path $results "$name.exitcode.txt"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $value = [int64]0
        $text = (Get-Content -LiteralPath $path -Raw).Trim()
        if (-not [int64]::TryParse(
                $text,
                [Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$value)) {
            $malformedResultNames.Add($name)
            continue
        }
        $exitValues[$name] = $value
    }
    $wrongResultValues = [Collections.Generic.List[string]]::new()
    foreach ($name in $requiredZeroTests) {
        if ($exitValues.ContainsKey($name) -and $exitValues[$name] -ne 0) {
            $wrongResultValues.Add("$name=$($exitValues[$name])")
        }
    }
    foreach ($name in @('baseline-remove-repeat-expected-refusal')) {
        if ($exitValues.ContainsKey($name) -and $exitValues[$name] -eq 0) {
            $wrongResultValues.Add("$name=0")
        }
    }
    $specialExpectedValues = [ordered]@{
        'production-manifest-modified' = @(5)
        'production-manifest-wrong-build' = @(5)
        'production-manifest-expired' = @(5)
        'production-manifest-rollback' = @(5)
        'production-policy-wrong-signature' = @(3)
        'production-policy-wrong-scope' = @(5)
        'production-policy-expired' = @(3)
        'production-policy-rollback' = @(3)
        'production-policy-authorized-rollback' = @(0)
        'production-policy-emergency-revoke' = @(3)
        'production-backend-replay' = @(3)
        'baseline-driver-gate-create' = @(0)
        'baseline-driver-gate-trigger' = @(0)
        'baseline-driver-gate-detection' = @(1)
        'baseline-driver-gate-stop' = @(0, 1062)
        'baseline-driver-gate-delete' = @(0)
    }
    foreach ($entry in $specialExpectedValues.GetEnumerator()) {
        if ($exitValues.ContainsKey($entry.Key) -and
            $exitValues[$entry.Key] -notin $entry.Value) {
            $wrongResultValues.Add("$($entry.Key)=$($exitValues[$entry.Key])")
        }
    }
    $exactResultSetPass = $missingResultNames.Count -eq 0 -and
        $unexpectedResultNames.Count -eq 0 -and
        $malformedResultNames.Count -eq 0 -and
        $wrongResultValues.Count -eq 0

    $unexpectedRestart = Test-Path -LiteralPath (Join-Path $results 'verifier-unexpected-reboot.txt')
    $baselineUnexpectedRestart = Test-Path -LiteralPath `
        (Join-Path $results 'baseline-unexpected-reboot.txt')
    $fatalFiles = @(Get-ChildItem -LiteralPath $results -Filter '*-failure.txt' -File)
    $summaryPass = [ordered]@{}
    $summaryErrors = [Collections.Generic.List[string]]::new()
    foreach ($summaryName in @(
            'baseline-driver-gate-summary',
            'production-boundary-summary',
            'backend-boundary-summary',
            'removal-boundary-summary',
            'baseline-provenance-summary')) {
        $summaryPath = Join-Path $results "$summaryName.json"
        try {
            $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
            $summaryPass[$summaryName] = $summary.pass -is [bool] -and $summary.pass
            if (-not $summaryPass[$summaryName]) {
                $summaryErrors.Add("$summaryName did not report pass=true")
            }
        } catch {
            $summaryPass[$summaryName] = $false
            $summaryErrors.Add("$summaryName is missing or invalid")
        }
    }

    $baselineIdentityPass = $false
    try {
        $baselineSummary = Get-Content -LiteralPath `
            (Join-Path $results 'baseline-summary.json') -Raw | ConvertFrom-Json
        $baselineStart = [DateTime]::MinValue
        $baselineIdentityPass = $baselineSummary.pass -is [bool] -and
            $baselineSummary.pass -and
            [string]$baselineSummary.campaign_id -ceq $script:CampaignId -and
            [string]$baselineSummary.manifest_sha256 -ceq $script:ManifestHash -and
            [string]$baselineSummary.source_commit -ceq $script:SourceCommit -and
            [DateTime]::TryParse(
                [string]$baselineSummary.campaign_start_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$baselineStart) -and
            $baselineStart.ToUniversalTime() -eq $script:CampaignStartUtc
    } catch { }
    if (-not $baselineIdentityPass) {
        $summaryErrors.Add('baseline-summary identity or pass state is invalid')
    }

    $manifestHashNow = (Get-FileHash -LiteralPath `
        (Join-Path $root 'package-manifest.json') -Algorithm SHA256).Hash
    $manifestCurrent = $manifestHashNow -ceq $script:ManifestHash

    $verifierResetPass = $false
    try {
        $verifierResetPass = -not $unexpectedRestart -and
            (Read-CapturedExit 'verifier-reset') -in @(0, 2)
    } catch { }

    $serviceStates = [ordered]@{}
    foreach ($serviceName in @('OACService', 'OAC')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $serviceStates[$serviceName] = if ($null -eq $service) {
            'missing'
        } else {
            [string]$service.Status
        }
    }
    $containedServiceStates = @('missing', 'Stopped')
    $servicesContained = `
        ($containedServiceStates -ccontains $serviceStates.OACService) -and
        ($containedServiceStates -ccontains $serviceStates.OAC)
    $servicesPresentAndStopped = $serviceStates.OACService -ceq 'Stopped' -and
        $serviceStates.OAC -ceq 'Stopped'

    $gateService = Get-Service -Name 'OACGateProbe' -ErrorAction SilentlyContinue
    if ($null -ne $gateService) {
        try { Stop-TestService 'final-gate-stop' 'OACGateProbe' } catch {
            $containmentErrors.Add("OACGateProbe stop: $($_.Exception.Message)")
        }
        try {
            $deleteExit = Invoke-ConsoleCapture 'final-gate-delete' `
                'sc.exe' @('delete', 'OACGateProbe')
            if ($deleteExit -notin @(0, 1060, 1072)) {
                $containmentErrors.Add("OACGateProbe delete exit=$deleteExit")
            }
        } catch {
            $containmentErrors.Add("OACGateProbe delete: $($_.Exception.Message)")
        }
    }
    $gateDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while ((Get-Service -Name 'OACGateProbe' -ErrorAction SilentlyContinue) -and
        [DateTime]::UtcNow -lt $gateDeadline) {
        Start-Sleep -Milliseconds 250
    }
    $gateProbePath = Join-Path $root 'OAC-Gate-Probe.sys'
    if (Test-Path -LiteralPath $gateProbePath) {
        try { Remove-Item -LiteralPath $gateProbePath -Force } catch {
            $containmentErrors.Add("OACGateProbe image: $($_.Exception.Message)")
        }
    }
    $gateContained = $null -eq (Get-Service -Name 'OACGateProbe' `
            -ErrorAction SilentlyContinue) -and
        -not (Test-Path -LiteralPath $gateProbePath)
    $auxiliaryValidation = Get-AuxiliaryExitValidation $expectedResultNames $true
    $exactResultSetPass = $exactResultSetPass -and
        $auxiliaryValidation.Missing.Count -eq 0 -and
        $auxiliaryValidation.Unexpected.Count -eq 0 -and
        $auxiliaryValidation.Malformed.Count -eq 0 -and
        $auxiliaryValidation.Wrong.Count -eq 0

    $interactiveStagingRemoved = $false
    try {
        $interactiveRoot = Get-InteractiveTaskRootPath
        if (Test-Path -LiteralPath $interactiveRoot -PathType Container) {
            $stagedItems = @(Get-ChildItem -LiteralPath $interactiveRoot -Force)
            if ($stagedItems.Count -ne 0) {
                throw "Interactive staging contains $($stagedItems.Count) residual item(s)."
            }
            Remove-Item -LiteralPath $interactiveRoot -Force
        }
        $interactiveStagingRemoved = -not (Test-Path -LiteralPath $interactiveRoot)
    } catch {
        $containmentErrors.Add("Interactive staging: $($_.Exception.Message)")
    }

    Clear-LabAutoLogon
    $autoLogonCleared = $false
    try {
        $winlogon = Get-ItemProperty -LiteralPath `
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
            -ErrorAction Stop
        $autoLogonNames = @(
            'AutoAdminLogon', 'DefaultUserName', 'DefaultDomainName',
            'DefaultPassword', 'AutoLogonCount')
        $presentAutoLogonNames = @($winlogon.PSObject.Properties.Name |
            Where-Object { $_ -in $autoLogonNames })
        $autoLogonCleared = $presentAutoLogonNames.Count -eq 0
        if (-not $autoLogonCleared) {
            $containmentErrors.Add(
                "Auto-logon values remain: $($presentAutoLogonNames -join ', ')")
        }
    } catch {
        $containmentErrors.Add("Auto-logon validation: $($_.Exception.Message)")
    }
    $remainingTasks = @()
    $taskEnumerationSuccess = $false
    try {
        $remainingTasks = @(Get-ScheduledTask -ErrorAction Stop |
            Where-Object TaskName -Like 'OAC-VM-*' |
            Select-Object -ExpandProperty TaskName -Unique)
        $taskEnumerationSuccess = $true
    } catch {
        $containmentErrors.Add("Scheduled-task enumeration: $($_.Exception.Message)")
    }
    $temporaryTasks = @($remainingTasks | Where-Object { $_ -cne 'OAC-VM-Test' })
    $recoveryTaskCount = @($remainingTasks | Where-Object { $_ -ceq 'OAC-VM-Test' }).Count
    $tasksContained = $taskEnumerationSuccess -and
        $temporaryTasks.Count -eq 0 -and $recoveryTaskCount -eq 1

    $protocolTestCount = @($requiredZeroTests | Where-Object {
            $_ -match 'protocol'
        }).Count
    $clientScanCount = @($requiredZeroTests | Where-Object {
            $_ -match 'client|preflight|launch'
        }).Count
    $fatalFileNames = @($fatalFiles | ForEach-Object { $_.Name })
    $crashEventIds = @($crashEvents | ForEach-Object { $_.Id })
    $overallPass = $exactResultSetPass -and $dumps.Count -eq 0 -and `
        $crashEvents.Count -eq 0 -and $verifierResetPass -and `
        $systemExportSuccess -and $systemQuerySuccess -and `
        $integrityExportSuccess -and $integrityQuerySuccess -and `
        -not $unexpectedRestart -and -not $baselineUnexpectedRestart -and `
        $fatalFiles.Count -eq 0 -and `
        @($summaryPass.Values | Where-Object { -not $_ }).Count -eq 0 -and `
        $baselineIdentityPass -and $manifestCurrent -and `
        $servicesPresentAndStopped -and `
        $gateContained -and $interactiveStagingRemoved -and $tasksContained -and `
        $containmentErrors.Count -eq 0

    $containmentReady = $servicesContained -and $gateContained -and `
        $interactiveStagingRemoved -and $autoLogonCleared -and `
        $tasksContained -and `
        -not (Test-Path -LiteralPath $verifierAuthorizationPath) -and `
        -not (Test-Path -LiteralPath `
            (Join-Path $root 'verifier-authorized.consumed.json')) -and `
        $containmentErrors.Count -eq 0
    if (-not $containmentReady) {
        throw 'Final containment did not reach the durable publication boundary.'
    }
    Write-CampaignMarker $containmentReadyPath

    $operatingSystem = Get-CimInstance Win32_OperatingSystem
    $status = [ordered]@{
        schema = 1
        campaign_id = $script:CampaignId
        campaign_start_utc = $script:CampaignStartUtc.ToString('o')
        manifest_sha256 = $script:ManifestHash
        source_commit = $script:SourceCommit
        completed_utc = [DateTime]::UtcNow.ToString('o')
        computer_name = $env:COMPUTERNAME
        windows = $operatingSystem.Caption
        windows_version = $operatingSystem.Version
        windows_build = $operatingSystem.BuildNumber
        required_test_count = $expectedResultNames.Count
        protocol_test_count = $protocolTestCount
        client_scan_count = $clientScanCount
        exact_result_set_pass = $exactResultSetPass
        missing_test_results = $missingResultNames
        unexpected_test_results = $unexpectedResultNames
        malformed_test_results = @($malformedResultNames)
        wrong_test_results = @($wrongResultValues)
        missing_auxiliary_results = @($auxiliaryValidation.Missing)
        unexpected_auxiliary_results = @($auxiliaryValidation.Unexpected)
        malformed_auxiliary_results = @($auxiliaryValidation.Malformed)
        wrong_auxiliary_results = @($auxiliaryValidation.Wrong)
        baseline_unexpected_restart = $baselineUnexpectedRestart
        verifier_unexpected_restart = $unexpectedRestart
        verifier_reset_pass = $verifierResetPass
        verifier_inactive = $true
        minidump_count = $dumps.Count
        crash_event_count = $crashEvents.Count
        crash_event_ids = $crashEventIds
        system_export_success = $systemExportSuccess
        system_export_error = $systemExportError
        system_query_success = $systemQuerySuccess
        system_query_error = $systemQueryError
        code_integrity_event_count = $integrityEvents.Count
        code_integrity_export_success = $integrityExportSuccess
        code_integrity_export_error = $integrityExportError
        code_integrity_query_success = $integrityQuerySuccess
        code_integrity_query_error = $integrityQueryError
        driver_gate_pass = $summaryPass['baseline-driver-gate-summary']
        production_boundary_pass = $summaryPass['production-boundary-summary']
        removal_boundary_pass = $summaryPass['removal-boundary-summary']
        kernel_provenance_pass = $summaryPass['baseline-provenance-summary']
        baseline_identity_pass = $baselineIdentityPass
        summary_errors = @($summaryErrors)
        manifest_current = $manifestCurrent
        service_states = $serviceStates
        services_contained = $servicesContained
        driver_gate_contained = $gateContained
        interactive_staging_removed = $interactiveStagingRemoved
        auto_logon_cleared = $autoLogonCleared
        remaining_oac_tasks = $remainingTasks
        temporary_oac_tasks = $temporaryTasks
        recovery_task_present = $recoveryTaskCount -eq 1
        tasks_contained_except_recovery = $tasksContained
        containment_ready = $containmentReady
        containment_errors = @($containmentErrors)
        fatal_failure_files = $fatalFileNames
        overall_pass = $overallPass
    }
    Publish-FinalResult $status
    Set-Phase 'complete'
    Remove-MainRecoveryTask
    if (Test-BaselineFailureEvidence) {
        Write-RunLog 'Baseline failed; final evidence is durable, shutting down.'
        Start-Sleep -Seconds 3
        Stop-Computer -Force
    }
}

$script:CurrentPhase = 'startup'
try {
    Initialize-CampaignContext
    $phase = Get-TestPhase
    $script:CurrentPhase = $phase
    Write-RunLog "Startup orchestrator entered phase $phase"
    switch ($phase) {
    'post-testsigning' { Install-And-RunBaseline }
    'baseline-running' { Recover-FromBaselineRestart }
    'baseline-complete' { Arm-DriverVerifier }
    'verifier-authorized' { Recover-FromVerifierRestart }
    'verifier-armed' { Run-UnderDriverVerifier }
    'verifier-running' { Recover-FromVerifierRestart }
    'finalize' { Collect-FinalResults }
    'complete' { Remove-MainRecoveryTask }
    default { throw "Unknown or missing test phase: $phase" }
    }
} catch {
    $fatalError = $_
    $failurePhase = $script:CurrentPhase
    if ($failurePhase -eq 'complete' -and
        (Test-Path -LiteralPath (Join-Path $root 'final-status.json')) -and
        (Test-Path -LiteralPath (Join-Path $root 'results.zip'))) {
        Remove-MainRecoveryTask
        return
    }
    Write-RunLog "FATAL in phase ${failurePhase}: $($fatalError.Exception.Message)"
    $fatalError | Out-String | Out-File -LiteralPath `
        (Join-Path $results "$failurePhase-failure.txt") -Encoding utf8
    $fatalResetExit = -1
    try {
        $fatalResetExit = Invoke-ConsoleCapture 'fatal-verifier-reset' `
            'verifier.exe' @('/reset')
        if ($fatalResetExit -notin @(0, 2)) {
            throw "verifier.exe /reset exited with $fatalResetExit"
        }
    } catch {
        $_ | Out-String | Out-File -LiteralPath `
            (Join-Path $results 'verifier-reset-failure.txt') -Encoding utf8
    }
    if ($failurePhase -eq 'finalize' -or $failurePhase -eq 'complete') {
        $failureStatus = [ordered]@{
            schema = 1
            campaign_id = $script:CampaignId
            campaign_start_utc = $script:CampaignStartUtc.ToString('o')
            manifest_sha256 = $script:ManifestHash
            source_commit = $script:SourceCommit
            completed_utc = [DateTime]::UtcNow.ToString('o')
            overall_pass = $false
            fatal_phase = $failurePhase
            fatal_message = $fatalError.Exception.Message
            verifier_reset_exit = $fatalResetExit
        }
        Publish-FinalResult $failureStatus
        Set-Phase 'complete'
        Remove-MainRecoveryTask
        if (Test-BaselineFailureEvidence) {
            Write-RunLog 'Baseline failure publication is durable; shutting down.'
            Start-Sleep -Seconds 3
            Stop-Computer -Force
        }
    } elseif ($failurePhase -eq 'startup') {
        Clear-LabAutoLogon
        Write-RunLog 'Startup validation failed; shutting down without entering a reboot loop.'
        Start-Sleep -Seconds 3
        Stop-Computer -Force
    } else {
        Set-Phase 'finalize'
        Start-Sleep -Seconds 3
        Restart-Computer -Force
    }
}
