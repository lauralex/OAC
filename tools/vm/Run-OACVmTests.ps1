[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = 'C:\OACTest'
$results = Join-Path $root 'results'
$phasePath = Join-Path $root 'phase.txt'
$phaseBackupPath = Join-Path $root 'phase.previous.txt'
$runLog = Join-Path $results 'orchestrator.log'
$validPhases = @(
    'post-testsigning', 'baseline-running', 'baseline-complete',
    'verifier-armed', 'verifier-running', 'finalize', 'complete')
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
        'baseline-complete' { return 'verifier-armed' }
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
    [string[]]$Arguments = @()) {
    $stdout = Join-Path $results "$Name.stdout.txt"
    $stderr = Join-Path $results "$Name.stderr.txt"
    Write-RunLog "Starting $Name"
    $startParameters = @{
        FilePath = $FilePath
        WindowStyle = 'Hidden'
        Wait = $true
        PassThru = $true
        RedirectStandardOutput = $stdout
        RedirectStandardError = $stderr
    }
    if ($Arguments.Count -ne 0) { $startParameters.ArgumentList = $Arguments }
    $process = Start-Process @startParameters
    Write-DurableAsciiFile (Join-Path $results "$Name.exitcode.txt") `
        ([string]$process.ExitCode)
    Write-RunLog "$Name exited with $($process.ExitCode)"
    return [int]$process.ExitCode
}

function Invoke-ConsoleCapture(
    [string]$Name,
    [string]$FilePath,
    [string[]]$Arguments = @()) {
    Write-RunLog "Starting $Name"
    $text = & $FilePath @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $text | Out-File -LiteralPath (Join-Path $results "$Name.txt") -Encoding utf8
    Write-DurableAsciiFile (Join-Path $results "$Name.exitcode.txt") `
        ([string]$exitCode)
    Write-RunLog "$Name exited with $exitCode"
    return [int]$exitCode
}

function Publish-FinalResult([object]$Status) {
    $statusPath = Join-Path $root 'final-status.json'
    $resultStatusPath = Join-Path $results 'final-status.json'
    $archivePath = Join-Path $root 'results.zip'
    Write-RunLog 'Serializing final status with the direct UTF-8 writer.'
    $json = ConvertTo-Json -InputObject $Status -Depth 4
    [IO.File]::WriteAllText(
        $statusPath,
        $json,
        [Text.UTF8Encoding]::new($false))
    [IO.File]::Copy($statusPath, $resultStatusPath, $true)

    if ([IO.File]::Exists($archivePath)) {
        [IO.File]::SetAttributes($archivePath, [IO.FileAttributes]::Normal)
        [IO.File]::Delete($archivePath)
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Write-RunLog 'Creating the result archive with System.IO.Compression.ZipFile.'
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $results,
        $archivePath,
        [IO.Compression.CompressionLevel]::Optimal,
        $false)
}

function Start-ScanTarget {
    $command = 'ping.exe -t 127.0.0.1 >nul'
    $process = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
        -ArgumentList @('/d', '/c', $command) -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 2
    if ($process.HasExited) { throw 'The disposable scan target exited prematurely.' }
    Write-RunLog "Started scan target PID $($process.Id)"
    return $process
}

function Stop-ScanTarget([Diagnostics.Process]$Process) {
    if ($null -eq $Process -or $Process.HasExited) { return }
    & taskkill.exe /PID $Process.Id /T /F 2>&1 |
        Out-File -LiteralPath (Join-Path $results "target-$($Process.Id)-stop.txt") -Encoding utf8
}

function Save-PlatformState([string]$Prefix) {
    Get-CimInstance Win32_OperatingSystem |
        Format-List * | Out-File -LiteralPath (Join-Path $results "$Prefix-os.txt") -Encoding utf8
    Get-CimInstance Win32_ComputerSystem |
        Format-List * | Out-File -LiteralPath (Join-Path $results "$Prefix-system.txt") -Encoding utf8
    Get-CimInstance Win32_Processor |
        Format-List * | Out-File -LiteralPath (Join-Path $results "$Prefix-cpu.txt") -Encoding utf8
    & bcdedit.exe /enum all 2>&1 |
        Out-File -LiteralPath (Join-Path $results "$Prefix-bcd.txt") -Encoding utf8
    try {
        Confirm-SecureBootUEFI |
            Out-File -LiteralPath (Join-Path $results "$Prefix-secureboot.txt") -Encoding utf8
    } catch {
        $_ | Out-String | Out-File -LiteralPath `
            (Join-Path $results "$Prefix-secureboot.txt") -Encoding utf8
    }
}

function Test-DriverGate {
    $serviceName = 'OACGateProbe'
    $probePath = Join-Path $root 'OAC-Gate-Probe.sys'
    $reportDirectory = Join-Path $results 'baseline-driver-gate-report'
    $reportPath = Join-Path $reportDirectory 'oac-report.txt'
    $summaryPath = Join-Path $results 'baseline-driver-gate-summary.json'
    Copy-Item -LiteralPath (Join-Path $root 'package\OAC.sys') `
        -Destination $probePath -Force

    $createExit = Invoke-ConsoleCapture 'baseline-driver-gate-create' 'sc.exe' @(
        'create', $serviceName, 'type=', 'kernel', 'start=', 'demand',
        'binPath=', $probePath)
    if ($createExit -ne 0) {
        throw "Could not create the transient gate probe; exit code $createExit."
    }

    $startExit = -1
    $detectionExit = -1
    $gateFinding = $false
    $callbackFinding = $false
    try {
        # The renamed, signed copy maps far enough to notify the already-running
        # OAC instance, then its own DriverEntry fails on OAC's existing device.
        $startExit = Invoke-ConsoleCapture 'baseline-driver-gate-trigger' 'sc.exe' @(
            'start', $serviceName)
        if ($startExit -eq 0) {
            throw 'The transient gate probe unexpectedly completed DriverEntry.'
        }

        $detectionExit = Invoke-NativeCapture 'baseline-driver-gate-detection' `
            (Join-Path $root 'package\OAC-Client.exe') @(
                '--preflight', '--mode', 'test', '--fail-on', 'medium',
                '--output', $reportDirectory)
        if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
            $report = Get-Content -LiteralPath $reportPath -Raw
            $gateFinding = $report -match `
                '(?im)\[critical\]\[driver/load-gate\].*observed=[1-9][0-9]*'
            $callbackFinding = $report -match `
                '(?im)\[critical\]\[kernel/driver\].*Driver-load gate tripped.*OAC-Gate-Probe\.sys'
        }

        $passed = $detectionExit -eq 1 -and $gateFinding -and $callbackFinding
        $summary = [ordered]@{
            timestamp_utc = [DateTime]::UtcNow.ToString('o')
            trigger_exit = $startExit
            detection_exit = $detectionExit
            persistent_gate_finding = $gateFinding
            callback_finding = $callbackFinding
            pass = $passed
        }
        $summary | ConvertTo-Json | Out-File -LiteralPath $summaryPath -Encoding utf8
        if (-not $passed) {
            throw "Post-start driver gate probe failed; see $summaryPath."
        }
        Write-RunLog 'Transient renamed-driver load was retained by the fail-closed gate.'
        return [pscustomobject]$summary
    } finally {
        Invoke-ConsoleCapture 'baseline-driver-gate-stop' 'sc.exe' @(
            'stop', $serviceName) | Out-Null
        Invoke-ConsoleCapture 'baseline-driver-gate-delete' 'sc.exe' @(
            'delete', $serviceName) | Out-Null
        Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
    }
}

function Install-And-RunBaseline {
    Set-Phase 'baseline-running'
    Write-RunLog 'Beginning signed-load and baseline protocol tests.'
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
        '-ConfirmDisposableVm')
    if ($installExit -ne 0) { throw "Driver installation failed with exit code $installExit." }

    Get-AuthenticodeSignature -FilePath (Join-Path $root 'package\OAC.sys') |
        Format-List * | Out-File -LiteralPath (Join-Path $results 'baseline-driver-signature.txt') -Encoding utf8
    Invoke-ConsoleCapture 'baseline-sc-query' 'sc.exe' @('query', 'OAC') | Out-Null
    $protocolExit = Invoke-NativeCapture 'baseline-protocol' `
        (Join-Path $root 'OAC-Protocol-Test.exe')
    $preflightExit = Invoke-NativeCapture 'baseline-preflight' `
        (Join-Path $root 'package\OAC-Client.exe') @(
            '--preflight', '--mode', 'test', '--fail-on', 'medium',
            '--output', (Join-Path $results 'baseline-preflight-report'))
    $launchExit = Invoke-NativeCapture 'baseline-launch' `
        (Join-Path $root 'package\OAC-Client.exe') @(
            '--launch', "$env:SystemRoot\System32\cmd.exe",
            '--launch-args', '"/d /c \"ping.exe -n 6 127.0.0.1 >nul\""',
            '--mode', 'test', '--fail-on', 'medium', '--monitor-interval-ms', '500',
            '--output', (Join-Path $results 'baseline-launch-report'))

    $target = Start-ScanTarget
    $gateSummary = $null
    try {
        $clientExit = Invoke-NativeCapture 'baseline-client' `
            (Join-Path $root 'package\OAC-Client.exe') @(
                '--pid', ([string]$target.Id), '--mode', 'test', '--fail-on', 'medium',
                '--output', (Join-Path $results 'baseline-client-report'))
        $gateSummary = Test-DriverGate
    } finally {
        Invoke-ConsoleCapture 'baseline-sc-stop' 'sc.exe' @('stop', 'OAC') | Out-Null
        Stop-ScanTarget $target
    }

    [ordered]@{
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        install_exit = $installExit
        protocol_exit = $protocolExit
        preflight_exit = $preflightExit
        launch_exit = $launchExit
        client_exit = $clientExit
        driver_gate_exit = $gateSummary.detection_exit
        driver_gate_pass = $gateSummary.pass
    } | ConvertTo-Json | Out-File -LiteralPath `
        (Join-Path $results 'baseline-summary.json') -Encoding utf8

    Set-Phase 'baseline-complete'
    Write-RunLog 'Baseline complete. Shutting down for a host-side clean snapshot.'
    Start-Sleep -Seconds 3
    Stop-Computer -Force
}

function Arm-DriverVerifier {
    Write-RunLog 'Arming standard Driver Verifier checks for OAC.sys.'
    Invoke-ConsoleCapture 'verifier-pre-reset' 'verifier.exe' @('/reset') | Out-Null
    $armExit = Invoke-ConsoleCapture 'verifier-arm' 'verifier.exe' `
        @('/standard', '/driver', 'OAC.sys')
    Invoke-ConsoleCapture 'verifier-armed-settings' 'verifier.exe' @('/querysettings') | Out-Null
    $armedSettings = Get-Content -LiteralPath `
        (Join-Path $results 'verifier-armed-settings.txt') -Raw
    if ($armExit -notin @(0, 2) -or $armedSettings -notmatch '(?im)^\s*OAC\.sys\s*$') {
        throw "Driver Verifier could not be armed for OAC.sys; exit code $armExit."
    }
    Set-Phase 'verifier-armed'
    Write-RunLog 'Driver Verifier armed. Rebooting before exercising the driver.'
    Start-Sleep -Seconds 3
    Restart-Computer -Force
}

function Run-UnderDriverVerifier {
    Set-Phase 'verifier-running'
    Write-RunLog 'Booted with Driver Verifier armed; beginning stress tests.'
    Save-PlatformState 'verifier'
    Invoke-ConsoleCapture 'verifier-active-settings' 'verifier.exe' @('/querysettings') | Out-Null
    $startExit = Invoke-ConsoleCapture 'verifier-sc-start' 'sc.exe' @('start', 'OAC')
    if ($startExit -ne 0 -and $startExit -ne 1056) {
        throw "The verified driver failed to start; sc.exe exit code $startExit."
    }

    for ($iteration = 1; $iteration -le 3; ++$iteration) {
        Invoke-NativeCapture "verifier-protocol-$iteration" `
            (Join-Path $root 'OAC-Protocol-Test.exe') | Out-Null
    }

    Invoke-NativeCapture 'verifier-preflight' `
        (Join-Path $root 'package\OAC-Client.exe') @(
            '--preflight', '--mode', 'test', '--fail-on', 'medium',
            '--output', (Join-Path $results 'verifier-preflight-report')) | Out-Null
    Invoke-NativeCapture 'verifier-launch' `
        (Join-Path $root 'package\OAC-Client.exe') @(
            '--launch', "$env:SystemRoot\System32\cmd.exe",
            '--launch-args', '"/d /c \"ping.exe -n 6 127.0.0.1 >nul\""',
            '--mode', 'test', '--fail-on', 'medium', '--monitor-interval-ms', '500',
            '--output', (Join-Path $results 'verifier-launch-report')) | Out-Null

    $target = Start-ScanTarget
    try {
        for ($iteration = 1; $iteration -le 2; ++$iteration) {
            Invoke-NativeCapture "verifier-client-$iteration" `
                (Join-Path $root 'package\OAC-Client.exe') @(
                    '--pid', ([string]$target.Id), '--mode', 'test', '--fail-on', 'medium',
                    '--output', (Join-Path $results "verifier-client-$iteration-report")) |
                Out-Null
        }
    } finally {
        Invoke-ConsoleCapture 'verifier-sc-stop' 'sc.exe' @('stop', 'OAC') | Out-Null
        Stop-ScanTarget $target
    }

    Invoke-ConsoleCapture 'verifier-query-after-stress' 'verifier.exe' @('/query') | Out-Null
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
    Invoke-ConsoleCapture 'verifier-emergency-reset' 'verifier.exe' @('/reset') | Out-Null
    Set-Phase 'finalize'
    Write-RunLog 'Verifier was reset after the unexpected reboot; rebooting to finalize safely.'
    Start-Sleep -Seconds 3
    Restart-Computer -Force
}

function Recover-FromBaselineRestart {
    Write-RunLog 'Detected an unexpected reboot during baseline driver testing.'
    Set-Content -LiteralPath (Join-Path $results 'baseline-unexpected-reboot.txt') `
        -Value ([DateTime]::UtcNow.ToString('o')) -Encoding ascii
    try { & verifier.exe /reset | Out-Null } catch { }
    Set-Phase 'finalize'
    Write-RunLog 'Rebooting to collect crash evidence without loading the demand-start driver.'
    Start-Sleep -Seconds 3
    Restart-Computer -Force
}

function Collect-FinalResults {
    Write-RunLog 'Collecting final VM, verifier, crash, signature, and event-log evidence.'
    Save-PlatformState 'final'
    Invoke-ConsoleCapture 'final-verifier-settings' 'verifier.exe' @('/querysettings') | Out-Null
    Invoke-ConsoleCapture 'final-sc-query' 'sc.exe' @('query', 'OAC') | Out-Null
    Invoke-ConsoleCapture 'final-driverquery' 'driverquery.exe' @('/v', '/fo', 'csv') | Out-Null

    try { & wevtutil.exe epl System (Join-Path $results 'System.evtx') /ow:true } catch { }
    try {
        & wevtutil.exe epl Microsoft-Windows-CodeIntegrity/Operational `
            (Join-Path $results 'CodeIntegrity-Operational.evtx') /ow:true
    } catch { }

    $campaignStartPath = Join-Path $root 'campaign-start-utc.txt'
    $since = (Get-Date).AddHours(-6)
    if (Test-Path -LiteralPath $campaignStartPath) {
        $parsedStart = [DateTime]::MinValue
        if ([DateTime]::TryParse(
                (Get-Content -LiteralPath $campaignStartPath -Raw).Trim(),
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$parsedStart)) {
            $since = $parsedStart
        }
    }
    $sinceUtc = $since.ToUniversalTime()
    $crashEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'; StartTime = $since.ToLocalTime(); Id = 41, 1001, 6008
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.TimeCreated.ToUniversalTime() -ge $sinceUtc
        })
    $crashEvents | Format-List TimeCreated, Id, ProviderName, LevelDisplayName, Message |
        Out-File -LiteralPath (Join-Path $results 'crash-events.txt') -Encoding utf8
    $integrityEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-CodeIntegrity/Operational';
            StartTime = $since.ToLocalTime()
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.TimeCreated.ToUniversalTime() -ge $sinceUtc
        })
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

    $exitFiles = @(Get-ChildItem -LiteralPath $results -Filter '*.exitcode.txt' -File)
    $testExitFiles = @($exitFiles | Where-Object {
            $_.BaseName -match '^(baseline-install|baseline-protocol|baseline-preflight|baseline-launch|baseline-client|verifier-protocol-\d+|verifier-preflight|verifier-launch|verifier-client-\d+)\.exitcode$'
        })
    $nonzeroTests = @($testExitFiles | Where-Object {
            [int](Get-Content -LiteralPath $_.FullName -Raw) -ne 0
        })
    $verifierText = Get-Content -LiteralPath (Join-Path $results 'final-verifier-settings.txt') -Raw
    $verifierStillActive = $verifierText -match '(?im)OAC\.sys'
    $bugcheckEvents = @($crashEvents | Where-Object { $_.Id -eq 1001 })
    $unexpectedRestart = Test-Path -LiteralPath (Join-Path $results 'verifier-unexpected-reboot.txt')
    $baselineUnexpectedRestart = Test-Path -LiteralPath `
        (Join-Path $results 'baseline-unexpected-reboot.txt')
    $fatalFiles = @(Get-ChildItem -LiteralPath $results -Filter '*-failure.txt' -File)
    $gateSummaryPath = Join-Path $results 'baseline-driver-gate-summary.json'
    $gatePass = $false
    if (Test-Path -LiteralPath $gateSummaryPath -PathType Leaf) {
        try {
            $gatePass = [bool]((Get-Content -LiteralPath $gateSummaryPath -Raw |
                    ConvertFrom-Json).pass)
        } catch { }
    }
    $protocolTestCount = @($testExitFiles | Where-Object {
            $_.Name -match 'protocol'
        }).Count
    $clientScanCount = @($testExitFiles | Where-Object {
            $_.Name -match 'client|preflight|launch'
        }).Count
    $nonzeroTestNames = @($nonzeroTests | ForEach-Object { $_.Name })
    $fatalFileNames = @($fatalFiles | ForEach-Object { $_.Name })
    $overallPass = $nonzeroTests.Count -eq 0 -and $dumps.Count -eq 0 -and `
        $bugcheckEvents.Count -eq 0 -and -not $verifierStillActive -and `
        -not $unexpectedRestart -and -not $baselineUnexpectedRestart -and `
        $fatalFiles.Count -eq 0 -and $gatePass

    $status = [ordered]@{
        schema = 1
        completed_utc = [DateTime]::UtcNow.ToString('o')
        computer_name = $env:COMPUTERNAME
        windows = (Get-CimInstance Win32_OperatingSystem).Caption
        windows_version = (Get-CimInstance Win32_OperatingSystem).Version
        windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        protocol_test_count = $protocolTestCount
        client_scan_count = $clientScanCount
        nonzero_test_exits = $nonzeroTestNames
        baseline_unexpected_restart = $baselineUnexpectedRestart
        verifier_unexpected_restart = $unexpectedRestart
        verifier_still_active = $verifierStillActive
        minidump_count = $dumps.Count
        bugcheck_event_count = $bugcheckEvents.Count
        code_integrity_event_count = $integrityEvents.Count
        driver_gate_pass = $gatePass
        fatal_failure_files = $fatalFileNames
        overall_pass = $overallPass
    }
    Publish-FinalResult $status
    Set-Phase 'complete'
    Write-RunLog "Final results ready; overall_pass=$overallPass. Waiting for PowerShell Direct retrieval."
}

$phase = Get-TestPhase
$script:CurrentPhase = $phase
Write-RunLog "Startup orchestrator entered phase $phase"

try {
    switch ($phase) {
    'post-testsigning' { Install-And-RunBaseline }
    'baseline-running' { Recover-FromBaselineRestart }
    'baseline-complete' { Arm-DriverVerifier }
    'verifier-armed' { Run-UnderDriverVerifier }
    'verifier-running' { Recover-FromVerifierRestart }
    'finalize' { Collect-FinalResults }
    'complete' { Write-RunLog 'Final results are already complete.' }
    default { throw "Unknown or missing test phase: $phase" }
    }
} catch {
    $failurePhase = $script:CurrentPhase
    Write-RunLog "FATAL in phase ${failurePhase}: $($_.Exception.Message)"
    $_ | Out-String | Out-File -LiteralPath `
        (Join-Path $results "$failurePhase-failure.txt") -Encoding utf8
    try { & verifier.exe /reset | Out-Null } catch { }
    if ($failurePhase -eq 'finalize' -or $failurePhase -eq 'complete') {
        $failureStatus = [ordered]@{
            schema = 1
            completed_utc = [DateTime]::UtcNow.ToString('o')
            overall_pass = $false
            fatal_phase = $failurePhase
            fatal_message = $_.Exception.Message
        }
        Publish-FinalResult $failureStatus
        Write-RunLog 'Fatal finalization evidence is ready for PowerShell Direct retrieval.'
    } else {
        Set-Phase 'finalize'
        Start-Sleep -Seconds 3
        Restart-Computer -Force
    }
}
