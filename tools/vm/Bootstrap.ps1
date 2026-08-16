[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

function Write-BootstrapLog([string]$Message) {
    $line = "[$([DateTime]::UtcNow.ToString('o'))] $Message"
    Add-Content -LiteralPath 'C:\OACTest\results\bootstrap.log' -Value $line -Encoding UTF8
    Write-SerialLine "BOOTSTRAP $Message"
}

function Clear-LabAutoLogon {
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($name in @(
        'AutoAdminLogon', 'DefaultUserName', 'DefaultDomainName',
        'DefaultPassword', 'AutoLogonCount')) {
        Remove-ItemProperty -Path $winlogon -Name $name `
            -ErrorAction SilentlyContinue
    }
}

$installRoot = 'C:\OACTest'
$results = Join-Path $installRoot 'results'
if (Test-Path -LiteralPath $installRoot) {
    throw 'Refusing to reuse C:\OACTest; every VM campaign requires a fresh guest directory.'
}
New-Item -ItemType Directory -Path $installRoot | Out-Null
New-Item -ItemType Directory -Path $results | Out-Null

try {
    Write-BootstrapLog "Copying read-only seed from $PSScriptRoot"
    foreach ($item in Get-ChildItem -LiteralPath $PSScriptRoot -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $installRoot -Recurse -Force
    }

    $installer = Join-Path $installRoot 'Install-OACTestDriver.ps1'
    & $installer -PackageDirectory (Join-Path $installRoot 'package') -ValidateOnly *>&1 |
        Out-File -LiteralPath (Join-Path $results 'package-validation.txt') -Encoding utf8
    $manifest = Get-Content -LiteralPath (Join-Path $installRoot 'package-manifest.json') `
        -Raw | ConvertFrom-Json
    if (-not $manifest.test_files) { throw 'Package manifest has no test-tool hashes.' }
    $sourceCommit = [string]$manifest.source_commit
    if ($sourceCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'Package manifest has no canonical source commit.'
    }
    $installPrefix = $installRoot + [IO.Path]::DirectorySeparatorChar
    foreach ($entry in @($manifest.test_files)) {
        $name = [string]$entry.name
        if ([IO.Path]::GetFileName($name) -ne $name) {
            throw "Test manifest contains a non-leaf file name: $name"
        }
        $path = [IO.Path]::GetFullPath((Join-Path $installRoot $name))
        if (-not $path.StartsWith($installPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-Item -LiteralPath $path).Length -ne [int64]$entry.bytes -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne
                [string]$entry.sha256) {
            throw "Test tool does not match its manifest: $name"
        }
    }
    Write-BootstrapLog 'Signed package, certificate, and test-tool hashes validated.'

    $campaignId = [Guid]::NewGuid().ToString('D')
    $campaignStart = [DateTime]::UtcNow.ToString('o')
    $manifestHash = (Get-FileHash -LiteralPath `
        (Join-Path $installRoot 'package-manifest.json') -Algorithm SHA256).Hash
    [IO.File]::WriteAllText(
        (Join-Path $installRoot 'campaign-id.txt'),
        $campaignId,
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        (Join-Path $installRoot 'campaign-start-utc.txt'),
        $campaignStart,
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        (Join-Path $installRoot 'campaign-manifest-sha256.txt'),
        $manifestHash,
        [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText(
        (Join-Path $installRoot 'campaign-source-commit.txt'),
        $sourceCommit,
        [Text.Encoding]::ASCII)
    Write-BootstrapLog `
        "Campaign $campaignId uses manifest SHA-256 $manifestHash from commit $sourceCommit."

    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' `
        -Name CrashDumpEnabled -PropertyType DWord -Value 3 -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' `
        -Name AutoReboot -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' `
        -Name MinidumpDir -PropertyType ExpandString -Value '%SystemRoot%\Minidump' -Force |
        Out-Null

    & bcdedit.exe /set testsigning on 2>&1 |
        Out-File -LiteralPath (Join-Path $results 'bcdedit-enable-testsigning.txt') -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw 'BCDEdit could not enable test-signing mode.' }
    Write-BootstrapLog 'Enabled Windows test-signing in the guest boot configuration.'

    try { & powercfg.exe /setactive SCHEME_MIN | Out-Null } catch { }

    Set-Content -LiteralPath (Join-Path $installRoot 'phase.txt') `
        -Value 'post-testsigning' -Encoding ascii
    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument `
        '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "C:\OACTest\Run-OACVmTests.ps1"'
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
        -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName 'OAC-VM-Test' -Action $action -Trigger $trigger `
        -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null

    # Keep exactly one post-reboot interactive session so the standard-user
    # launcher boundary can be exercised. The orchestrator removes these
    # values as soon as that session appears.
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    New-ItemProperty -Path $winlogon -Name AutoAdminLogon -PropertyType String `
        -Value '1' -Force | Out-Null
    New-ItemProperty -Path $winlogon -Name DefaultUserName -PropertyType String `
        -Value 'OACAdmin' -Force | Out-Null
    New-ItemProperty -Path $winlogon -Name DefaultDomainName -PropertyType String `
        -Value $env:COMPUTERNAME -Force | Out-Null
    New-ItemProperty -Path $winlogon -Name DefaultPassword -PropertyType String `
        -Value 'OacTest!2026' -Force | Out-Null
    New-ItemProperty -Path $winlogon -Name AutoLogonCount -PropertyType DWord `
        -Value 1 -Force | Out-Null
    Write-BootstrapLog 'Registered SYSTEM startup orchestrator; rebooting into test-signing mode.'
    Start-Sleep -Seconds 3
    Restart-Computer -Force
} catch {
    Clear-LabAutoLogon
    Write-BootstrapLog "FATAL: $($_.Exception.Message)"
    $_ | Out-String | Out-File -LiteralPath (Join-Path $results 'bootstrap-failure.txt') -Encoding utf8
    throw
}
