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

$installRoot = 'C:\OACTest'
$results = Join-Path $installRoot 'results'
New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
New-Item -ItemType Directory -Path $results -Force | Out-Null
[IO.File]::WriteAllText(
    (Join-Path $installRoot 'campaign-start-utc.txt'),
    [DateTime]::UtcNow.ToString('o'),
    [Text.UTF8Encoding]::new($false))

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

    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($name in @('AutoAdminLogon', 'DefaultUserName', 'DefaultPassword', 'AutoLogonCount')) {
        Remove-ItemProperty -Path $winlogon -Name $name -ErrorAction SilentlyContinue
    }
    Write-BootstrapLog 'Registered SYSTEM startup orchestrator; rebooting into test-signing mode.'
    Start-Sleep -Seconds 3
    Restart-Computer -Force
} catch {
    Write-BootstrapLog "FATAL: $($_.Exception.Message)"
    $_ | Out-String | Out-File -LiteralPath (Join-Path $results 'bootstrap-failure.txt') -Encoding utf8
    throw
}
