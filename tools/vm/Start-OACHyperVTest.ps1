[CmdletBinding()]
param(
    [string]$VMName = 'OAC-Win11-24H2-Test',

    [string]$WindowsIso = 'D:\OAC-VM\win11-24h2-noprompt.iso',

    [string]$SeedIso = 'D:\OAC-VM\oac-seed-20260814.iso',

    [string]$VMRoot = 'D:\OAC-VM\hyperv',

    [string]$ResultDirectory = 'D:\OAC-VM\hyperv-results',

    [TimeSpan]$InstallTimeout = '01:00:00',

    [TimeSpan]$TestTimeout = '00:45:00'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-HostLog([string]$Message) {
    $line = "[$([DateTime]::UtcNow.ToString('o'))] $Message"
    Write-Host $line
    Add-Content -LiteralPath $script:HostLog -Value $line -Encoding UTF8
}

function Get-GuestFinalStatus {
    $job = $null
    try {
        $job = Invoke-Command -VMName $VMName -Credential $script:GuestCredential `
            -ScriptBlock {
                if (Test-Path -LiteralPath 'C:\OACTest\final-status.json') {
                    Get-Content -LiteralPath 'C:\OACTest\final-status.json' -Raw
                }
            } -AsJob -ErrorAction Stop
        $completed = Wait-Job -Job $job -Timeout 5
        if ($completed) {
            $candidate = Receive-Job -Job $job -ErrorAction Stop
            if ($candidate) { return ($candidate | Out-String).Trim() }
        }
    } catch { }
    finally {
        if ($null -ne $job) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    return $null
}

function Wait-ForVMOff([TimeSpan]$Timeout, [string]$Reason) {
    $deadline = [DateTime]::UtcNow + $Timeout
    $seenRunning = $false
    $nextProgress = [DateTime]::MinValue
    $nextGuestProbe = [DateTime]::UtcNow.AddMinutes(5)
    while ([DateTime]::UtcNow -lt $deadline) {
        $vm = Get-VM -Name $VMName
        if ($vm.State -eq 'Running') { $seenRunning = $true }
        if ($seenRunning -and $vm.State -eq 'Off') {
            Write-HostLog "VM powered off after $Reason."
            return
        }
        if ([DateTime]::UtcNow -ge $nextProgress) {
            $vhdSize = if (Test-Path -LiteralPath $script:VhdPath) {
                (Get-Item -LiteralPath $script:VhdPath).Length
            } else { 0 }
            Write-HostLog "Waiting for $Reason; state=$($vm.State), VHDX bytes=$vhdSize."
            $nextProgress = [DateTime]::UtcNow.AddSeconds(30)
        }
        if ($vm.State -eq 'Running' -and [DateTime]::UtcNow -ge $nextGuestProbe) {
            $guestFinalStatus = Get-GuestFinalStatus
            if ($guestFinalStatus) {
                Write-HostLog "Guest produced a final result while waiting for $Reason."
                return $guestFinalStatus
            }
            $nextGuestProbe = [DateTime]::UtcNow.AddSeconds(30)
        }
        Start-Sleep -Seconds 10
    }
    throw "Timed out waiting for the VM to power off after $Reason."
}

function Invoke-VMDirect([scriptblock]$ScriptBlock) {
    Invoke-Command -VMName $VMName -Credential $script:GuestCredential `
        -ScriptBlock $ScriptBlock -ErrorAction Stop
}

function Copy-GuestFinalArtifacts([string]$FinalStatus) {
    $FinalStatus | Out-File -LiteralPath `
        (Join-Path $resultPath 'final-status.json') -Encoding utf8
    $session = New-PSSession -VMName $VMName -Credential $script:GuestCredential
    try {
        Copy-Item -FromSession $session -LiteralPath 'C:\OACTest\results.zip' `
            -Destination (Join-Path $resultPath 'oac-vm-results.zip') -Force
    } finally {
        Remove-PSSession $session
    }
    Write-HostLog 'Copied final guest status and result archive through PowerShell Direct.'
}

function Stop-GuestAfterResults {
    try {
        Invoke-VMDirect { & shutdown.exe /s /t 0 /f | Out-Null } | Out-Null
    } catch { }
    $offDeadline = [DateTime]::UtcNow.AddMinutes(5)
    while ((Get-VM -Name $VMName).State -ne 'Off' -and
           [DateTime]::UtcNow -lt $offDeadline) {
        Start-Sleep -Seconds 5
    }
    if ((Get-VM -Name $VMName).State -ne 'Off') {
        throw 'The guest result was copied, but the VM did not shut down within five minutes.'
    }
}

foreach ($path in @($WindowsIso, $SeedIso)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required ISO does not exist: $path"
    }
}
if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
    throw 'The Hyper-V PowerShell module is unavailable. Enable Microsoft-Hyper-V-All and reboot.'
}
try { $null = Get-VMHost } catch {
    throw 'This account cannot manage Hyper-V. Add it to Hyper-V Administrators or run elevated.'
}
if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
    throw "Refusing to replace an existing VM: $VMName"
}

$vmRootPath = [IO.Path]::GetFullPath($VMRoot)
$resultPath = [IO.Path]::GetFullPath($ResultDirectory)
New-Item -ItemType Directory -Path $vmRootPath, $resultPath -Force | Out-Null
$script:HostLog = Join-Path $resultPath 'hyperv-orchestrator.log'
$script:VhdPath = Join-Path $vmRootPath "$VMName.vhdx"
if (Test-Path -LiteralPath $script:VhdPath) {
    throw "Refusing to overwrite an existing VHDX: $script:VhdPath"
}

$guestPassword = ConvertTo-SecureString 'OacTest!2026' -AsPlainText -Force
$script:GuestCredential = [Management.Automation.PSCredential]::new(
    'OAC-HV\OACAdmin', $guestPassword)

Write-HostLog 'Creating isolated Generation 2 Hyper-V VM.'
$vm = New-VM -Name $VMName -Generation 2 -Path $vmRootPath `
    -MemoryStartupBytes 8GB -NewVHDPath $script:VhdPath -NewVHDSizeBytes 80GB
Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -CheckpointType Standard `
    -AutomaticStartAction Nothing -AutomaticStopAction TurnOff
Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false -StartupBytes 8GB
Set-VMProcessor -VMName $VMName -Count 2 -ExposeVirtualizationExtensions $false
Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue |
    Remove-VMNetworkAdapter -Confirm:$false

$windowsDvd = Add-VMDvdDrive -VMName $VMName -Path ([IO.Path]::GetFullPath($WindowsIso)) `
    -Passthru
$seedDvd = Add-VMDvdDrive -VMName $VMName -Path ([IO.Path]::GetFullPath($SeedIso)) `
    -Passthru
$hardDrive = Get-VMHardDiskDrive -VMName $VMName
Set-VMFirmware -VMName $VMName -EnableSecureBoot Off `
    -BootOrder @($hardDrive, $windowsDvd, $seedDvd)

[ordered]@{
    schema = 1
    created_utc = [DateTime]::UtcNow.ToString('o')
    vm_name = $VMName
    generation = 2
    processors = 2
    memory_bytes = 8GB
    network_adapters = @(Get-VMNetworkAdapter -VMName $VMName).Count
    secure_boot = $false
    windows_iso = [IO.Path]::GetFullPath($WindowsIso)
    windows_iso_sha256 = (Get-FileHash -LiteralPath $WindowsIso -Algorithm SHA256).Hash
    seed_iso = [IO.Path]::GetFullPath($SeedIso)
    seed_iso_sha256 = (Get-FileHash -LiteralPath $SeedIso -Algorithm SHA256).Hash
    vhdx = $script:VhdPath
} | ConvertTo-Json -Depth 4 | Out-File -LiteralPath `
    (Join-Path $resultPath 'hyperv-vm-manifest.json') -Encoding utf8

Write-HostLog 'Starting unattended Windows installation.'
Start-VM -Name $VMName | Out-Null
$earlyFinalStatus = Wait-ForVMOff -Timeout $InstallTimeout `
    -Reason 'baseline installation and driver smoke tests'
if ($earlyFinalStatus) {
    Copy-GuestFinalArtifacts $earlyFinalStatus
    Stop-GuestAfterResults
    throw 'The guest finalized a failed result before the baseline checkpoint; see copied VM evidence.'
}

$vhd = Get-VHD -Path $script:VhdPath
if ($vhd.FileSize -lt 5GB) {
    throw "The VM powered off before a plausible Windows installation completed; VHDX file size=$($vhd.FileSize)."
}
Write-HostLog 'Creating clean pre-Verifier checkpoint.'
Checkpoint-VM -Name $VMName -SnapshotName 'OAC-Baseline-Pre-Verifier' | Out-Null

Write-HostLog 'Starting Driver Verifier phase.'
Start-VM -Name $VMName | Out-Null
$deadline = [DateTime]::UtcNow + $TestTimeout
$nextProgress = [DateTime]::MinValue
$finalStatus = $null
while ([DateTime]::UtcNow -lt $deadline) {
    $vm = Get-VM -Name $VMName
    if ($vm.State -eq 'Running') {
        try {
            $candidate = Invoke-VMDirect {
                if (Test-Path -LiteralPath 'C:\OACTest\final-status.json') {
                    Get-Content -LiteralPath 'C:\OACTest\final-status.json' -Raw
                }
            }
            if ($candidate) {
                $finalStatus = ($candidate | Out-String).Trim()
                if ($finalStatus) { break }
            }
        } catch { }
    }
    if ([DateTime]::UtcNow -ge $nextProgress) {
        Write-HostLog "Waiting for final guest result; state=$($vm.State)."
        $nextProgress = [DateTime]::UtcNow.AddSeconds(30)
    }
    Start-Sleep -Seconds 10
}
if (-not $finalStatus) { throw 'Timed out waiting for the guest final-status.json.' }

Copy-GuestFinalArtifacts $finalStatus
Stop-GuestAfterResults

Write-HostLog 'Hyper-V driver test orchestration completed; VM is off and baseline checkpoint is retained.'
$statusObject = $finalStatus | ConvertFrom-Json
if (-not $statusObject.overall_pass) {
    throw 'The Hyper-V driver test completed with overall_pass=false; see copied VM evidence.'
}
$finalStatus
