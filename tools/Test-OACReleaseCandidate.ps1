[CmdletBinding()]
param(
    [string]$BuildDirectory,

    [string]$CandidateDirectory,

    [switch]$DevelopmentBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-CandidateValidation([string]$Path) {
    $command = @{
        BuildDirectory = $BuildDirectory
        OutputDirectory = $Path
        ValidateOnly = $true
        DevelopmentBuild = $DevelopmentBuild
    }
    & (Join-Path $PSScriptRoot 'New-OACReleaseCandidate.ps1') @command
}

function Assert-Rejected([string]$Name, [scriptblock]$Mutation) {
    $casePath = Join-Path $testRoot $Name
    Copy-Item -LiteralPath $candidateRoot -Destination $casePath -Recurse
    & $Mutation $casePath
    $rejected = $false
    try {
        Invoke-CandidateValidation $casePath
    } catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "Release candidate mutation was accepted: $Name"
    }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('oac-release-tests-' + [Guid]::NewGuid().ToString('N'))
try {
    [void](New-Item -ItemType Directory -Path $testRoot)
    if ([string]::IsNullOrWhiteSpace($CandidateDirectory)) {
        $candidateRoot = Join-Path $testRoot 'candidate'
        $create = @{
            BuildDirectory = $BuildDirectory
            OutputDirectory = $candidateRoot
            DevelopmentBuild = $DevelopmentBuild
        }
        & (Join-Path $PSScriptRoot 'New-OACReleaseCandidate.ps1') @create
    } else {
        $candidateRoot = [IO.Path]::GetFullPath($CandidateDirectory)
        if (-not (Test-Path -LiteralPath $candidateRoot -PathType Container)) {
            throw 'The release candidate under test is missing.'
        }
    }

    Invoke-CandidateValidation $candidateRoot

    Assert-Rejected 'payload-tamper' {
        param($path)
        $target = Join-Path $path 'public\OAC-Launcher.exe'
        $stream = [IO.File]::Open(
            $target,
            [IO.FileMode]::Append,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $stream.WriteByte(0x5A)
        } finally {
            $stream.Dispose()
        }
    }

    Assert-Rejected 'metadata-tamper' {
        param($path)
        $target = Join-Path $path 'public\release-manifest.json'
        $text = [IO.File]::ReadAllText($target)
        if (-not $text.Contains('"private_symbols_retained_separately":true')) {
            throw 'The release manifest test fixture is unexpected.'
        }
        [IO.File]::WriteAllText(
            $target,
            $text.Replace(
                '"private_symbols_retained_separately":true',
                '"private_symbols_retained_separately":false'),
            [Text.UTF8Encoding]::new($false))
    }

    Assert-Rejected 'symbol-tamper' {
        param($path)
        $target = Join-Path $path 'symbols\OAC-Service.pdb'
        $stream = [IO.File]::Open(
            $target,
            [IO.FileMode]::Append,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $stream.WriteByte(0x5A)
        } finally {
            $stream.Dispose()
        }
    }

    Assert-Rejected 'unexpected-public-file' {
        param($path)
        [IO.File]::WriteAllText(
            (Join-Path $path 'public\unexpected.txt'),
            'not allowed',
            [Text.UTF8Encoding]::new($false))
    }

    Assert-Rejected 'missing-lab-marker' {
        param($path)
        Remove-Item -LiteralPath (Join-Path $path 'lab\LAB-ONLY.txt')
    }

    Invoke-CandidateValidation $candidateRoot
    Write-Host 'Release candidate hostile validation passed: 5/5 mutations rejected.'
} finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
