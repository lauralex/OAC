[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location $root
try {
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        throw 'Git is required for repository validation.'
    }
    if (-not (Get-Command python.exe -ErrorAction SilentlyContinue)) {
        throw 'Python is required for Python and YAML validation.'
    }

    $files = @(& git.exe ls-files --cached --others --exclude-standard |
        Sort-Object -Unique)
    if ($LASTEXITCODE -ne 0 -or $files.Count -eq 0) {
        throw 'Git could not enumerate the repository files.'
    }

    $powerShellFiles = @($files | Where-Object { $_.EndsWith('.ps1') })
    foreach ($file in $powerShellFiles) {
        $tokens = $null
        $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $root $file),
            [ref]$tokens,
            [ref]$errors)
        if ($errors.Count -ne 0) {
            throw "PowerShell parse failed for $file`: $($errors.Message -join '; ')"
        }
    }

    & (Join-Path $root 'tools\Test-OACReleaseProfile.ps1')

    $xmlFiles = @($files | Where-Object {
            $_ -match '\.(xml|vcxproj|filters|props|targets)$'
        })
    foreach ($file in $xmlFiles) {
        try {
            [void][xml](Get-Content -LiteralPath (Join-Path $root $file) -Raw)
        } catch {
            throw "XML parse failed for $file`: $($_.Exception.Message)"
        }
    }

    $jsonFiles = @($files | Where-Object { $_.EndsWith('.json') })
    foreach ($file in $jsonFiles) {
        try {
            [void](Get-Content -LiteralPath (Join-Path $root $file) -Raw |
                ConvertFrom-Json)
        } catch {
            throw "JSON parse failed for $file`: $($_.Exception.Message)"
        }
    }

    $pythonFiles = @($files | Where-Object { $_.EndsWith('.py') })
    foreach ($file in $pythonFiles) {
        & python.exe -c `
            'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding=sys.argv[2]))' `
            (Join-Path $root $file) 'utf-8-sig'
        if ($LASTEXITCODE -ne 0) { throw "Python parse failed for $file" }
    }

    $yamlFiles = @($files | Where-Object { $_ -match '\.ya?ml$' })
    foreach ($file in $yamlFiles) {
        & python.exe -c `
            'import pathlib,sys,yaml; yaml.safe_load(pathlib.Path(sys.argv[1]).read_text(encoding=sys.argv[2]))' `
            (Join-Path $root $file) 'utf-8-sig'
        if ($LASTEXITCODE -ne 0) { throw "YAML parse failed for $file" }
    }

    $brokenLinks = [Collections.Generic.List[string]]::new()
    foreach ($file in @($files | Where-Object { $_.EndsWith('.md') })) {
        $fullPath = Join-Path $root $file
        $text = Get-Content -LiteralPath $fullPath -Raw
        foreach ($match in [regex]::Matches(
                $text,
                '\[[^\]]*\]\((?<target>[^)]+)\)')) {
            $target = $match.Groups['target'].Value.Trim()
            if ($target.StartsWith('<') -and $target.EndsWith('>')) {
                $target = $target.Substring(1, $target.Length - 2)
            }
            if ([string]::IsNullOrWhiteSpace($target) -or
                $target -match '^(https?://|mailto:|#)') {
                continue
            }
            $target = [Uri]::UnescapeDataString(($target -split '#', 2)[0])
            $resolved = Join-Path (Split-Path -Parent $fullPath) $target
            if (-not (Test-Path -LiteralPath $resolved)) {
                $brokenLinks.Add("$file -> $target")
            }
        }
    }
    if ($brokenLinks.Count -ne 0) {
        throw "Broken local Markdown links:`n$($brokenLinks -join "`n")"
    }

    $inf = Get-Content -LiteralPath (Join-Path $root 'OAC\OAC.inf')
    $startType = $inf | Select-String '^StartType\s*=\s*3\s*$'
    if ($null -eq $startType) { throw 'OAC.inf must remain demand-start (StartType=3).' }
    $serviceLines = @($inf | Select-String '^\s*AddService\s*=')
    $infText = $inf -join "`n"
    if ($serviceLines.Count -ne 1 -or
        $infText -notmatch
            '(?m)^\[DefaultInstall\.NTamd64\.Services\]\nAddService\s*=\s*OAC\s*,\s*,\s*OAC\.Service\s*$') {
        throw 'OAC.inf must install OAC as a device-less primitive service.'
    }

    foreach ($producer in @('OAC\main.c', 'OAC\protection.c', 'OAC\session.c')) {
        $producerText = Get-Content -LiteralPath (Join-Path $root $producer) -Raw
        if ($producerText -match 'OAC_V5_EVENT_POLICY_VIOLATION' -or
            $producerText -match 'OAC_V5_POLICY_(INFO|LOW|MEDIUM|HIGH|CRITICAL)') {
            throw "$producer must emit typed observations without policy labels."
        }
    }

    $blocked = @($files | Where-Object {
            $_ -match '(?i)\.(pdb|exe|sys|cat|cer|pfx|p12|pem|key|id0|id1|id2|idb|i64|nam|til|iso|vhdx?|avhdx|dmp)$'
        })
    if ($blocked.Count -ne 0) {
        throw "Generated or sensitive artifacts are tracked: $($blocked -join ', ')"
    }

    $textFiles = @($files | Where-Object {
            $_ -match '(?i)\.(asm|c|cpp|h|hpp|inc|inf|md|ps1|py|sln|txt|xml|ya?ml|json|vcxproj|filters|props|targets)$'
        })
    $trailingWhitespace = [Collections.Generic.List[string]]::new()
    foreach ($file in $textFiles) {
        $lineNumber = 0
        foreach ($line in Get-Content -LiteralPath (Join-Path $root $file)) {
            ++$lineNumber
            if ($line -match '[ \t]+$') {
                $trailingWhitespace.Add("$file`:$lineNumber")
            }
        }
    }
    if ($trailingWhitespace.Count -ne 0) {
        throw "Trailing whitespace found:`n$($trailingWhitespace -join "`n")"
    }

    & git.exe diff --check
    if ($LASTEXITCODE -ne 0) { throw 'git diff --check failed.' }

    Write-Host "Repository validation passed: $($files.Count) files, " `
        "$($powerShellFiles.Count) PowerShell, $($xmlFiles.Count) XML, " `
        "$($yamlFiles.Count) YAML, $($pythonFiles.Count) Python."
} finally {
    Pop-Location
}
