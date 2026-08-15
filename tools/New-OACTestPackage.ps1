[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [string]$OutputDirectory,

    [SecureString]$PfxPassword,

    [switch]$ExportPrivateKey,

    [switch]$KeepCertificateInCurrentUserStore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-MSBuildPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $installation = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($LASTEXITCODE -eq 0 -and $installation) {
            $candidate = Join-Path $installation 'MSBuild\Current\Bin\amd64\MSBuild.exe'
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }
    }
    throw 'Visual Studio 2022 with the x64 MSBuild host was not found.'
}

function Get-WindowsSdkTool([string]$Name, [string[]]$Architectures) {
    $kitRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
    foreach ($toolRootName in @('bin', 'Tools')) {
        $toolRoot = Join-Path $kitRoot $toolRootName
        if (-not (Test-Path -LiteralPath $toolRoot -PathType Container)) { continue }
        $versions = Get-ChildItem -LiteralPath $toolRoot -Directory |
            Where-Object { $_.Name -match '^10\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($version in $versions) {
            foreach ($architecture in $Architectures) {
                $candidate = Join-Path $version.FullName (Join-Path $architecture $Name)
                if (Test-Path -LiteralPath $candidate) { return $candidate }
            }
        }
    }
    throw "$Name was not found in the installed Windows SDK/WDK."
}

function Invoke-Checked([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath"
    }
}

function Invoke-SelfSignedVerification(
    [string]$SignTool,
    [string]$FilePath,
    [string]$ExpectedThumbprint
) {
    $verification = & $SignTool verify /v /pa $FilePath 2>&1
    $verifyExit = $LASTEXITCODE
    $verificationText = [string]::Join(
        [Environment]::NewLine,
        @($verification | ForEach-Object { $_.ToString() }))
    $authenticode = Get-AuthenticodeSignature -LiteralPath $FilePath
    $actualThumbprint = if ($authenticode.SignerCertificate) {
        $authenticode.SignerCertificate.Thumbprint
    } else {
        ''
    }

    $expectedTrustFailure =
        $verifyExit -eq 1 -and
        $verificationText.Contains('terminated in a root') -and
        $verificationText.Contains(
            'certificate which is not trusted by the trust provider.') -and
        $verificationText.Contains('Number of errors: 1') -and
        $verificationText.Contains("SHA1 hash: $ExpectedThumbprint")
    if (-not $expectedTrustFailure -or
        $actualThumbprint -ne $ExpectedThumbprint) {
        $verification | Write-Output
        throw "Self-signed signature verification failed for $FilePath."
    }
    Write-Host "Verified signature and signer for $(Split-Path -Leaf $FilePath); trust is intentionally deferred to the disposable VM."
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$solution = Join-Path $repoRoot 'OAC.sln'
if (-not (Test-Path -LiteralPath $solution -PathType Leaf)) {
    throw "Repository solution was not found at $solution"
}

if (-not $OutputDirectory) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) "OAC-TestPackage-$stamp"
}
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    if (Get-ChildItem -LiteralPath $output -Force | Select-Object -First 1) {
        throw "Output directory is not empty: $output"
    }
} else {
    New-Item -ItemType Directory -Path $output | Out-Null
}
$package = Join-Path $output 'package'
$certificateDirectory = Join-Path $output 'certificate'
New-Item -ItemType Directory -Path $package | Out-Null
New-Item -ItemType Directory -Path $certificateDirectory | Out-Null

$msbuild = Get-MSBuildPath
$signTool = Get-WindowsSdkTool 'signtool.exe' @('x64', 'x86')
$inf2Cat = Get-WindowsSdkTool 'inf2cat.exe' @('x86', 'x64')
$infVerif = Get-WindowsSdkTool 'infverif.exe' @('x64', 'x86')
Invoke-Checked $msbuild @(
    $solution, '/m', '/t:Rebuild', "/p:Configuration=$Configuration", '/p:Platform=x64',
    '/p:PreferredToolArchitecture=x64', '/p:SkipPackageVerification=true',
    '/p:Inf2CatUseLocalTime=true'
)

$builtPackage = Join-Path $repoRoot "x64\$Configuration\OAC"
$client = Join-Path $repoRoot "x64\$Configuration\OAC-Client.exe"
$protocolTest = Join-Path $repoRoot "x64\$Configuration\OAC-Protocol-Test.exe"
foreach ($required in @(
    (Join-Path $builtPackage 'OAC.sys'),
    (Join-Path $builtPackage 'OAC.inf'),
    $client,
    $protocolTest
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Expected build artifact is missing: $required"
    }
}
Copy-Item -LiteralPath (Join-Path $builtPackage 'OAC.sys') -Destination $package
Copy-Item -LiteralPath (Join-Path $builtPackage 'OAC.inf') -Destination $package
Invoke-Checked $infVerif @('/w', '/v', (Join-Path $package 'OAC.inf'))

if ($PfxPassword -and -not $ExportPrivateKey) {
    throw 'PfxPassword was supplied without -ExportPrivateKey.'
}
if ($ExportPrivateKey -and -not $PfxPassword) {
    $PfxPassword = Read-Host 'Password for the exported local-test PFX' -AsSecureString
}

$certificate = $null
try {
    $keyExportPolicy = if ($ExportPrivateKey) { 'Exportable' } else { 'NonExportable' }
    Write-Host 'Generating an ephemeral RSA-3072 local-test certificate.'
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=OAC LOCAL TEST ONLY - NOT FOR PRODUCTION' `
        -FriendlyName 'OAC local test signing certificate (disposable VM only)' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy $keyExportPolicy `
        -NotAfter (Get-Date).AddDays(30) `
        -TextExtension @('2.5.29.19={text}CA=FALSE', '2.5.29.37={text}1.3.6.1.5.5.7.3.3')

    $cerPath = Join-Path $certificateDirectory 'OAC-Local-Test.cer'
    [IO.File]::WriteAllBytes(
        $cerPath,
        $certificate.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    Write-Host 'Exported the public test certificate.'
    if ($ExportPrivateKey) {
        $pfxPath = Join-Path $certificateDirectory 'OAC-Local-Test.pfx'
        Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $PfxPassword |
            Out-Null
    }
    $driver = Join-Path $package 'OAC.sys'
    Invoke-Checked $signTool @(
        'sign', '/v', '/fd', 'SHA256', '/sha1', $certificate.Thumbprint,
        '/s', 'My', $driver
    )

    Invoke-Checked $inf2Cat @("/driver:$package", '/os:10_X64', '/uselocaltime')
    $catalog = Join-Path $package 'OAC.cat'
    if (-not (Test-Path -LiteralPath $catalog -PathType Leaf)) {
        throw "Inf2Cat did not create $catalog"
    }
    Invoke-Checked $signTool @(
        'sign', '/v', '/fd', 'SHA256', '/sha1', $certificate.Thumbprint,
        '/s', 'My', $catalog
    )
    Invoke-SelfSignedVerification `
        $signTool $driver $certificate.Thumbprint
    Invoke-SelfSignedVerification `
        $signTool $catalog $certificate.Thumbprint

    Copy-Item -LiteralPath $client -Destination $package
    $protocolTestOutput = Join-Path $output 'OAC-Protocol-Test.exe'
    Copy-Item -LiteralPath $protocolTest -Destination $protocolTestOutput
    $files = Get-ChildItem -LiteralPath $package -File | Sort-Object Name | ForEach-Object {
        [ordered]@{
            name = $_.Name
            bytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
    }
    $testFiles = @([ordered]@{
        name = 'OAC-Protocol-Test.exe'
        bytes = (Get-Item -LiteralPath $protocolTestOutput).Length
        sha256 = (Get-FileHash -LiteralPath $protocolTestOutput -Algorithm SHA256).Hash
    })
    $manifest = [ordered]@{
        schema = 1
        purpose = 'OAC disposable-VM test package; never production'
        created_utc = [DateTime]::UtcNow.ToString('o')
        configuration = $Configuration
        protocol_version = '0x00040000'
        certificate_subject = $certificate.Subject
        certificate_thumbprint = $certificate.Thumbprint
        certificate_not_after_utc = $certificate.NotAfter.ToUniversalTime().ToString('o')
        files = @($files)
        test_files = $testFiles
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText(
        (Join-Path $output 'package-manifest.json'),
        $manifestJson,
        [Text.UTF8Encoding]::new($false))

    Write-Host "Test package created: $output"
    Write-Host 'The certificate is self-signed, expires in 30 days, and is only for a disposable VM.'
    if (-not $ExportPrivateKey) {
        Write-Host 'No private-key file was exported.'
    }
} finally {
    if ($certificate -and -not $KeepCertificateInCurrentUserStore) {
        $myStore = [Security.Cryptography.X509Certificates.X509Store]::new(
            'My',
            [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        try {
            $myStore.Open(
                [Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $matches = $myStore.Certificates.Find(
                [Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $certificate.Thumbprint,
                $false)
            foreach ($match in $matches) {
                $myStore.Remove($match)
            }
        } finally {
            $myStore.Close()
        }
    }
}
