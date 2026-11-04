$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$manifest = Get-Content (Join-Path $root 'Cargo.toml') -Raw
$versionMatch = [regex]::Match($manifest, '(?m)^version\s*=\s*"([^"]+)"\s*$')
if (-not $versionMatch.Success) {
    throw 'Could not read the package version from Cargo.toml.'
}
$version = $versionMatch.Groups[1].Value

$compilerCandidates = @(
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
)
$compiler = $compilerCandidates |
    Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
    Select-Object -First 1
if (-not $compiler) {
    throw 'Inno Setup 6 is required. Install it, then rerun this script.'
}

Push-Location $root
try {
    cargo build --release --locked
    if ($LASTEXITCODE -ne 0) {
        throw 'cargo build failed.'
    }

    $dist = Join-Path $root 'dist'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    & $compiler `
        "/DAppVersion=$version" `
        "/DSourceDir=$root\target\release" `
        (Join-Path $root 'installer\IsItSafe.iss')
    if ($LASTEXITCODE -ne 0) {
        throw 'Inno Setup compilation failed.'
    }

    $installer = Join-Path $dist "IsItSafe-$version-windows-x64-setup.exe"
    if (-not (Test-Path -LiteralPath $installer)) {
        throw "Expected installer was not created: $installer"
    }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash.ToLowerInvariant()
    $checksumFile = "$installer.sha256"
    Set-Content -LiteralPath $checksumFile -Value "$hash  $(Split-Path -Leaf $installer)" -Encoding ascii

    Write-Host "Installer: $installer"
    Write-Host "SHA-256:  $hash"
}
finally {
    Pop-Location
}
