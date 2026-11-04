$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null

Compress-Archive `
    -Path (Join-Path $root 'extension\chromium\*') `
    -DestinationPath (Join-Path $dist 'isitsafe-chromium-extension.zip') `
    -Force

Compress-Archive `
    -Path (Join-Path $root 'extension\firefox\*') `
    -DestinationPath (Join-Path $dist 'isitsafe-firefox-extension.zip') `
    -Force

Write-Host "Extension packages written to $dist"
