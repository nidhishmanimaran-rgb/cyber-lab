param(
    [string]$OutputRoot = "release"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$releaseName = "CyberCommandCenter-1.0.0"
$releaseDirectory = Join-Path $projectRoot (Join-Path $OutputRoot $releaseName)

if (Test-Path $releaseDirectory) {
    throw "Release directory already exists: $releaseDirectory. Remove or archive it before packaging again."
}

New-Item -ItemType Directory -Path $releaseDirectory | Out-Null
foreach ($entry in @("backend", "agent", "frontend", "docs", "scripts", "requirements.txt", "pyproject.toml", "README.md", ".env.example")) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $entry) -Destination $releaseDirectory -Recurse
}

$androidSource = Join-Path $projectRoot "android\CyberCommandCenter"
$androidDestination = Join-Path $releaseDirectory "android\CyberCommandCenter"
Copy-Item -LiteralPath $androidSource -Destination $androidDestination -Recurse -Exclude "build", ".gradle", "local.properties"

$apk = Join-Path $projectRoot "android\CyberCommandCenter\app\build\outputs\apk\debug\app-debug.apk"
if (Test-Path $apk) {
    $apkDestination = Join-Path $releaseDirectory "android\apk"
    New-Item -ItemType Directory -Path $apkDestination | Out-Null
    Copy-Item -LiteralPath $apk -Destination $apkDestination
}

$archive = Join-Path (Join-Path $projectRoot $OutputRoot) "$releaseName.zip"
Compress-Archive -Path $releaseDirectory -DestinationPath $archive -CompressionLevel Optimal
Write-Host "Release package created: $archive"
