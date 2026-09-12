$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if (Test-Path ".venv\Scripts\python.exe") {
    $python = ".\.venv\Scripts\python.exe"
} else {
    $python = "python"
}

function Get-CccEnvValue {
    param(
        [string]$Name,
        [string]$Default
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ($value) {
        return $value
    }

    if (Test-Path ".env") {
        $line = Get-Content ".env" | Where-Object { $_ -match "^$Name\s*=" } | Select-Object -First 1
        if ($line) {
            return (($line -split "=", 2)[1]).Trim().Trim('"').Trim("'")
        }
    }

    return $Default
}

if (-not (Test-Path ".env")) {
    throw "Missing .env. Run .\scripts\setup.ps1 before starting the release backend."
}

$hostName = Get-CccEnvValue -Name "CCC_API_HOST" -Default "127.0.0.1"
$port = Get-CccEnvValue -Name "CCC_API_PORT" -Default "8001"
$authEnabled = Get-CccEnvValue -Name "CCC_AUTH_ENABLED" -Default "true"
$apiToken = Get-CccEnvValue -Name "CCC_API_TOKEN" -Default ""

if ($authEnabled.ToLowerInvariant() -in @("1", "true", "yes", "on") -and $apiToken.Length -lt 32) {
    throw "CCC_AUTH_ENABLED is true but CCC_API_TOKEN is missing or too short. Run .\scripts\new_token.py and securely update .env."
}

& $python .\scripts\database_maintenance.py initialize
Write-Host "Starting Cyber Command Center on $hostName`:$port. Port-forwarding to the public internet is not supported."

& $python -m uvicorn backend.main:app --host $hostName --port $port
