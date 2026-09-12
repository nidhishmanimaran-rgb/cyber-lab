$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    $token = & .\.venv\Scripts\python.exe .\scripts\new_token.py
    $config = Get-Content ".env.example" -Raw
    $config = $config -replace "(?m)^CCC_API_TOKEN=.*$", "CCC_API_TOKEN=$token"
    [System.IO.File]::WriteAllText((Join-Path $projectRoot ".env"), $config, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Created .env with authentication enabled and a new local API token."
    Write-Host "Keep .env private; copy the token directly into the Android app only when needed."
}

& .\.venv\Scripts\python.exe .\scripts\database_maintenance.py initialize

Write-Host "Cyber Command Center v1.0 setup complete."
Write-Host "Run .\scripts\start.ps1 to start the backend."
