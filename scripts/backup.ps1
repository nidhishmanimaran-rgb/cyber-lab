param(
    [string]$Destination
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$python = if (Test-Path ".venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
$arguments = @(".\scripts\database_maintenance.py", "backup")
if ($Destination) { $arguments += @("--destination", $Destination) }
& $python @arguments
