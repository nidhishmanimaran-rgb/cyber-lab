param(
    [Parameter(Mandatory = $true)]
    [string]$Source,
    [string]$Destination,
    [switch]$Replace
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$python = if (Test-Path ".venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
$arguments = @(".\scripts\database_maintenance.py", "restore", "--source", $Source)
if ($Destination) { $arguments += @("--destination", $Destination) }
if ($Replace) { $arguments += "--replace" }
& $python @arguments
