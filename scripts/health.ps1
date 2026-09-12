param(
    [string]$Url = "http://127.0.0.1:8001"
)

$ErrorActionPreference = "Stop"
$response = Invoke-WebRequest -Uri "$($Url.TrimEnd('/'))/api/status" -UseBasicParsing -TimeoutSec 10
if ($response.StatusCode -ne 200) {
    throw "Backend health check returned HTTP $($response.StatusCode)."
}
Write-Host "Cyber Command Center health check passed."
