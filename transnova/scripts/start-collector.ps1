# Dashboard laptop: start the collector so the honeypot laptop can send events (port 8000 on the hotspot).
#   powershell -ExecutionPolicy Bypass -File .\scripts\start-collector.ps1
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path "secrets\web.token")) { Write-Host "Run: python scripts\make_secrets.py   (creates secrets\web.token)" -ForegroundColor Red; exit 1 }
New-Item -ItemType Directory -Force data\dev | Out-Null
$env:COLLECTOR_DB_PATH      = "data\dev\collector.db"
$env:SOC_READ_TOKEN_FILE    = "secrets\read.token"
$env:SOC_CONSOLE_TOKEN_FILE = "secrets\console.token"
$env:SSH_INGEST_TOKEN_FILE  = "secrets\ssh.token"
$env:WEB_INGEST_TOKEN_FILE  = "secrets\web.token"
$ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -like "Wi-Fi*" -and $_.IPAddress -notlike "169.254*" } | Select-Object -First 1).IPAddress
Write-Host "Collector for the honeypot laptop:  -DashboardIP $ip   token: $(Get-Content secrets\web.token)" -ForegroundColor Cyan
& ".\.venv\Scripts\python.exe" -m uvicorn collector.app:app --host 0.0.0.0 --port 8000 --http h11 --no-server-header --no-access-log
