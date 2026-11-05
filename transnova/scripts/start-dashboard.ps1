# Dashboard laptop: start the TransNova SOC console on http://127.0.0.1:8501 (only this laptop can open it).
#   powershell -ExecutionPolicy Bypass -File .\scripts\start-dashboard.ps1
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path "frontend\dist\index.html")) { Write-Host "Build the dashboard first: cd frontend; npm ci; npm run build; cd .." -ForegroundColor Red; exit 1 }
$env:COLLECTOR_BASE_URL     = "http://127.0.0.1:8000"
$env:SOC_READ_TOKEN_FILE    = "secrets\read.token"
$env:SOC_CONSOLE_TOKEN_FILE = "secrets\console.token"
$env:SOC_USERS_FILE         = "secrets\users.txt"
Write-Host "Open http://127.0.0.1:8501 and sign in." -ForegroundColor Cyan
& ".\.venv\Scripts\python.exe" -m uvicorn console.serve:app --host 127.0.0.1 --port 8501 --no-server-header
