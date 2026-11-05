# Full stack WITHOUT Docker: MariaDB on 127.0.0.1:3307, collector on :8000, dashboard on :8501.
# For machines where Docker Desktop cannot start. Everything binds to loopback only.
#
#   .\services\database\scripts\start_native_stack.ps1 -MariaDbHome C:\path\mariadb-11.4.9-winx64 -WorkDir C:\path\lab
#   .\services\database\scripts\start_native_stack.ps1 -MariaDbHome ... -WorkDir ... -Fresh    # wipe lab and SOC data first
#   .\services\database\scripts\start_native_stack.ps1 -MariaDbHome ... -WorkDir ... -Stop
param(
    [Parameter(Mandatory)] [string] $MariaDbHome,
    [Parameter(Mandatory)] [string] $WorkDir,
    [switch] $Fresh,
    [switch] $Stop
)

$repo = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$py = "$repo\.venv-db\Scripts\python.exe"
$lab = "$PSScriptRoot\native_lab.py"
$soc = "$WorkDir-soc"
$env:DECOY_DB_PASSWORD = if ($env:DECOY_DB_PASSWORD) { $env:DECOY_DB_PASSWORD } else { "Summer2026-ops" }
$env:CONTROLLER_DB_PASSWORD = if ($env:CONTROLLER_DB_PASSWORD) { $env:CONTROLLER_DB_PASSWORD } else { "native-lab-controller" }

function Stop-Stack {
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -match 'db_sensor\.main|collector\.app:app|streamlit' -and $_.CommandLine -match [regex]::Escape($repo) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    & $py $lab stop --mariadb-home $MariaDbHome --workdir $WorkDir 2>$null
}

if ($Stop) { Stop-Stack; return }

if ($Fresh) {
    Stop-Stack
    Start-Sleep -Seconds 2
    foreach ($dir in $WorkDir, $soc) {
        if ((Test-Path "$dir\my.ini") -or (Test-Path "$dir\collector.db")) { Remove-Item -Recurse -Force $dir }
    }
}
New-Item -ItemType Directory -Force "$soc\logs" | Out-Null

if (Test-Path "$WorkDir\data") {
    & $py $lab start --mariadb-home $MariaDbHome --workdir $WorkDir
} else {
    & $py $lab init --mariadb-home $MariaDbHome --workdir $WorkDir
}
if (-not $?) { throw "MariaDB did not start" }

function Start-Hidden([string[]] $Arguments, [string] $Name, [hashtable] $Environment) {
    foreach ($key in $Environment.Keys) { Set-Item "env:$key" $Environment[$key] }
    Start-Process -FilePath $py -ArgumentList $Arguments -WorkingDirectory $repo -WindowStyle Hidden `
        -RedirectStandardOutput "$soc\logs\$Name.out.log" -RedirectStandardError "$soc\logs\$Name.err.log"
}

Start-Hidden @("-m", "uvicorn", "collector.app:app", "--host", "127.0.0.1", "--port", "8000", "--no-access-log") "collector" `
    @{ COLLECTOR_DB_PATH = "$soc\collector.db"; PYTHONPATH = $repo }
Start-Sleep -Seconds 3
Start-Hidden @("-m", "db_sensor.main") "sensor" @{
    PYTHONPATH = "$repo\services\database\sensor"; AUDIT_LOG_PATH = "$WorkDir\logs\server_audit.log"
    SENSOR_DATA_DIR = "$soc\sensor"; COLLECTOR_BASE_URL = "http://127.0.0.1:8000"; DB_HOST = "127.0.0.1"; DB_PORT = "3307"
    INTERNAL_ACCOUNTS = "deception_ctrl@127.0.0.1,root@127.0.0.1"
}
Start-Hidden @("-m", "streamlit", "run", "dashboard\app.py", "--server.address=127.0.0.1", "--server.port=8501",
               "--server.headless=true", "--browser.gatherUsageStats=false") "dashboard" `
    @{ COLLECTOR_BASE_URL = "http://127.0.0.1:8000"; PYTHONPATH = $repo }

Write-Output "Dashboard: http://127.0.0.1:8501   Collector: http://127.0.0.1:8000/health"
Write-Output "Attacker:  mysql -h 127.0.0.1 -P 3307 --bind-address=127.0.0.2 -u decoy_user -p transnova_logistics"
