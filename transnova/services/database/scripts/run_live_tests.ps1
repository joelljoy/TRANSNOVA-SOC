# Rebuilds a clean native lab, then runs the live tests with a genuine MySQL client.
# Works without Docker. Deletes only -WorkDir (the disposable lab it created).
#
#   .\services\database\scripts\run_live_tests.ps1 -MariaDbHome C:\path\mariadb-11.4.9-winx64 -WorkDir C:\path\lab
#   ... -Suite audit     runs the readiness audit instead of the end-to-end suite
param(
    [Parameter(Mandatory)] [string] $MariaDbHome,
    [Parameter(Mandatory)] [string] $WorkDir,
    [ValidateSet("live", "audit")] [string] $Suite = "live",
    [string] $MysqlClient = "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe",
    [string] $Python = "$PSScriptRoot\..\..\..\.venv-db\Scripts\python.exe"
)

$lab = "$PSScriptRoot\native_lab.py"
$env:DECOY_DB_PASSWORD = "Summer2026-ops"
$env:CONTROLLER_DB_PASSWORD = "native-lab-controller"
$env:NATIVE_ROOT_PASSWORD = "native-lab-root"

& $Python $lab stop --mariadb-home $MariaDbHome --workdir $WorkDir 2>$null
Start-Sleep -Seconds 2
if (Test-Path "$WorkDir\my.ini") { Remove-Item -Recurse -Force $WorkDir }
& $Python $lab init --mariadb-home $MariaDbHome --workdir $WorkDir
if (-not $?) { throw "native lab failed to start" }

$env:LIVE_MYSQL_CLIENT = $MysqlClient
$env:LIVE_AUDIT_LOG = "$WorkDir\logs\server_audit.log"
$env:LIVE_MARIADB_HOME = $MariaDbHome
$env:LIVE_WORKDIR = $WorkDir
& $Python -m pytest "$PSScriptRoot\..\tests\$Suite" -v -p no:cacheprovider --tb=short
