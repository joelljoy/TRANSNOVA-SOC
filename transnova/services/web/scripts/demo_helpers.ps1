# Demo helpers for the web decoy (Windows PowerShell 5.1+ and PowerShell 7).
#
# Load once per PowerShell window, from ANY folder:
#     . C:\Users\<you>\...\PS4---DJS\services\web\scripts\demo_helpers.ps1
# (note the leading dot and space: "dot-sourcing" keeps the functions in your window)
#
# Then:
#     Last        newest event, readable, with the rules that fired
#     Rules       every event, one line each, with the rules that fired
#     Watch       LIVE: prints each new event the moment it happens (Ctrl+C to stop)
#     Find X      only events where rule X fired, e.g.  Find W-AUTH-02   (or a label: Find auth:)
#     Summary     counts: events, rules fired, outcomes, top source IPs
#     Timeline X  one attacker's story in order: X = an IP (127.0.0.1) or a session_id
#     ClearLog    empty the event log before a demo
#     DemoFiles   create the scratch files used by the size/slow/upload cases
#     CleanFiles  delete those scratch files
#
# Paths are resolved relative to this script, so the current folder does not matter.

$script:WebDir  = Split-Path -Parent $PSScriptRoot
$script:EventLog = Join-Path $script:WebDir "data\web-events.jsonl"

function Last {
    if (-not (Test-Path $script:EventLog)) { "No events yet ($script:EventLog)"; return }
    $line = Get-Content $script:EventLog -Tail 1
    if (-not $line) { "Log is empty"; return }
    $e = $line | ConvertFrom-Json
    "path=$($e.request_path)  status=$($e.http_status)  outcome=$($e.outcome)  ip=$($e.source_ip)  campaign=$($e.campaign_id)  tags=$($e.tags -join ',')"
    foreach ($d in $e.raw_evidence_redacted.detections) {
        $tech = ($d.attack | ForEach-Object { $_.technique }) -join ','
        "   RULE $($d.rule) [$($d.confidence)] field=$($d.field) attack=$tech  -> $($d.rationale)"
    }
}

function Rules {
    if (-not (Test-Path $script:EventLog)) { "No events yet ($script:EventLog)"; return }
    Get-Content $script:EventLog | ForEach-Object {
        $e = $_ | ConvertFrom-Json
        $r = ($e.raw_evidence_redacted.detections | ForEach-Object { $_.rule + "(" + $_.confidence + ")" }) -join ", "
        "{0,-28} {1}" -f $e.request_path, $r
    }
}

function _Events {
    if (-not (Test-Path $script:EventLog)) { return @() }
    Get-Content $script:EventLog | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json }
}

function _Line($e) {
    # PowerShell 7 turns ISO timestamps into [datetime]; Windows PowerShell 5.1 keeps strings.
    $t = if ($e.timestamp -is [datetime]) { $e.timestamp.ToUniversalTime().ToString("HH:mm:ss") }
         elseif ("$($e.timestamp)".Length -ge 19) { "$($e.timestamp)".Substring(11, 8) } else { "$($e.timestamp)" }
    $r = ($e.raw_evidence_redacted.detections | ForEach-Object { $_.rule + "(" + $_.confidence + ")" }) -join ", "
    "{0}  {1,-15} {2,-6} {3,-28} {4,-4} {5,-9} {6}" -f $t, $e.source_ip, $e.http_method, $e.request_path, $e.http_status, $e.outcome, $r
}

function Watch {
    if (-not (Test-Path $script:EventLog)) { New-Item -ItemType File -Force -Path $script:EventLog | Out-Null }
    "Watching $script:EventLog  (Ctrl+C to stop)"
    "TIME      SOURCE IP       METHOD PATH                         CODE OUTCOME   RULES"
    Get-Content $script:EventLog -Wait -Tail 0 | Where-Object { $_ } | ForEach-Object { _Line ($_ | ConvertFrom-Json) }
}

function Find([string]$Rule) {
    if (-not $Rule) { "Usage: Find W-AUTH-02   (rule id, or part of a label like auth:)"; return }
    $hits = _Events | Where-Object {
        $d = $_.raw_evidence_redacted.detections
        ($d | Where-Object { $_.rule -like "*$Rule*" -or $_.label -like "*$Rule*" })
    }
    "$(@($hits).Count) event(s) matching '$Rule'"
    foreach ($e in $hits) {
        _Line $e
        foreach ($d in $e.raw_evidence_redacted.detections | Where-Object { $_.rule -like "*$Rule*" -or $_.label -like "*$Rule*" }) {
            $tech = ($d.attack | ForEach-Object { $_.technique }) -join ','
            "          -> $($d.rule) [$($d.confidence)] field=$($d.field) attack=$tech : $($d.rationale)"
        }
    }
}

function Summary {
    $all = @(_Events)
    "Events in log: $($all.Count)"
    if ($all.Count -eq 0) { return }
    ""
    "Rules fired (how many times):"
    $all | ForEach-Object { $_.raw_evidence_redacted.detections } | Where-Object { $_ } |
        Group-Object rule | Sort-Object Count -Descending | Format-Table @{n='Count';e={$_.Count}}, @{n='Rule';e={$_.Name}} -AutoSize | Out-String
    "Outcomes:"
    $all | Group-Object outcome | Sort-Object Count -Descending | Format-Table @{n='Count';e={$_.Count}}, @{n='Outcome';e={$_.Name}} -AutoSize | Out-String
    "Top source IPs:"
    $all | Group-Object source_ip | Sort-Object Count -Descending | Select-Object -First 5 |
        Format-Table @{n='Count';e={$_.Count}}, @{n='Source IP';e={$_.Name}} -AutoSize | Out-String
}

function Timeline([string]$Who) {
    if (-not $Who) { "Usage: Timeline 127.0.0.1   or   Timeline <session_id>"; return }
    $evs = @(_Events | Where-Object { $_.source_ip -eq $Who -or $_.session_id -eq $Who })
    "$($evs.Count) event(s) for $Who, oldest first:"
    "TIME      SOURCE IP       METHOD PATH                         CODE OUTCOME   RULES"
    foreach ($e in $evs) { _Line $e }
}

function ClearLog {
    if (Test-Path $script:EventLog) { Clear-Content $script:EventLog }
    "Event log cleared: $script:EventLog"
}

function DemoFiles {
    Push-Location $script:WebDir
    [IO.File]::WriteAllText((Join-Path $script:WebDir "big.txt"), ("a" * 70000))
    [IO.File]::WriteAllText((Join-Path $script:WebDir "slow.txt"), ("a" * 2000))
    [IO.File]::WriteAllText((Join-Path $script:WebDir "avatar.jpg"), "<?php system(1); ?>")
    [IO.File]::WriteAllBytes((Join-Path $script:WebDir "big.bin"), (New-Object byte[] 1500000))
    Pop-Location
    "Created big.txt, slow.txt, avatar.jpg, big.bin in $script:WebDir (run the demo commands from this folder)"
}

function CleanFiles {
    foreach ($f in "big.txt", "slow.txt", "avatar.jpg", "big.bin", "jar.txt") {
        $p = Join-Path $script:WebDir $f
        if (Test-Path $p) { Remove-Item $p }
    }
    "Scratch files removed"
}

"Demo helpers loaded. Log: $script:EventLog"
"Commands: Last, Rules, Watch, Find <rule>, Summary, Timeline <ip|session>, ClearLog, DemoFiles, CleanFiles"
