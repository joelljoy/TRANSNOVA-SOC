# Web Decoy: 2-Minute Demo Runbook

Two ways to run it:
- **A. Team demo**: the simulator owner's container sends the web scenario from `172.28.0.50`
  (spec: `docs/SIMULATOR_WEB_SCENARIO.md`), and events show in the integrator's dashboard.
- **B. Solo rehearsal**: you send the requests yourself from this machine. No simulator or
  dashboard needed; you read the decoy's own log.

All commands run from the repo root unless stated. Windows: use PowerShell.

---

## A. Team demo (isolated lab)

**Before you present** (about 1 min, not part of the 2 minutes):
```bash
docker compose -f docker-compose.web.yml up -d --build
docker compose -f docker-compose.web.yml ps        # wait for (healthy)
```
Then, to have the containment proof ready on screen:
```bash
docker compose -f docker-compose.web.yml exec -T web-decoy python - < services/web/scripts/isolation_check.py
```
Windows:
```bash
Get-Content services/web/scripts/isolation_check.py | docker compose -f docker-compose.web.yml exec -T web-decoy python -
```

**The 2 minutes:**

| Time | Say | Show |
|---|---|---|
| 0:00 | "This is a fake logistics partner portal. Nothing in it is real, and it can't reach the internet or the host." | The isolation check output: `RESULT: ALL PASS` |
| 0:20 | "Our simulator now attacks it the way a real intruder would: scan, guess passwords, get in, then poke at the app." | Simulator owner starts the web scenario |
| 0:40 | "Every request became one event. The 8th missing page from one IP is flagged as a wordlist scan (T1595.003); the 5th wrong password is brute force (T1110.001)." | Dashboard event list, or the log (command below) |
| 1:05 | "The fake login worked, so everything after it is attacker activity: reading another customer's record, SQL injection, XSS, path traversal, an internal-URL fetch attempt, and a PHP file disguised as a JPEG." | Detections for steps 4–6 of the scenario |
| 1:35 | "Every probe is labelled an attempt, not a success. A webshell path probe is never called a deployed webshell, and the passwords they typed are not stored anywhere." | `Select-String` / `grep` for a guessed password returns nothing |
| 1:50 | "All of it carries one campaign ID, so the SOC sees one incident instead of 24 alerts." | Dashboard campaign timeline |

Decoy log, if the dashboard isn't ready:
```bash
docker compose -f docker-compose.web.yml exec web-decoy tail -n 30 /data/web-events.jsonl
```

---

## B. Solo rehearsal (no simulator, no dashboard)

**Helpers:** load once per PowerShell window, from any folder:
`. .\services\web\scripts\demo_helpers.ps1` (from the repo root). It gives you `Last`, `Rules`, `ClearLog`,
`DemoFiles` and `CleanFiles`, and they find the event log themselves.

Run without Docker so you can send requests from this machine. Do this in `services/web`, with the venv active.
**Use `python -m web_decoy.serve`, not plain `uvicorn`:** plain uvicorn trusts a forged
`X-Forwarded-For` from localhost (PLAN P13) and has no slow-header deadline.

```bash
$env:COLLECTOR_URL=""; $env:WEB_DECOY_HOST="127.0.0.1"; $env:WEB_DECOY_PORT="8081"
python -m web_decoy.serve
```

In a second window (also in `services/web`):

```bash
Clear-Content data\web-events.jsonl
```

Scan (9 paths):
```bash
"/admin","/.env","/.git/config","/backup","/config","/backup.zip","/wp-login.php","/phpmyadmin","/server-status" | ForEach-Object { curl.exe -s -o NUL "http://127.0.0.1:8081$_" }
```

Brute force, then the decoy credential:
```bash
1..5 | ForEach-Object { curl.exe -s -o NUL -d "username=j.miller&password=guess$_" http://127.0.0.1:8081/login }; curl.exe -s -o NUL -c jar.txt -d "username=j.miller&password=TransNova%23Spring26" http://127.0.0.1:8081/login
```

After login: IDOR, SQLi, XSS, traversal, SSRF, disguised upload, webshell probe:
```bash
curl.exe -s -o NUL -b jar.txt http://127.0.0.1:8081/api/v1/users/1002; curl.exe -s -o NUL "http://127.0.0.1:8081/search?q=%27%20UNION%20SELECT%20password%20FROM%20users--"; curl.exe -s -o NUL "http://127.0.0.1:8081/search?q=%3Cscript%3Ealert(1)%3C/script%3E"; curl.exe -s -o NUL "http://127.0.0.1:8081/download?file=../../etc/passwd"; curl.exe -s -o NUL "http://127.0.0.1:8081/api/v1/preview?url=http://169.254.169.254/"; [IO.File]::WriteAllText("$PWD\avatar.jpg", "<?php system(1); ?>"); curl.exe -s -o NUL -b jar.txt -F "document=@avatar.jpg;type=image/jpeg" http://127.0.0.1:8081/upload; curl.exe -s -o NUL http://127.0.0.1:8081/wp-content/uploads/shell.php
```

Rules view:
```bash
Get-Content data\web-events.jsonl | ForEach-Object { $e = $_ | ConvertFrom-Json; "{0,-28} {1}" -f $e.request_path, (($e.raw_evidence_redacted.detections | ForEach-Object { $_.rule + "(" + $_.confidence + ")" }) -join ", ") }
```

Clean up the two scratch files:
```bash
Remove-Item jar.txt, avatar.jpg
```

Expected: the rows match `services/web/samples/web-attack-campaign.sample.jsonl` (W-ENUM-02 from the
8th scan path on; that sample was captured with 0.7.0, where it showed only on the 8th: since 0.8.0 the 9th and 10th scan paths carry it too, W-AUTH-02 on the 5th failure, W-AUTH-04, W-IDOR-01, W-SQLI-01, W-XSS-01, W-PATH-01,
W-SSRF-01, W-UPL-01, W-SHELL-01). In this mode `campaign_id` stays empty, because only the simulator's lab IP may set one.

---

## If something goes wrong

| Symptom | Fix |
|---|---|
| Health stays `starting` | `docker compose -f docker-compose.web.yml logs web-decoy` |
| Isolation check: `no egress` FAIL | You started it with the browse override. Run `down`, then `up` with only `docker-compose.web.yml` |
| `W-AUTH-02` / `W-ENUM-02` appear on earlier lines than expected on a re-run | The counters remember the last 60 s. Wait 60 s, or restart the decoy |
| Port 8081 in use | Pick another port, and change it in every command |
