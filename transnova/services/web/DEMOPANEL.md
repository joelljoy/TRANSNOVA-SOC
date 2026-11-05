# Demo Panel — Web Decoy (TransNova Logistics)

Your one-page guide for the judges. It covers **what each case tests, the exact rule and
threshold behind it, the command to run, and the output you should see.** Every "Expected" block was
captured from a real run of version **0.6.0** (2026-10-31); 0.7.0 only adds HTTPS inside the container, so the local-run outputs are unchanged. 0.8.0 changes one thing you will see: once a behaviour rule (W-ENUM-02, W-AUTH-02, W-AUTH-03) crosses its threshold, **every** following qualifying request carries it too, not just the first one. **0.9.0** rebrands the portal to TransNova Logistics (password now `TransNova#Spring26`, URL-encoded `TransNova%23Spring26` in curl), adds realism pages (/status, /changelog, /help, /robots.txt) and labels Tor/VPN/hosting visitors with W-ANON-01/02 (see `docs/TOR_VPN.md`). Normal 127.0.0.1 runs show no W-ANON label unless you put `127.0.0.1 tor` in `services/anonintel/data/demo.txt`. Cases H and K were verified on the
same code; K's output is what your own Windows machine printed.

Thresholds are quoted from the code; the file is named next to each one, so you can open it if a judge asks.

---

## 0. Setup (every time, before the judges)

**Window 1: the decoy** (from `PS4---DJS\services\web`):
```bash
.\.venv\Scripts\Activate.ps1
```
```bash
$env:COLLECTOR_URL=""; $env:WEB_DECOY_HOST="127.0.0.1"; $env:WEB_DECOY_PORT="8081"; python -m web_decoy.serve
```
✅ The last line must be `Uvicorn running on http://127.0.0.1:8081`, with **no** `ERROR` line.
**Always use `python -m web_decoy.serve`**, never plain `uvicorn`: plain uvicorn trusts faked IP headers and has no slow-header deadline.

**Window 2: the attacker and evidence** (from `PS4---DJS`):
```bash
. .\services\web\scripts\demo_helpers.ps1
```
```bash
cd services\web
```
```bash
(curl.exe -s http://127.0.0.1:8081/health | ConvertFrom-Json).version
```
✅ It must print `0.10.0`. Anything else means an old server is answering: stop it (`netstat -ano | findstr :8081`, then `taskkill /PID <n> /F`).
```bash
ClearLog
```
```bash
DemoFiles
```

**Window 3: isolation** (from `PS4---DJS`, Docker Desktop showing "Engine running"):
```bash
docker compose -f docker-compose.web.yml up -d --build
```

**Helper commands** (from `demo_helpers.ps1`): `Last` = newest event; `Rules` = all events with the rules that fired; `ClearLog`; `DemoFiles`; `CleanFiles`.

**Order matters:** run Case A **before** opening the browser. Browser visits to `/admin`, `/docs` and the automatic `/favicon.ico` also count toward the scan, which would make the scan label fire on an earlier line.
**Counters remember the last 60 s per IP (spraying: 5 min):** if you rehearsed within that time, the pattern labels appear on earlier lines than shown below. Restart Window 1 and run `ClearLog` first.

---

## 1. How to read the output

**Rule ID**, e.g. `W-ENUM-02`:
- `W` = web decoy
- the middle part = category: `ENUM` snooping, `AUTH` login attacks, `SQLI` / `XSS` / `PATH` / `SSRF` injection, `UPL` upload, `IDOR` access control, `SHELL` webshell probe
- the number = the rule in that category

**Confidence**: how strongly the evidence shows a *deliberate attack*. It is **not** how much damage was done; in a decoy, nothing is damaged.

| Level | Meaning | Rules at this level |
|---|---|---|
| **low** | Suspicious, but one event alone is weak evidence (bots, typos, broken links) | W-ENUM-01, W-AUTH-01, W-SHELL-01 |
| **medium** | A clear attack **pattern** or attack **string**; intent is clear, success is not proven | W-ENUM-02, W-AUTH-02 (5–14 failures), W-AUTH-03, W-SQLI-01, W-XSS-01, W-PATH-01, W-SSRF-01, W-UPL-01, W-IDOR-01 |
| **high** | Almost certainly a determined attacker | W-AUTH-02 at 15+ failures; W-AUTH-04 (nobody legitimate can ever log into the fake account) |

**Event fields:**
- `outcome`: `observed` = seen and recorded; `failed` / `succeeded` = login result; `blocked` = refused for size or time.
- **Every probe is an attempt, never a success.** That's why SQL injection is `medium`, not "critical": the decoy proves someone *tried*, and nothing worked.

**ATT&CK codes** (only where the evidence supports them, always marked "candidate"):
- **T1595.003** wordlist scanning
- **T1110.001** password guessing
- **T1110.003** password spraying
- **T1190** exploit attempt against a public app (SQLi)
- **T1505.003** (webshell) is **never** used: requesting `/shell.php` only proves someone *looked*.

---

## 2. Every threshold in one table

| What | Threshold (exact) | Over the limit → | Where in code |
|---|---|---|---|
| Normal request body (login, search, API) | **65,536 bytes** (64 KiB). 65,536 is accepted; 65,537 is rejected | `413` + event `blocked`, tag `body_rejected` | `config.py` `max_body_bytes` |
| Uploaded file | **983,040 bytes** (960 KiB) for the file itself | `413` + `blocked` | `config.py` `max_upload_bytes` |
| Whole upload request (file + multipart wrapping) | **1,048,576 bytes** (1 MiB) = 960 KiB + 64 KiB overhead. Kept ≤ 1 MiB so the file never touches disk | `413` + `blocked`, tag `body_rejected` | `config.py` `max_upload_bytes + multipart_overhead_bytes` |
| `Content-Length` header that isn't a number | Any non-digit value | `400` | `telemetry/middleware.py` |
| Time to send the whole body | **15 seconds** total, from the moment headers arrive | `408` + `blocked`, tag `body_timeout` | `config.py` `body_timeout_s` |
| Time to send the headers | **10 seconds** from connecting. Absolute: trickling bytes doesn't reset it | Connection closed (**no event**: the request never existed) | `serve.py` `HEADER_TIMEOUT_S` |
| Idle keep-alive connection | **5 seconds** | Connection closed | `serve.py` `timeout_keep_alive` |
| Simultaneous requests | **200** | `503` from the server | `serve.py` `limit_concurrency` |
| Simultaneous connections from **one** IP | **20** of the 200 | Extra connections closed immediately (not logged) | `serve.py` `MAX_CONN_PER_IP` |
| Request speed from **one** IP | **20 per second**, burst of **60** | `429 Too Many Requests` (nginx page); one `rate_limited` event per IP per 10 s, with a count | `web_decoy/ratelimit.py`, `config.py` `rate_limit_*` |
| Route scan (W-ENUM-02) | **8 different paths** answered 403/404/405 or on the bait list, **same IP**, within **60 s**. Then tags **every** further such request while the count stays ≥ 8 | label `medium`, T1595.003 | `detection/behavior.py` `SCAN_*` |
| Brute force (W-AUTH-02) | **5 failed logins**, same username, same IP, within **60 s** → medium; **15** → high. Tags **every** failure while the count stays ≥ 5 | T1110.001 | `detection/behavior.py` `BRUTE_*` |
| Password spraying (W-AUTH-03) | **4 different usernames**, each tried **at most 2 times**, same IP, within **300 s** (5 min). Then tags **every** failed login while the condition holds | `medium`, T1110.003 | `detection/behavior.py` `SPRAY_*` |
| Decoy login (W-AUTH-04) | Username `j.miller` + password `TransNova#Spring26` (synthetic; protects nothing) | `high` | `config.py` `decoy_user/decoy_password` |
| Text examined by injection rules | URL-decoded **up to 2 times**, Unicode-folded (NFKC), lowercased, NUL bytes removed, cut to **2,048 characters** | — | `detection/normalize.py` |
| Stored value length | **512 characters** per value, **50** keys per section, **4,096 bytes** of evidence per event | Truncated with a `…[truncated N]` marker | `telemetry/redact.py` |
| Detections per event | Max **10** | Extra are dropped | `telemetry/middleware.py` `MAX_DETECTIONS` |
| Who may set a campaign ID | Header `X-Campaign-Id` matching `^[A-Za-z0-9_-]{1,64}$` **and** sent from **172.28.0.50** (the simulator's lab IP) | Otherwise dropped, tag `untrusted_campaign_header` | `config.py` `simulator_cidrs`; `middleware.py` `CAMPAIGN_RE` |
| Who sees detailed `/health` | **127.0.0.1** only (inside the container / local run) | Everyone else gets a normal `404` | `config.py` `health_allowed` |
| `X-Forwarded-For` | **Ignored** (`TRUST_PROXY=0`) | The real TCP address is logged | `serve.py` `proxy_headers=False` |

**Why these numbers:**
- **64 KiB** is far larger than any real login or search form, and small enough that 200 concurrent requests can't exhaust memory.
- **15 s / 10 s** is generous for a real client on a slow link, while stopping "slowloris" attacks that hold connections open on purpose.
- **8 paths / 60 s** separates scanners from a human clicking a couple of broken links.
- **5 failures / 60 s** separates guessing from someone mistyping their password once or twice.

---

## Case A — Scan for hidden files

**What you're testing:** single sensitive-path probes (low), and the scan pattern (medium) once enough of them pile up.

**Parameters:**
- **W-ENUM-01 (low)** fires when the path is on the bait list:
  - exact paths: `/admin`, `/admin/`, `/backup`, `/backup/`, `/config`, `/api`, `/api/`, `/.env`, `/config.php`, `/wp-login.php`, `/wp-admin`, `/phpmyadmin`, `/server-status`, `/.DS_Store`, `/web.config`, `/actuator`, `/actuator/env`, `/console`, `/.htaccess`, `/.htpasswd`
  - prefixes: `/.git/`, `/.svn/`, `/.aws/`, `/.ssh/`, `/admin/`, `/backup/`, `/.env.`
  - backup-file endings: `.sql .bak .old .orig .swp .zip .tar .tgz .gz .7z .rar .dump`
- **W-ENUM-02 (medium, T1595.003)** fires when **8 different** such paths (or any 403/404/405) arrive from one IP within **60 s**.

```bash
"/.env","/.git/config","/backup","/config","/backup.zip","/wp-login.php","/phpmyadmin","/server-status" | ForEach-Object { curl.exe -s -o NUL "http://127.0.0.1:8081$_" }; Rules
```
**Expected:**
```
/.env                        W-ENUM-01(low)
/.git/config                 W-ENUM-01(low)
/backup                      W-ENUM-01(low)
/config                      W-ENUM-01(low)
/backup.zip                  W-ENUM-01(low)
/wp-login.php                W-ENUM-01(low)
/phpmyadmin                  W-ENUM-01(low)
/server-status               W-ENUM-01(low), W-ENUM-02(medium)
```
**Say:** "Each sensitive path alone is a low probe. The 8th different one within a minute is a wordlist scan, ATT&CK T1595.003. Seven small signals become one clear one."

---

## Case B — Password guessing

**What you're testing:** failed logins (low each) adding up to a brute-force pattern (medium).

**Parameters:**
- **W-AUTH-01 (low)** fires on every failed login.
- **W-AUTH-02** fires at **5** failures for the **same username** from the **same IP** within **60 s** (medium), and stays on **every** failure after that: medium for 5–14, **high from 15 on**. It drops off only when fewer than 5 failures remain in the last 60 s.

```bash
1..5 | ForEach-Object { curl.exe -s -o NUL -d "username=j.miller&password=guess$_" http://127.0.0.1:8081/login }; Last
```
**Expected:**
```
path=/login  status=401  outcome=failed  ip=127.0.0.1  campaign=  tags=auth:failed,auth:bruteforce
   RULE W-AUTH-01 [low] field=form.username attack=  -> failed login attempt
   RULE W-AUTH-02 [medium] field=form.username attack=T1110.001  -> 5 failed logins for one username from this source within 60s (threshold 5 medium / 15 high)
```
**Say:** "The 5th wrong password within 60 seconds is brute force, ATT&CK T1110.001, and the threshold is written into the event itself."

---

## Case C — Attacker gets in with the fake account

**What you're testing:** use of the decoy credential, which is the strongest signal there is.

**Parameters:**
- **W-AUTH-04 (high)** fires when `j.miller` / `TransNova#Spring26` is accepted.
- The rationale counts earlier failures for that username in the last **300 s**.
- The new session ID ties every later request to this intruder.

```bash
curl.exe -s -o NUL -c jar.txt -d "username=j.miller&password=TransNova%23Spring26" http://127.0.0.1:8081/login; Last
```
**Expected:**
```
path=/login  status=302  outcome=succeeded  ip=127.0.0.1  campaign=  tags=authenticated_session,auth:decoy_success
   RULE W-AUTH-04 [high] field=form.username attack=  -> synthetic decoy credential accepted; all later activity in this session is attacker activity (after 5 failed attempts for this username within 300s)
```
**Say:** "This account is fake, so no legitimate user can ever log in with it. Everything from here on is attacker activity, linked by one session ID."

---

## Case D — Attack hidden in the password box

**What you're testing:**
1. The detector reads the **raw** input in memory, **before** redaction.
2. The password is **never written** to the log.

**Parameters:**
- **W-SQLI-01 (medium, T1190 candidate)** fires if the normalized text matches any of these SQL patterns:
  - quote + `or`/`and` + comparison, e.g. `' OR 1=1`, `' or 'a'='a`
  - `union [all] select`
  - quote/backtick/bracket followed by a comment: `--`, `#`, `/*`
  - `sleep(`, `benchmark(`, `pg_sleep(`, `waitfor delay`
  - `information_schema`, `sqlite_master`, `sys.tables`
  - `;` followed by `drop` / `delete` / `insert` / `update` / `truncate` / `shutdown` / `exec` / `select`
  - `or 1=1` without a quote
  - `extractvalue(`, `updatexml(`, `load_file(`
- **Redaction:** any field whose **name** contains `pass`, `pwd`, `secret`, `token`, `api_key`, `auth`, `session`, `cookie`, `jwt`, `bearer`, `otp`, `credential` or `private_key` is stored as `[REDACTED]`. Values that **look like** secrets (JWTs, `Bearer …`, AWS keys, GitHub tokens, private keys, `password=…`) are redacted in every field.
- **Order in code:** `telemetry/middleware.py` runs the detectors at line 234 and redacts at line 240.

```bash
curl.exe -s -o NUL -d "username=admin&password=' OR 1=1 -- MySecret123" http://127.0.0.1:8081/login; Last
```
**Expected:**
```
path=/login  status=401  outcome=failed  ip=127.0.0.1  campaign=  tags=probe:sqli,auth:failed
   RULE W-SQLI-01 [medium] field=form.password attack=T1190  -> SQL injection-like syntax in form.password; attempt observed; no evidence of success
   RULE W-AUTH-01 [low] field=form.username attack=  -> failed login attempt
```
```bash
Select-String -Path data\web-events.jsonl -Pattern "MySecret123"
```
**Expected:** **no output at all.**
```bash
(Get-Content data\web-events.jsonl -Tail 1 | ConvertFrom-Json).raw_evidence_redacted.form
```
**Expected:**
```
username password
-------- --------
admin    [REDACTED]
```
**Say:** "The attack was hidden in the password field. The detector caught it from the raw value in memory, and then the password was removed before anything was saved. We know *what* happened and *where*, but we never store what they typed."

---

## Case E — Post-login attacks, each labelled

**What you're testing:** six different attack types, each recognised, and none of them working.

**Parameters:**

| Rule | Fires when | What the trap does instead |
|---|---|---|
| **W-IDOR-01** (medium) | A **logged-in** user GETs `/api/v1/users/<id>` or `/portal/shipments/<id>` that belongs to **someone else**. Fake users: 1001 = j.miller, 1002, 1003 | Returns fake data; the label records the access-control probe |
| **W-XSS-01** (medium) | `<script`, `on…=` handlers (`onerror=`, `onload=`…), `javascript:`, `vbscript:`, `data:text/html`, `<iframe`/`<svg`/`<object`/`<embed`/`<math`/`<base`/`<meta`, `document.cookie`, `srcdoc=` | The page shows the text escaped; it never runs |
| **W-PATH-01** (medium) | `../` or `..\`, `/etc/passwd` / `shadow` / `hosts` / `group`, `/proc/self/`, `win.ini` / `boot.ini` / `system.ini`, `C:\Windows\`, or a NUL byte (`%00`). Works even double-encoded (`%252e%252e%252f`) or full-width (`．．／`) | The download is a dictionary lookup of 2 fake files; no file is ever opened |
| **W-SSRF-01** (medium) | A URL using `file` / `gopher` / `dict` / `ftp` / `ldap` / `tftp` / `jar` / `netdoc` / `php` / `expect`, **or** an http(s) URL to loopback, private, link-local, `0.0.0.0` or reserved addresses, `localhost`, `*.internal`, or cloud-metadata hosts, including decimal (`2130706433`) and hex (`0x7f000001`) forms | Always answers "preview unavailable"; nothing is ever fetched |
| **W-UPL-01** (medium) | Content looks like PHP / ELF / EXE / script; **or** an executable extension (`.php .phtml .phar .jsp .jspx .asp .aspx .sh .bash .py .pl .rb .exe .dll .so .elf .bat .ps1 .cgi`); **or** declared as an image but isn't one; **or** PHP/JSP/ASP code markers found **anywhere** in the file | The file is hashed (SHA-256), labelled, and **thrown away**; never stored or run |
| **W-SHELL-01** (low) | A script extension (`.php .phtml .phar .jsp .jspx .asp .aspx .ashx .cgi .pl`) **and** either a known webshell name (`shell`, `cmd`, `c99`, `r57`, `wso`, `b374k`, `webshell`, `backdoor`, `up`, `x`, `1`, `alfa`, `indoxploit`, `mini`, `sh`, `bypass`) or `/upload` in the path | `404`; labelled a probe, never a deployed webshell |

```bash
curl.exe -s -o NUL -b jar.txt http://127.0.0.1:8081/api/v1/users/1002; curl.exe -s -o NUL "http://127.0.0.1:8081/search?q=%3Cscript%3Ealert(1)%3C/script%3E"; curl.exe -s -o NUL "http://127.0.0.1:8081/download?file=../../etc/passwd"; curl.exe -s -o NUL "http://127.0.0.1:8081/api/v1/preview?url=http://169.254.169.254/"; curl.exe -s -o NUL -b jar.txt -F "document=@avatar.jpg;type=image/jpeg" http://127.0.0.1:8081/upload; curl.exe -s -o NUL http://127.0.0.1:8081/wp-content/uploads/shell.php; Rules
```
**Expected** (the **last 6 lines**; the lines above them are from Cases A–D):
```
/api/v1/users/1002           W-IDOR-01(medium)
/search                      W-XSS-01(medium)
/download                    W-PATH-01(medium)
/api/v1/preview              W-SSRF-01(medium)
/upload                      W-UPL-01(medium)
/wp-content/uploads/shell.php W-SHELL-01(low)
```
**Say:** "Reading another customer's record, script injection, a system-file grab, an attempt to make the server fetch cloud credentials, a webshell disguised as a JPEG, and a webshell probe. All six are recognised, and none worked: no file opened, no URL fetched, the upload thrown away."

---

## Case F — Too big

**What you're testing:** oversized requests are refused before they can use up memory, and still logged.

**Parameters:**
- A normal body over **65,536 bytes** → `413`.
  - `big.txt` is **70,000 bytes**.
  - It's checked twice: against the declared `Content-Length`, **and** against the bytes actually received (so chunked uploads can't sneak past).
- A whole upload over **1,048,576 bytes**, or a file over **983,040 bytes** → `413`.
  - `big.bin` is **1,500,000 bytes**.

```bash
curl.exe -s -o NUL -w "%{http_code}`n" --data-binary "@big.txt" -H "Content-Type: application/x-www-form-urlencoded" http://127.0.0.1:8081/login; Last
```
**Expected:**
```
413
path=/login  status=413  outcome=blocked  ip=127.0.0.1  campaign=  tags=body_rejected
```
```bash
curl.exe -s -o NUL -w "%{http_code}`n" -F "document=@big.bin" http://127.0.0.1:8081/upload; Last
```
**Expected:**
```
413
path=/upload  status=413  outcome=blocked  ip=127.0.0.1  campaign=  tags=body_rejected
```
**Say:** "Anything over 64 KB, or an upload over 960 KB, is refused, and the attempt is still recorded."

---

## Case G — Too slow (body)

**What you're testing:** a client that sends its data extremely slowly, to tie up the server, gets cut off.

**Parameters:**
- The whole body must arrive within **15 seconds** of the headers, or the server returns `408`, logged as `blocked` with tag `body_timeout`.
- `slow.txt` is **2,000 bytes**, sent at **100 bytes/s**, which would take **20 s**.

```bash
$t=Get-Date; curl.exe -s -o NUL -w "%{http_code}`n" --limit-rate 100 --data-binary "@slow.txt" -H "Content-Type: application/x-www-form-urlencoded" http://127.0.0.1:8081/login; "took {0:N0} s" -f ((Get-Date)-$t).TotalSeconds; Last
```
**Expected:**
```
408
took 15 s
path=/login  status=408  outcome=blocked  ip=127.0.0.1  campaign=  tags=body_timeout
```
**Say:** "Before our security review, about 200 of these slow connections could silently black out the decoy. Now each one is cut off after 15 seconds and recorded."

---

## Case H — Too slow (headers)

**What you're testing:** the same trick at the header stage, before the app is even involved.

**Parameters:**
- The headers must be complete within **10 seconds** of connecting.
- The deadline is **absolute**: sending one byte per second does **not** reset it.
- Stock uvicorn's own timer *does* reset on every byte, which is why we added this.

```bash
$c=New-Object System.Net.Sockets.TcpClient("127.0.0.1",8081); $s=$c.GetStream(); $b=[Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: x`r`nX-Slow: "); $s.Write($b,0,$b.Length); $t=Get-Date; try { while ($true) { Start-Sleep 1; $s.WriteByte(97); $s.Flush() } } catch { "server cut us off after {0:N0} s" -f ((Get-Date)-$t).TotalSeconds }
```
**Expected:** `server cut us off after 10 s` (or `11 s`).
**No event appears in the log**, because the connection is closed before a request exists. That's a known, documented limit.

**Say:** "Same trick at the header stage. The 10-second deadline doesn't reset however slowly they trickle data in."

---

## Case I — Faked IP and campaign ID

**What you're testing:** an attacker can't lie about who they are, or tag their traffic as our simulator.

**Parameters:**
- `X-Forwarded-For` is **ignored**; the real TCP address is logged.
- `X-Campaign-Id` is accepted only if it matches `^[A-Za-z0-9_-]{1,64}$` **and** comes from **172.28.0.50**. Otherwise it's dropped and tagged `untrusted_campaign_header`.

```bash
curl.exe -s -o NUL -H "X-Forwarded-For: 8.8.8.8" -H "X-Campaign-Id: fake-campaign" http://127.0.0.1:8081/admin; Last
```
**Expected:**
```
path=/admin  status=302  outcome=observed  ip=127.0.0.1  campaign=  tags=untrusted_campaign_header,enum:sensitive_path
   RULE W-ENUM-01 [low] field=path attack=  -> request for an admin/backup/config/VCS path commonly targeted by scanners
```
**Say:** "It claimed to be 8.8.8.8 and tried to plant a fake campaign label. We logged the real address and refused the label, because only our simulator's fixed lab address may set one."

---

## Case J — It looks real (browser; only after Case A)

**What you're testing:** realism. An attacker shouldn't be able to tell it's a trap.

**Parameters:**
- Every error page imitates **nginx**, and the server header says `Server: nginx`.
- FastAPI's tell-tale pages (`/docs`, `/redoc`, `/openapi.json`) are switched off.
- The data is synthetic but plausible: users, shipments, orders.

**Do:** open `http://127.0.0.1:8081`, then `http://127.0.0.1:8081/admin`, then `http://127.0.0.1:8081/docs`.

**Expected:**
1. The TransNova Logistics homepage.
2. The "Administration console" login.
3. A plain **404 Not Found — nginx** page.

**Say:** "To an attacker it's an ordinary logistics portal on nginx. Nothing reveals it's Python, or a honeypot."

---

## Case K — It can't escape (isolation)

**What you're testing:** even a fully compromised decoy is stuck in a sealed box.

**Parameters (Docker):**

| Check | Exact setting | Stops |
|---|---|---|
| No internet | Lab network `internal: true` | Downloading tools, phoning home |
| No route to your PC | `com.docker.network.bridge.inhibit_ipv4: "true"`, so no default route | Attacking other services on the host |
| Not admin | Runs as user **10001** | Root-level actions |
| No special powers | `cap_drop: [ALL]`, so `CapEff=0000000000000000` | Network/system tricks |
| Can't gain powers | `no-new-privileges:true` | Privilege escalation |
| Can't change itself | `read_only: true` (only `/data` is writable, for the log) | Planting a backdoor in the app |
| Resource caps | 256 MB memory, 128 processes; auto-restart if it crashes | Taking down the host; staying down |

Run from the top `PS4---DJS` folder:
```bash
Get-Content services/web/scripts/isolation_check.py | docker compose -f docker-compose.web.yml exec -T web-decoy python -
```
**Expected** (from your Windows machine):
```
PASS  no egress to 1.1.1.1:443: OSError (Network is unreachable)
PASS  no egress to 8.8.8.8:443: OSError (Network is unreachable)
PASS  no external DNS: gaierror
PASS  no default route: none
INFO  collector:8000 reachable=False (gaierror (Temporary failure in name resolution))
PASS  not root: uid=10001
PASS  no effective capabilities: CapEff=0000000000000000
PASS  no-new-privileges: NoNewPrivs=1
PASS  read-only app filesystem: OSError
RESULT: ALL PASS
```
The `INFO collector` line is expected: no collector is running.

**Optional live proof.** Each command is something an attacker would try after breaking in.

Check which user it runs as:
```bash
docker compose -f docker-compose.web.yml exec web-decoy id
```
→ `uid=10001(decoy)`

Try to modify the app:
```bash
docker compose -f docker-compose.web.yml exec web-decoy touch /app/hacked.txt
```
→ `Read-only file system`

Try to reach the internet:
```bash
docker compose -f docker-compose.web.yml exec web-decoy python -c "import socket; socket.create_connection(('1.1.1.1',443),3)"
```
→ `Network is unreachable`

**Say:** "A sealed glass room. Even if an attacker took over the app completely, they'd be a powerless user, with no door to the internet or to my laptop, unable to change anything inside."

---

## After the demo

Stop the isolated container:
```bash
docker compose -f docker-compose.web.yml down
```
Clean up the test files:
```bash
CleanFiles
```
Then press **Ctrl + C** in Window 1.

## For a 5-minute slot
Run **A → B → C → D → E → J → K**. Keep **F, G, H, I** ready for judge questions such as "what if someone floods it?" or "can they fake their IP?".

## If an output differs
1. Is the version still `0.10.0`?
2. Did you rehearse within the last 60 s? If so, restart Window 1 and run `ClearLog`.
3. Are you in `services\web` (for `big.txt`, `avatar.jpg`, `jar.txt`)?

If it still differs, copy the exact output and compare it with the "Expected" block.

## OWASP Top 10

Mapping for both the 2021 and 2025 editions, with the protection and the test for each category: `services/web/OWASP.md`.
**Note:** the container (Case K) serves **HTTPS only**, with a certificate generated fresh at each start. The local run
in Cases A–J stays plain HTTP on `127.0.0.1`, which is why every command above uses `http://127.0.0.1:8081`.

## Honest limits (say them before you're asked)
- It isn't connected to the team dashboard yet; the integrator hasn't built it.
- Detection is pattern-based, so heavily disguised attacks can slip past.
- Counters live in memory and reset on restart.
- The slow-header cutoff (Case H) leaves no log entry.
- It's built for an isolated lab, not the public internet.
