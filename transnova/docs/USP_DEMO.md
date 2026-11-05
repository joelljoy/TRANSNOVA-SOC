# USP demo: how to check each one works (and what to say)

Setup: the two-laptop setup from `docs/TWO_LAPTOP_SETUP.md` (or everything on one laptop). The examples below use
`H_IP` = the honeypot laptop and attack from **a third device or the dashboard laptop's browser**. Single-laptop rehearsal:
replace `H_IP` with `127.0.0.1`. The main site still needs `BLOCKLIST_URL` and `BLOCKLIST_TOKEN` (see Step 7 of the setup guide).

Honeypot `0.10.0`. Decoy login `j.miller` / `TransNova#Spring26`.

---

## USP 6: adaptive deception (the bait appears only for attackers)
**Idea:** ordinary visitors see a normal portal. Once a source shows attack intent, the portal quietly shows it one extra link
(a "nightly ERP replica export"). Nobody else is ever shown it, so opening it is a near-certain attacker signal.

1. Open `http://H_IP:8081/` in a fresh browser: the **Systems** box has **no** export link.
2. Show intent: search for `1' OR '1'='1` (or try 5 wrong passwords, or open `/download?file=../../etc/passwd`).
3. Reload `http://H_IP:8081/`: the Systems box now shows **"Nightly ERP replica export (ops): erp-replica-2026-10-31.sql"**.
   It also shows up on `/status` and in search results.
4. Click it: a fake SQL dump with fake credentials downloads.
5. Dashboard: alert **W-ADAPT-01 Adaptive bait taken (high)**, technique T1213, Engage *Lures* + *Decoy Content*.

**Prove it's per-attacker:** from another device, `http://H_IP:8081/backup/erp-replica-2026-10-31.sql` returns **404**.

Terminal version (PowerShell, from any hotspot device):
```bash
curl.exe -s -o NUL "http://H_IP:8081/search?q=1'%20OR%20'1'='1"
```
```bash
curl.exe -s http://H_IP:8081/ | Select-String "erp-replica"
```
✅ One line containing `erp-replica-2026-10-31.sql`.
```bash
curl.exe -s -o NUL -w "%{http_code}`n" http://H_IP:8081/backup/erp-replica-2026-10-31.sql
```
✅ `200` (from the device that showed intent). From any other device, `404`.

**Say:** "The decoy adapts. It baits only people who already attacked it, so this alert has essentially no false positives."

## USP 1: the honeypot protects the real site (Response)
**Idea:** detection alone isn't enough. When the honeypot catches someone with a zero-false-positive signal (decoy login used,
or adaptive bait taken), the SOC blocks them on the **real** TransNova website automatically.

1. Before: `http://H_IP:8088/` opens normally from the attacker device.
2. Trigger: log in to the portal with `j.miller` / `TransNova#Spring26` (or finish USP 6 step 4).
3. Within ~5 seconds, reload `http://H_IP:8088/`: **"Access restricted. Your connection was refused by our security policy."**
   It deliberately doesn't say "honeypot".
4. Dashboard → **Response** (left menu): the attacker IP, "Automatic: W-AUTH-04", expiry in 24 h, and the history.
   The alert page has a **Response on the real site** panel with **Lift block** / **Block on main site** buttons.
5. Click **Lift**. Within ~5 s the main site works again for that device.
6. Manual block: Response page → "Block an address by hand" → any IP.

Terminal check from the attacker device:
```bash
curl.exe -s -o NUL -w "%{http_code}`n" http://H_IP:8088/
```
✅ `200` before, `403` after the decoy login.

**Safety notes:**
- Only W-AUTH-04 and W-ADAPT-01 block automatically (`AUTO_BLOCK_RULES` on the collector). One wrong password never blocks anyone.
- If your laptop goes offline, the main site keeps the last list, so an attacker can't unblock themselves by cutting the link.
- Blocks expire (`BLOCK_TTL_S`, 24 h by default).
- The feed needs the web token.

**Say:** "Deception, then detection, then response: the moment someone touches the bait, the real business is protected from them."

## USP 2: ATT&CK + MITRE Engage on every alert
**Idea:** ATT&CK says *what the attacker did*. MITRE Engage (MITRE's deception framework) says *which of our deceptions exposed it*.

1. Open any alert, e.g. W-AUTH-04.
2. Under **MITRE ATT&CK mapping**: Tactic → Technique (T1078 Valid Accounts) ← Rule.
3. Below it, under **Which deception exposed it**: *Decoy Credential (Expose · Detect)*, *Decoy Account (Elicit · Motivate)*.
4. The **Response** page shows the block itself as Engage *Security Controls (Affect · Prevent)*.

Activity names and goals follow https://engage.mitre.org/matrix/. We don't show Engage IDs because we couldn't verify them from an authoritative source.

**Say:** "Every alert answers two questions: what technique, and which deception caught it. That's how a deception programme proves its value."

## USP 5: export to MITRE's own tool
1. Dashboard → **MITRE ATT&CK** → **Download Navigator layer** (top right). A `transnova-attack-layer-<date>.json` file downloads.
2. Open https://mitre-attack.github.io/attack-navigator/ → **Open Existing Layer** → **Upload from local** → pick the file.
   This needs internet on the laptop that opens it.
3. The observed techniques appear shaded on the official ATT&CK matrix, with event counts as scores and the rules in comments.

**Say:** "This isn't a closed toy: any real SOC can load our findings into MITRE's own Navigator."

---

## Full 3-minute demo order
1. The main site is a real company site (track `TNL50211`).
2. Follow the footer **Partner portal** link (or `/admin`): the honeypot.
3. SQL injection in the search box → dashboard alert W-SQLI-01 + ATT&CK/Engage cards (**USP 2**).
4. Reload the portal: the bait appears (**USP 6**). Open it: W-ADAPT-01 high.
5. Reload the main site: **403** (**USP 1**). Show the Response page and lift the block.
6. MITRE page → heatmap → **Download Navigator layer** (**USP 5**).

## If something doesn't happen
| Symptom | Check |
|---|---|
| No bait after the SQLi | Did the search actually reach the honeypot (an event on the dashboard)? Reload `/` or `/status`. The bait shows only to the same IP |
| Main site never blocks | Main-site window needs `BLOCKLIST_URL=http://D_IP:8000/api/blocklist/feed` and `BLOCKLIST_TOKEN`; the collector needs `WEB_INGEST_TOKEN_FILE`. On the honeypot laptop, `curl.exe -s http://127.0.0.1:8088/healthz` → `soc_blocklist.last_error` |
| Everyone is blocked | You attacked from the honeypot laptop itself (127.0.0.1). Lift it on the Response page and attack from another device |
| Navigator file won't open | Use "Open Existing Layer" → "Upload from local", not "Create New Layer" |
