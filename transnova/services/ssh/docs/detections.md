# SSH detections and ATT&CK mapping

All rules live in `collector/src/cowrie_soc/detection.py` and are configured in
`collector/config/collector.toml` under `[detection.<config key>]`. Every rule can be
disabled with `enabled = false`; unknown keys or invalid severities are rejected at startup.

Rules run on **normalized events**, and every finding carries:

- `evidence.event_ids`: the supporting events (up to 50)
- `evidence.observed`: the values the rule saw
- `evidence.window_seconds` and `evidence.threshold`: the limits that applied
- `severity`, `confidence`, `attack[]`, a plain-language `explanation`, and a `recommended_action`

The recommended action is advisory text only. This component never blocks or responds automatically.

Time comes from event timestamps, so replaying a log gives the same findings as live processing.

## Rule summary

| Rule ID | Config key | Fires when | Default severity | ATT&CK |
|---|---|---|---|---|
| SSH-BRUTE-001 | `ssh_bruteforce` | ≥ `threshold` (5) failed logins from one source IP within `window_seconds` (60). One finding per episode; an episode ends after a failure-free gap longer than the window | medium | T1110, because tried passwords are not recorded |
| SSH-AUTH-002 | `ssh_decoy_login` | Any successful login to the decoy (the decoy has no legitimate users). Escalated when ≥ `min_prior_failures` (3) failures came from that IP within `lookback_seconds` (600) | medium → high (escalated) | T1078; escalated adds T1110 |
| SSH-EXEC-001 | `ssh_shell_activity` | First command in a session | low | T1059.004 |
| SSH-DISC-001 | `ssh_discovery` | A session uses N distinct discovery techniques within `window_seconds` (300). `levels = [[3,"medium"],[5,"high"]]` emits once per level | medium / high | Only the techniques actually observed: T1082, T1033, T1087.001, T1083, T1016, T1049, T1057 |
| SSH-CRED-001 | `ssh_credential_access` | Read of a configured honeytoken file, of `/etc/shadow`, or of a generic credential file (`.env`, `.my.cnf`, `id_rsa`, ...) | critical (honeytoken), high (others) | T1552.001; T1003.008 for shadow |
| SSH-TOOL-001 | `ssh_ingress_tool_transfer` | `wget`/`curl`/`tftp`/`ftpget` with a URL, or a Cowrie `file_download` event | high | T1105 |
| SSH-SEQ-001 | `ssh_download_execute` | Same session within `window_seconds` (300): download → `chmod +x` on the same file name → execution of it | critical | T1105, T1222.002, T1059.004 |
| SSH-EVADE-001 | `ssh_history_tampering` | `history -c`, `unset HISTFILE`, `HISTSIZE=0`, deleting or nulling `.bash_history` | high | T1070.003 |

## How command evidence is derived

`commands.py` turns each command line Cowrie logged into individual commands. It handles `;`, `&&`, `||`, `|`, quoting and redirections, removes wrappers (`sudo`, `busybox`, `nohup`, `env`, `timeout`, ...), and then compares each program and file operand against fixed tables.

This step is needed because OpenSSH exec sessions arrive as one line, for example `uname -a; cat /etc/shadow; ls -la /var/backups/db`, captured live in this lab.

Command text is untrusted attacker input. It is only tokenized and compared against those tables. It is never executed, never used as a path, and never sent to a shell or SQL. Lines that are not valid shell syntax fall back to a naive split, and `parse_fallback` is set on the event.

Each `shell_command` event also gets per-command ATT&CK tags in `attack[]`, with reasons in `details.command_analysis.indicators`. A single `whoami` is therefore visible to the SOC without raising a finding, and the aggregate rules decide when the activity is worth an alert.

| Technique | Evidence that triggers it |
|---|---|
| T1082 System Information Discovery | `uname`, `hostnamectl`, `lscpu`, `lsb_release`, `uptime`, `free`, `df`, `lspci`, ...; reads of `/etc/os-release`, `/proc/cpuinfo`, `/proc/version`, `/etc/*release` |
| T1033 System Owner/User Discovery | `whoami`, `id`, `who`, `w`, `users`, `logname` |
| T1087.001 Local Account Discovery | reads of `/etc/passwd` or `/etc/group`; `getent passwd/group`; `lastlog`, `last`, `compgen -u` |
| T1083 File and Directory Discovery | `ls`, `find`, `locate`, `tree`, `du` |
| T1016 System Network Configuration Discovery | `ifconfig`, `ip addr/route/link/neigh`, `route`, `arp`, `hostname -I`, `iptables -L`; reads of `/etc/resolv.conf`, `/etc/hosts` |
| T1049 System Network Connections Discovery | `netstat`, `ss`, `lsof -i` |
| T1057 Process Discovery | `ps`, `top`, `pstree`, `pgrep` |
| T1003.008 /etc/passwd and /etc/shadow | reads of `/etc/shadow`, `/etc/gshadow`; `unshadow` |
| T1552.001 Credentials In Files | reads of credential-bearing file names; honeytoken paths |
| T1105 Ingress Tool Transfer | downloader + URL; Cowrie `file_download(.failed)` |
| T1222.002 Linux File Permissions Modification | `chmod +x`, `chmod 7xx` (any execute bit) |
| T1059.004 Unix Shell | command execution in the emulated shell |
| T1070.003 Clear Command History | see SSH-EVADE-001 |
| T1110 / T1110.001 / T1110.003 Brute Force | authentication failures (SSH-BRUTE-001). Tried passwords are not recorded, so the rule reports the parent technique T1110. The sub-techniques need password counts and apply only if capture is enabled |
| T1078 Valid Accounts | successful login to a **decoy** account; no production account is ever involved |

## Honeytokens and path resolution

`honeytoken_paths` must match the synthetic files baked into `cowrie/decoy-fs/`:
`/var/backups/db/.my.cnf` and `/var/backups/app/.env`.

The engine tracks each session's working directory (`cd`, including `cd x && cat y` on one line) and the logged-in user's home from `[user_homes]`. Relative reads such as `cat db/.my.cnf` resolve to an exact path, which gives confidence **high**.

If the collector never saw the login (for example, it started mid-session), the engine falls back to a unique path-suffix match, which gives confidence **medium**.

## Results on real captured traffic

`cowrie-soc replay collector/tests/fixtures/real_capture_2026-10-31.json --config collector/config/collector.toml --summary` produces 14 findings from the 104 events captured from the live container. That run covered the paramiko scenarios plus one OpenSSH exec session:

```
MEDIUM   SSH-BRUTE-001  SSH brute force from 172.18.0.3: 5 failed logins in 6s  [T1110]
HIGH     SSH-AUTH-002   Decoy SSH login as 'backup' from 172.18.0.3 after 8 failed attempts  [T1110,T1078]
MEDIUM   SSH-DISC-001   Discovery burst: 3 ATT&CK discovery techniques in session 03394a5fdc06  [T1033,T1082,T1087.001]
HIGH     SSH-DISC-001   Discovery burst: 5 ATT&CK discovery techniques ...  [T1016,T1033,T1049,T1082,T1087.001]
CRITICAL SSH-CRED-001   Honeytoken credential file read: /var/backups/db/.my.cnf  [T1552.001]
CRITICAL SSH-CRED-001   Honeytoken credential file read: /var/backups/app/.env  [T1552.001]
HIGH     SSH-TOOL-001   Download attempt from http://192.0.2.10/bins/update.sh  [T1105]
CRITICAL SSH-SEQ-001    Dropper sequence: download -> chmod +x -> execute 'update.sh'  [T1105,T1222.002,T1059.004]
MEDIUM   SSH-AUTH-002   Decoy SSH login as 'backup' from 172.18.0.1  [T1078]
HIGH     SSH-CRED-001   Credential material accessed: reads password hash file /etc/shadow  [T1003.008]
(+4 LOW SSH-EXEC-001)
```

The `benign` scenario (`date`, `uptime`, `df -h`) produces only a decoy-login finding (medium) and a shell-activity finding (low). It does not trigger a discovery burst, because it shows one discovery technique, which is below the threshold of 3.

## Limitations (honest scope)

- **Coverage.** These are rule-based detections for common SSH honeypot behavior. They do not provide full ATT&CK coverage. Known misses (checked in review on 2026-10-31):
  - glob or quoting tricks such as `/bin/c?t /etc/shadow`
  - base64-encoded commands
  - commands nested inside `sh -c '...'` or `bash -c`, which are not analyzed
  - `curl ... | sh` (download is detected, the pipe-to-shell sequence is not)
- **No passwords.** `include_passwords = false` is the project setting, so SSH-BRUTE-001 reports the parent technique T1110: guessing and spraying can't be told apart without passwords.
- **Copy destinations.** For `cp` and `scp`, the last operand is treated as a destination, not a read. So `cp .env.example .env` is not a credential access.
- **Commands that fail in Cowrie still count.** For example, `ip addr` printed "command not found" in the emulated shell but still counts as T1016 intent. The event's `shell_command_not_found` companion shows the result.
- **Correlation keys.** Brute force is correlated by source IP only. Behind NAT, several actors look like one. Each TCP connection is a separate Cowrie session, so `session_ids` lists them all.
- **No state across restarts.** Detection state is in memory and is not persisted. An episode that spans a collector restart may produce an extra or a missing finding. Events themselves are never lost.
- **No cross-service correlation.** Findings cover SSH evidence only. Correlation across SSH, web and DB belongs to the shared SOC pipeline and is **not** implemented here.
