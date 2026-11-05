# SSH honeypot: handoff (PS04)

Owner component: the **Cowrie SSH decoy plus its collector**.

> **Integrated use:** this component now lives in `services/ssh` and runs from `docker-compose.isolated.yml` (project `soc-ssh-isolated`), on its own internal network with no published port. It is not connected to the shared SOC yet. Sensor identity is `ssh-01`. Tried passwords are not recorded. Commands below that use `docker compose ... collector`, `dev-receiver` or `127.0.0.1:2222` describe the original standalone project. See [docs/safety-and-isolation.md](docs/safety-and-isolation.md#what-is-stored-about-attacker-input).

The Web and DB honeypots, the shared SOC backend, the dashboard, the Demo Attacker module and cross-honeypot correlation are **not** part of this component. **Nothing is integrated** with a shared backend yet.

Last reviewed: 2026-11-01, on Windows 11 with Docker Desktop 29.8. Each item below says whether it was checked live, with fixtures or synthetic tests, or not at all.

## 0. Deployment prerequisites (NOT done; required before any team-network demo)

1. **Run the decoy on a Linux Docker Engine host that has no personal or sensitive services.**
   - On Docker Desktop, a process that compromised Cowrie could reach the host's TCP services, including ones bound to 127.0.0.1, plus the internet and other compose networks by IP (see §5).
2. **Apply and test the host firewall rules** in [docs/deployment.md](docs/deployment.md#host-firewall-honeypot-laptop-linux): `DOCKER-USER` plus `INPUT` on `br-ps04-decoy`.
   - They are written but **have never been executed**.
   - **The host firewall is not fixed.** It cannot be applied from the Windows host on this Docker Desktop machine.
3. Bind only to the private team network: `COWRIE_BIND_ADDR=<private LAN IP>`, never `0.0.0.0` or a public address.
4. Check that `source_ip` shows the attacker laptop's real IP. Docker Desktop masks it.
5. Use a generated `SOC_INGEST_TOKEN` and never commit it. The real backend must require it.

## 1. Start it

```bash
cp .env.example .env            # optional: COWRIE_BIND_ADDR / COWRIE_SSH_PORT / COWRIE_SENSOR_NAME
docker compose up -d --build    # cowrie + collector; decoy on 127.0.0.1:2222 by default; HTTP sink off
```

Optional local stand-in for the backend (**not** the SOC backend). Under compose it refuses to start without a token:

```bash
export SOC_INGEST_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(24))")   # shell only, not a file
SOC_INGEST_URL=http://dev-receiver:8088/ingest docker compose --profile dev up -d --build
```

## 2. Verify it

All steps were run live on 2026-11-01 against the localhost decoy with the host's OpenSSH client:

| Check | Command | Expected (observed) |
|---|---|---|
| Containers up | `docker compose ps` | `cowrie` and `collector` running; `127.0.0.1:2222->2222/tcp` |
| Config loaded | `docker compose logs cowrie \| grep -E "Reading configuration\|Ready"` | `Reading configuration from ['/etc/cowrie/cowrie.cfg']`, `Ready to accept SSH connections` |
| Failed login | `ssh -p 2222 root@127.0.0.1` (any password) | `Permission denied (publickey,password)` |
| Decoy login | `ssh -p 2222 backup@127.0.0.1`, password `Backup@2024` (synthetic) | Shell as `backup@bkp-db-01`. `ls -a /var/backups/db` shows `.my.cnf  README  mysql_nightly.sh`. Plain `ls` hides `.my.cnf`, as a real shell does |
| Events flowing | `docker compose exec collector tail -n 3 /data/state/normalized.jsonl` | JSON records with `"source_service":"ssh"`, `"sensor_id":"cowrie-ssh-01"` |
| Queue healthy | `docker compose exec collector cowrie-soc status --config /app/config/collector.toml` | Every sink `pending: 0`, `dead_letters: 0`, `quarantined: 0` |
| Tests | `cd collector && python -m pytest -q` | `144 passed` (none of them live; see §7) |

On Git Bash for Windows, prefix `docker compose exec … /abs/path` with `MSYS_NO_PATHCONV=1`.

## 3. Collection and event output

**Collection.**
- Cowrie writes its own JSON log (`cowrie.json`, rotated daily by rename).
- The collector reads it read-only from a shared volume, using byte-offset checkpoints and a first-line fingerprint so it can follow rotation.
- Each line is validated. Invalid or wrong-typed lines are quarantined, never dropped silently.
- Each line is normalized, run through the detection rules, and stored with its checkpoint in one SQLite transaction.
- Delivery is at-least-once to `normalized.jsonl` and, if `SOC_INGEST_URL` is set, to HTTP.

**HTTP body.** `{"source":"cowrie-ssh","sensor_id":…,"sent_at":…,"count":N,"records":[…]}`. A real example is in [docs/examples/envelope-example.json](docs/examples/envelope-example.json).

| Record | Schema | Key fields |
|---|---|---|
| `event` `ps04.event.v0.1` | [docs/schema/event.schema.json](docs/schema/event.schema.json) | `event_id`, `timestamp` (Cowrie's, UTC), `ingested_at`, `source_service:"ssh"`, `source_product:"cowrie"`, `sensor_id`, `source_ip`, `source_port`, `session_id`, `event_type`, `category`, `outcome`, `username`, `password`, `command`, `attack[]`, `details`, `raw` |
| `finding` `ps04.finding.v0.1` | [docs/schema/finding.schema.json](docs/schema/finding.schema.json) | `finding_id`, `rule_id`, `severity`, `confidence`, `attack[]`, `evidence.event_ids`, `evidence.observed`, `explanation`, `session_ids`, `source_ip` |

Field details that matter for integration:

- **`event_id`** is a UUIDv5 of the SHA-256 of the raw Cowrie line. It is stable across re-processing (verified live: replay produced identical IDs).
  - De-duplicate on `event_id` and `finding_id`, never on `ingested_at`.
- **Sensor identity.**
  - `sensor_id` comes from the **collector's** setting (`COWRIE_SOC_SENSOR_ID`).
  - Cowrie's own `sensor` value is kept in `raw.cowrie_sensor`.
  - Compose sets both from `COWRIE_SENSOR_NAME`, so they match unless the collector is run separately with a different value.
- **Null handling.** Fields Cowrie doesn't provide are `null`:
  - `username` is only on authentication events, so join on `session_id` for commands.
  - `command` is only on command events.
  - `password` is always null: tried passwords are not recorded.
  - `outcome` is only set where Cowrie states it.
  - One exception: `protocol` defaults to `"ssh"` if a line lacks it. Every observed Cowrie line had it.
- **`source_ip`** is the address Cowrie saw. On Docker Desktop it is the bridge gateway (e.g. `172.19.0.1`), not the attacker.
- **Untrusted text.** `command`, `username`, `password`, `message`, `details` and `raw` contain attacker-controlled text. Escape and parameterize them; never interpret them.

## 4. Detection capabilities

There are 8 rule-based, configurable rules, run in the collector ([docs/detections.md](docs/detections.md)). ATT&CK is mapped only from the observed evidence:

| Rule | Fires on | Default severity | ATT&CK |
|---|---|---|---|
| SSH-BRUTE-001 | ≥5 failed logins from one source IP in 60 s (one finding per episode) | medium | T1110, because tried passwords are not recorded |
| SSH-AUTH-002 | Any login to the decoy; escalated if ≥3 failures from that IP in 600 s | medium → high | T1078; escalated adds T1110 |
| SSH-EXEC-001 | First command in a session | low | T1059.004 |
| SSH-DISC-001 | ≥3 (medium) / ≥5 (high) distinct discovery techniques in one session within 300 s | medium / high | The observed subset of T1082, T1033, T1087.001, T1083, T1016, T1049, T1057 |
| SSH-CRED-001 | Read of a honeytoken file (critical), `/etc/shadow` (T1003.008) or a credential-named file | critical / high | T1552.001, T1003.008 |
| SSH-TOOL-001 | `wget`/`curl`/`tftp`/`ftpget` with a URL, or a Cowrie download event | high | T1105 |
| SSH-SEQ-001 | Download → `chmod +x` → execute of the same file in one session | critical | T1105, T1222.002, T1059.004 |
| SSH-EVADE-001 | History clearing or disabling (`history -c`, `HISTFILE=`, `HISTSIZE=0`, …) | high | T1070.003 |

Each `shell_command` event also carries per-command ATT&CK tags in `attack[]`.

This is **not** full ATT&CK coverage. Known misses:
- `sh -c '…'` and `bash -c`
- glob tricks (`/bin/c?t`)
- base64-encoded commands
- `curl | sh` as a sequence

Detection state is held in memory. A collector restart can repeat or miss a threshold finding; events are unaffected.

## 5. Security limitations

| Item | Status |
|---|---|
| Emulated commands cannot open network connections (`out_addr=127.0.0.1`); SSH forwarding and telnet are off | Verified live |
| Containers are non-root, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, no host bind mounts, no Docker socket | Verified (`docker inspect`) |
| The decoy container holds no real secrets. Its environment is only the sensor name. Decoy files contain **synthetic** credentials by design | Verified |
| **Docker Desktop: a process inside Cowrie reached 12 of 13 probed host TCP listeners through `host.docker.internal`, including 127.0.0.1-only ones** (mongod 27017, mysqld 3307, SMB 445, RPC 135, TeamViewer 5939, Edge debug 9222, dev receiver 8088, …; only NetBIOS on 192.168.56.1 refused). It also reached the internet (1.1.1.1:443) and the dev receiver on the other compose network by IP | Verified 2026-11-01 with plain-socket probes (what a Cowrie compromise could do; the emulated shell cannot) |
| Dev receiver requires the token for `/ingest` and `/records` and exits (code 2) if `--token-env` is set but empty, as it is under compose | Verified live: 401 to the decoy, exit 2 without a token. Run by hand **without** `--token-env`, it has no auth |
| Credentials and query strings in the ingest URL are removed from log messages | Unit-tested |
| Linux `DOCKER-USER` + `INPUT` firewall rules that close the reachability above | **Written, never executed. Deployment prerequisite (§0)** |
| Attacker IP masked on Docker Desktop | Verified |

## 6. What teammates need

**Backend teammate.** Details are in [docs/integration-contract.md](docs/integration-contract.md), including an 11-item checklist. Please provide:
- the exact ingest URL (redirects are not followed; a 3xx is retried and logged)
- a **required** token
- the accepted body shape and field names
- the status codes for retry (5xx/429) vs reject (400/422)
- de-duplication on `event_id` and `finding_id`
- whether you want findings or only events
- size and rate limits

The SSH side then needs only `SOC_INGEST_URL`, `SOC_INGEST_TOKEN` and possibly a `field_map`. No endpoint has been assumed.

**Web and DB teammates.** To make the three honeypots line up, agree on:
- `source_service` values (SSH uses `ssh`; proposed `web`, `db`)
- a `sensor_id` per instance
- UTC ISO-8601 `timestamp`
- a stable, deterministic `event_id`
- the shared `event_type` names (`authentication_failure`, `authentication_success`, `session_closed`, …)
- `null` for unknown values, plus a `raw` copy of the original log record

The proposed common/SSH-specific field split is in the contract doc. Whether SQL queries reuse `command` or `details.query` is still open.

## 7. What remains unverified

- **The firewall rules** (§0) and Cowrie on a Linux Docker host.
- **The multi-laptop LAN test,** including the real attacker IP in `source_ip`.
- **Integration with the real backend** (it does not exist). HTTP delivery was tested only against the local dev receiver, over http; https is untested.
- **Live midnight log rotation.** Only a simulated rename was tested, matching Cowrie's code.
- **Cowrie `file_download`, `file_upload` and port-forward events.** Synthetic or fixture only, because the safety settings block them live.
- **The team Demo Attacker module.** Not ready, and not used.

**Tests.** 144 automated tests:
- 19 fixture-based, using 104 real Cowrie events captured on 2026-10-31
- 120 synthetic
- 5 docs/contract checks
- **0 live**

The live checks (SSH sessions, delivery, probes) were run manually during the reviews and are listed above.
