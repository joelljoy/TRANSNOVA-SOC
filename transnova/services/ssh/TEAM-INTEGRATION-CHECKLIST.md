# PS04 team integration checklist

**Status (2026-11-01):** only the SSH honeypot exists in this repo.
- The Web honeypot, DB honeypot, shared backend and dashboard are being built separately.
- **No cross-component integration has been tested.**

Every ☐ below is an open **team decision** or task. Details for SSH: [SSH-HANDOFF.md](SSH-HANDOFF.md) and [docs/integration-contract.md](docs/integration-contract.md).

---

## 1. What SSH sends today

| Item | Current SSH behaviour |
|---|---|
| Transport | `POST $SOC_INGEST_URL`, `Content-Type: application/json`, `Authorization: Bearer $SOC_INGEST_TOKEN`. Off until a URL is set; tested only against the local dev receiver |
| Body | `{"source":"cowrie-ssh","sensor_id":"cowrie-ssh-01","sent_at":…,"count":N,"records":[…]}` (`payload_format = "array"` sends a bare list). Batches of 100 |
| Record types | `event` (`ps04.event.v0.1`) and `finding` (`ps04.finding.v0.1`). Schemas: [event](docs/schema/event.schema.json), [finding](docs/schema/finding.schema.json). Real example: [envelope-example.json](docs/examples/envelope-example.json) |
| Required event fields | `record_type`, `schema_version`, `event_id`, `timestamp`, `ingested_at`, `source_service`, `source_product`, `sensor_id`, `session_id`, `event_type`, `category`, `details`, `attack`, `raw` |
| Optional / nullable | `source_ip`, `source_port`, `dest_ip`, `dest_port`, `protocol`, `outcome`, `username`, `password`, `command`, `message`, `scenario_id` |
| Identity | `source_service: "ssh"`, `source_product: "cowrie"`, `sensor_id: "cowrie-ssh-01"` |
| IDs | `event_id` = UUIDv5 of the SHA-256 of the raw Cowrie line. Stable across re-processing (checked against live data by replay). `finding_id` = UUIDv5 of sensor, rule and key |
| Delivery | At-least-once, in order. Retries on network errors, 408/425/429/5xx and 3xx (redirects are not followed). Any other 4xx dead-letters the whole batch |
| Findings | 8 SSH rules with ATT&CK mappings, computed by the SSH collector and sent alongside events |

## 2. What the Web honeypot must provide (Web owner)

- ☐ Records in the agreed common shape (§4), with `source_service = <agreed value>` and its own `sensor_id`.
- ☐ A **deterministic** `event_id`, for example a hash of the raw log line, so re-sends can be de-duplicated.
- ☐ `timestamp` in UTC ISO-8601, taken from when the decoy observed the request (not when it was sent).
- ☐ The client IP in `source_ip`, plus a session or correlation key in `session_id`. **Decision:** what counts as a web "session" (cookie, IP + time window, request ID)?
- ☐ Login attempts mapped to the shared event names (`authentication_failure` / `authentication_success`) with `username` (and `password`, if the team keeps it).
- ☐ Request details (method, path, status, user agent) in `details`. **Decision:** promote any of them to common fields?
- ☐ The original log record in `raw`.
- ☐ The same delivery rules as SSH: auth token, retry on 5xx/429, idempotent IDs.

## 3. What the DB honeypot must provide (DB owner)

- ☐ Same common shape, `source_service = <agreed value>`, its own `sensor_id`, a deterministic `event_id`, a UTC `timestamp`, and a `raw` copy.
- ☐ Connection and authentication events mapped to the shared names, with `username` and `source_ip`.
- ☐ Queries. **Decision:** reuse `command` (as SSH does for shell lines) or use `details.query`?
- ☐ `session_id` per DB connection.
- ☐ Synthetic data only, and no real credentials.

## 4. Common vocabulary the team must agree on (all three owners + backend)

| # | Decision | SSH proposal |
|---|---|---|
| 4.1 ☐ | `source_service` values | `ssh`, `web`, `db` |
| 4.2 ☐ | `sensor_id` naming | `<product>-<service>-NN`, e.g. `cowrie-ssh-01` |
| 4.3 ☐ | Common required fields | The SSH required list in §1 |
| 4.4 ☐ | Shared `event_type` names | `authentication_failure`, `authentication_success`, `session_closed`, `file_download`, `file_upload`. Service-specific types stay distinct (SSH: `ssh_connection`, `shell_command`, …) |
| 4.5 ☐ | `category` values | `connection`, `authentication`, `command`, `session`, `file_transfer`, `network`, `client_fingerprint`, `other` |
| 4.6 ☐ | Unknown values | `null`, never guessed |
| 4.7 ☐ | Keep `password` in events? | Yes (SSH can redact via config) |
| 4.8 ☐ | Do honeypots send `finding` records, or does the backend do all detection? | SSH sends findings today |
| 4.9 ☐ | ATT&CK format | `attack: [{technique_id, name, tactic}]` |
| 4.10 ☐ | `schema_version` naming once the schema is final | `ps04.event.v0.1` |

## 5. Backend ingest questions (backend owner)

None of these are decided. SSH has **not** assumed any of them.

| # | Question | Notes |
|---|---|---|
| 5.1 ☐ | Ingest URL: host or IP on the team LAN, port, **exact path including any trailing slash** | SSH does not follow redirects. A 3xx is logged and retried |
| 5.2 ☐ | Authentication scheme and how tokens are issued (one per sensor, or shared) | **Must be required.** A compromised decoy could reach an open endpoint |
| 5.3 ☐ | Payload shape: envelope or bare array; field names | SSH can rename top-level fields with `field_map` |
| 5.4 ☐ | Success response | SSH treats any 2xx as "whole batch accepted" |
| 5.5 ☐ | Retry codes | SSH retries 5xx, 429, 408, 425 |
| 5.6 ☐ | Reject codes | SSH dead-letters the **whole batch** on other 4xx. Is per-record rejection needed? |
| 5.7 ☐ | De-duplication key | Upsert on `event_id` / `finding_id`; never on `ingested_at` |
| 5.8 ☐ | Limits: max body size, batch size, rate limit | SSH default batch is 100 |
| 5.9 ☐ | TLS: http on the isolated LAN, self-signed, or a real certificate | SSH https is untested |
| 5.10 ☐ | Ordering | Order the timeline by `timestamp`; there is no ordering guarantee across sensors |
| 5.11 ☐ | NTP on all laptops | Needed for cross-sensor timelines |

## 6. Integration tests (run once all three honeypots and the backend exist)

**None of these have been run yet.** Record the date, the commands and the results for each.

| # | Test | Pass condition |
|---|---|---|
| 6.1 ☐ | Each sensor delivers to the backend | Backend count = sensor's local record count. SSH check: `cowrie-soc status` shows `http` `pending: 0`, `dead_letters: 0` |
| 6.2 ☐ | Schema conformance | Every stored record from SSH, Web and DB has the agreed common fields and `source_service` values |
| 6.3 ☐ | Auth enforced | Request without or with a wrong token → 401/403, nothing stored |
| 6.4 ☐ | De-duplication | Re-send the same batch (or restart a collector) → no duplicate rows |
| 6.5 ☐ | Backend outage | Stop the backend, generate traffic, restart it → all records arrive, none duplicated |
| 6.6 ☐ | Bad URL / redirect | Wrong path → SSH logs the 3xx/4xx and keeps records queued; after fixing the URL they arrive |
| 6.7 ☐ | Real attacker IP | From the attacker laptop, `source_ip` on SSH, Web and DB events equals the attacker laptop's LAN IP (not a Docker gateway) |
| 6.8 ☐ | End-to-end attack story | One scripted run across SSH, Web and DB (from the Demo Attacker once it's ready) appears in the dashboard timeline in correct time order |
| 6.9 ☐ | Detection evidence | A finding's `evidence.event_ids` resolve to stored events in the backend |
| 6.10 ☐ | Cross-service correlation | Only if the backend implements it; otherwise report it as not implemented |

## 7. Security prerequisite (separate gate before ANY network deployment)

**Owner:** whoever prepares the honeypot laptop, together with the SSH owner. **Status: NOT done.**

- ☐ The honeypot laptop runs **Linux Docker Engine** and has **no personal or sensitive services**.
  - Reason: on Docker Desktop (Windows) we verified that a process inside the Cowrie container could reach 12 of 13 probed host services, including 127.0.0.1-only ones, plus the internet and other compose networks by IP.
- ☐ Apply the `DOCKER-USER` and `INPUT` rules for `br-ps04-decoy` from [docs/deployment.md](docs/deployment.md#host-firewall-honeypot-laptop-linux). They are written but **have never been executed**.
- ☐ Verify with the plain-socket probe in that doc. Every target must show `timeout`, and SSH from the attacker laptop must still work.
- ☐ Decoys bind only to the private team LAN IP (`COWRIE_BIND_ADDR`), never `0.0.0.0` or a public address.
- ☐ Backend ingest requires a token. Tokens are generated, kept out of git, and never placed in decoy containers.
- ☐ The Web and DB decoys get equivalent isolation (non-root, no host mounts, egress blocked, synthetic data only). **Their owners must confirm.**
