# Integration boundary: Cowrie SSH component → shared SOC backend

**Status: NOT INTEGRATED.** Attacker input is now cleaned before storage, so some fields below hold less than this contract first described. See [safety-and-isolation.md](safety-and-isolation.md#what-is-stored-about-attacker-input).

The team's common schema and backend endpoint did not exist when this component was built. Nothing here assumes or invents the backend API.

The component works on its own, writes JSONL locally, and has a configurable HTTP sink. That sink has only been tested against this repo's **local dev receiver** and test stubs.

## What this component outputs

There are two record types, both JSON objects with `record_type` and `schema_version`:

| Record | Schema | Purpose |
|---|---|---|
| `event` (`ps04.event.v0.1`) | [schema/event.schema.json](schema/event.schema.json) | One normalized Cowrie event. The original Cowrie JSON is kept verbatim in `raw.event`, with `raw.sha256` and the file name and byte offset in `raw.ref` |
| `finding` (`ps04.finding.v0.1`) | [schema/finding.schema.json](schema/finding.schema.json) | One explainable detection, which references its evidence by `event_id` |

Examples generated from the real capture are in [examples/sample-records.jsonl](examples/sample-records.jsonl). That file has one event per event type plus all findings, so some referenced `event_id`s are not included in the sample.

The event fields follow the project-level handoff proposal (`event_id`, `timestamp`, `source_service`, `sensor_id`, `source_ip`, `source_port`, `session_id`, `event_type`, `category`, `raw_event_ref` → `raw.ref`, `details`, `scenario_id`) plus SSH fields (`username`, `password`, `command`). This is a proposal for the team to accept, rename or replace.

Key properties the backend can rely on:

- **Stable identifiers.**
  - `event_id` is a UUIDv5 of the raw log line's SHA-256.
  - `finding_id` is a UUIDv5 of the sensor, rule and detection key.
  - Re-deliveries carry the same IDs, so the backend should upsert or de-duplicate on them.
- **At-least-once delivery, in order.** Records are stored in a durable outbox before sending. A batch is re-sent until it gets a 2xx response.
- **No silent loss.**
  - Lines that fail validation are kept in the collector's quarantine table.
  - Batches the backend permanently rejects (4xx other than 408/425/429) go to a dead-letter table.
  - If the backend is down, ingestion pauses once `max_pending_records` is reached. Cowrie keeps writing to its own log in the meantime.
- **Untrusted content.** `command`, `username`, `password`, `message` and everything in `details` and `raw` contain attacker-controlled text. The backend and dashboard must treat them as data: escape them in HTML, parameterize SQL, and never interpret them.
- **Timestamps.** All timestamps are ISO-8601 UTC. `timestamp` is when Cowrie observed the event; `ingested_at` is when the collector processed it.
- **Source IP.** `source_ip` is the address Cowrie saw. See the NAT caveat in [deployment.md](deployment.md).
- **Findings are sensor-side.** The backend may display them, re-score them, or ignore them and run its own rules on the events.

## Field classification for the shared schema

This is a proposal for the team. The SSH component already emits all of these fields. The Web and DB owners can map their logs onto the "common" set.

**Common fields** (meaningful for any honeypot; present on every SSH event, null when unknown):

| Field | Type | Notes |
|---|---|---|
| `record_type` | `"event"` / `"finding"` | |
| `schema_version` | string | `ps04.event.v0.1` |
| `event_id` | UUID string | Stable de-duplication key (see below) |
| `timestamp` | ISO-8601 UTC | When the honeypot observed it |
| `ingested_at` | ISO-8601 UTC | When the collector processed it; **differs on re-processing**, so never use it for de-duplication |
| `source_service` | string | Honeypot type: `ssh` for this component |
| `source_product` | string | `cowrie` |
| `sensor_id` | string | Instance name |
| `source_ip`, `source_port` | string / int / null | Client address as seen by the honeypot |
| `dest_ip`, `dest_port` | string / int / null | Decoy address inside Docker |
| `protocol` | string | `ssh` |
| `session_id` | string | Honeypot session; Cowrie uses one per TCP connection |
| `event_type`, `category`, `outcome` | string / null | The vocabulary needs team agreement; see below |
| `username`, `password` | string / null | Login attempts. Probably shared with web and DB logins |
| `message` | string / null | Human-readable line from the honeypot |
| `attack` | list | ATT&CK techniques supported by this event's evidence |
| `details` | object | Product-specific extras |
| `raw` | object | Original record, `sha256` and `ref` (evidence) |
| `scenario_id` | string / null | Optional lab correlation hint |

**SSH-specific content** (must remain, but can live in `details` if the team prefers a smaller common core):

- `command`: the exact line typed in the emulated shell. A DB honeypot's SQL query is the closest analogue, so the team should decide whether it shares this field or uses `details.query`.
- `details.command_analysis`: the programs and ATT&CK indicators per command.
- `details.client_version`, `details.hassh`: SSH client fingerprint.
- `details.ttylog`, `details.duration_ms`, `details.size`, `details.width`/`height`: session metadata.
- `raw.format = "cowrie-json"` and `raw.cowrie_eventid`.
- SSH-only `event_type` values: `ssh_connection`, `client_version`, `client_kex`, `publickey_offered`, `terminal_size`, `client_env_var`, `session_params`, `shell_command`, `shell_command_not_found`, `port_forward_*`, `tty_log_closed`.
  - Generic values that other honeypots could reuse: `authentication_failure`, `authentication_success`, `session_closed`, `file_download`, `file_upload`.

**Fields that are null by design** (never filled in or guessed):

- `username` is only set on authentication events. Cowrie does not log the user on `command.input`, so join on `session_id`.
- `command` is only set on command events.
- `password` is always null: tried passwords are not recorded.
- `details.ttylog` and session recordings are absent: recording is off.
- `outcome` is only set where Cowrie states it.

## ID stability (de-duplication)

- `event_id = UUIDv5(fixed namespace, "cowrie-event" + SHA-256(raw log line))`.
- Verified on 2026-10-31: re-processing the live `cowrie.json` with `cowrie-soc replay` produced the **identical** set of 274 `event_id`s as the running collector.
- These IDs are unique to this sensor's log lines, because each Cowrie line includes a microsecond timestamp, the session ID and the sensor name.
- `finding_id = UUIDv5(namespace, "cowrie-finding", sensor_id, rule_id, key)` is stable for the same detection.
  - However, findings depend on in-memory detection state. In the same comparison, 36 of 37 live findings matched the replay. The extra live finding was a decoy-login alert emitted just after a collector restart, which an uninterrupted run would have suppressed as a repeat login.
  - So the backend should de-duplicate findings by `finding_id`, but must not assume the set of findings is identical across restarts.

## Envelope example

[examples/envelope-example.json](examples/envelope-example.json) is a real batch. It was produced by the collector's `EnvelopeEncoder` from live records captured on 2026-10-31: an `authentication_failure` event, a `shell_command` event and a finding.

```json
{"source": "cowrie-ssh", "sensor_id": "cowrie-ssh-01", "sent_at": "...", "count": 3, "records": [ ... ]}
```

Source identification exists at two levels: the envelope's `source` (`cowrie-ssh`) and each record's `source_service` (`ssh`), `source_product` (`cowrie`) and `sensor_id`.

**Proposed SSH identifier: `source_service = "ssh"`.**
- Each record is self-describing even if the backend un-batches the envelope.
- The proposal for the team is `ssh`, `web`, `db` (or `database`) as the honeypot types, with `sensor_id` for individual instances.

## Event source identification

Each record says which honeypot produced it, without relying on the network path:

| Field | Value from this component | Meaning |
|---|---|---|
| `source_service` | `ssh` | Honeypot type. Web and DB components would use their own values; the team should agree the vocabulary |
| `source_product` | `cowrie` | Software that produced the raw log |
| `sensor_id` | `cowrie-ssh-01` (`COWRIE_SENSOR_NAME`) | The specific sensor instance |
| `raw.format` | `cowrie-json` | Format of `raw.event` |
| Envelope `source` | `cowrie-ssh` | Sender of the HTTP batch |

`source_ip` is the client address Cowrie saw (`src_ip`), or null when Cowrie did not record one. Fields Cowrie doesn't provide for an event type are null and never filled in. For example, `username` is null on connect events, and `command` is null on everything except command events.

## Transport (HTTP sink)

**Superseded for the shared SOC by [canonical-mapping.md](canonical-mapping.md).** Delivery to the shared collector sends validated canonical events as a plain JSON array of at most 50, from `soc_outbox` only, and never dead-letters. Its token, responses and strict checks are under "What the collector requires" there. The envelope, `field_map` and retry notes below describe the original standalone project. Delivery is off.

The HTTP sink is enabled only when a URL is configured, through `COWRIE_SOC_HTTP_URL` or `SOC_INGEST_URL` in `.env` for compose, or `[sinks.http]` in `collector.toml`.

- `POST <url>`, `Content-Type: application/json`, optional `Authorization: Bearer $COWRIE_SOC_HTTP_TOKEN`.
- Body when `payload_format = "envelope"` (the default):
  `{"source":"cowrie-ssh","sensor_id":"...","sent_at":"...","count":N,"records":[...]}`
- Body when `payload_format = "array"`: `[record, ...]`
- Batch size defaults to 100, with a 5 s timeout.
- **Success** is any 2xx.
- **Retry** with exponential backoff from 1 s up to 60 s happens on network errors, timeouts, and 408, 425, 429 and 5xx responses.
- **Dead-letter** applies to any other 4xx.
- `field_map` renames top-level fields, for example `{ source_ip = "src_ip" }`, so the output can match the team schema without code changes. For deeper changes, add an `Encoder` in `collector/src/cowrie_soc/encoders.py`. That file is the only place a schema change should need code.

### Expected response

- Any **2xx** means the whole batch was accepted. The response body is read but ignored, so the backend may return anything, for example per-record results.
- The backend should return **5xx, 429 or 503** when it is temporarily unable to store a batch. The collector will retry.
- The backend should return **400 or 422** only when the request itself is wrong. The collector dead-letters the **entire batch** and does not retry.

### Authentication requirement

The backend **must** require a secret, for example `Authorization: Bearer <token>`. Leaving the endpoint open is not acceptable.

The review on 2026-10-31 verified that a process inside the Cowrie container can reach services published on the host. An unauthenticated ingest endpoint would therefore let a compromised decoy inject forged events.

The token is passed only to the collector container (`SOC_INGEST_TOKEN`), never to Cowrie.

### Delivery limitations (current implementation)

- **Batch-level rejection.** One record the backend rejects with 4xx dead-letters its whole batch (up to `batch_size`, default 100). Replay from the dead-letter table is manual.
- **Redirects are not followed.** A 3xx response (for example FastAPI's `/ingest` → `/ingest/`, or http → https) is logged as `HTTP 3xx redirect ... to <Location>`. The records stay queued and are retried until `SOC_INGEST_URL` is set to the exact final URL. Before 2026-10-31 this dead-lettered every batch; it is fixed and covered by tests.
- **No special handling for 413 or Retry-After.** 413 (request too large) is treated as permanent, so lower `batch_size` instead. `Retry-After` headers are ignored; the collector uses its own backoff (1–60 s).
- **Ordering.** Records are delivered in order per collector. There is no ordering guarantee across sensors (SSH, web, DB), so the backend must order timelines by `timestamp`.
- **History when the sink is enabled later.** A newly enabled HTTP sink receives only records still in the outbox: the newest `retain_delivered_records` (20,000) plus any undelivered ones.
- **Detection state is not persisted.** Findings are computed in memory. A collector restart in the middle of an attack can miss or repeat a threshold finding; events are unaffected.
- **Source IP masking.** On Docker Desktop the client IP is masked (it appears as the bridge gateway). See [deployment.md](deployment.md#requirements).

If the backend prefers to **pull** rather than receive pushes, it can tail the collector's `normalized.jsonl` instead (the `collector-state` volume). That file contains the same records in the same order.

## What the backend teammate needs to provide

1. **Endpoint.** The URL (host or IP on the team network, port, path), and whether it is HTTP or HTTPS. If HTTPS uses a self-signed certificate, `verify_tls = false` is available, but only for the lab.
2. **Auth.** A bearer token or equivalent secret. Required; see "Authentication requirement" above.
3. **Payload shape.** Will the backend accept the envelope or array as-is? If not, which top-level fields must be renamed (`field_map`) or restructured (a new Encoder)?
4. **Schema decisions.** Will the shared schema keep the `event_type` and `category` vocabulary in [schema/event.schema.json](schema/event.schema.json), or map it to a team vocabulary? Should findings be sent at all, or only events?
5. **Responses.** Which status codes mean "malformed, do not retry" versus "temporarily unavailable"? Ideally 4xx and 5xx/429 respectively, as above.
6. **Idempotency.** Confirm the backend de-duplicates on `event_id` and `finding_id`.
7. **Limits.** Maximum request size and batch size, and any rate limit.
8. **Clock.** Whether the SOC laptop and honeypot laptop need NTP sync for timeline ordering. Strongly recommended.

## Backend integration checklist

Fill this in with the backend teammate. Nothing here has been assumed in code. Every item marked "SSH side ready" works today against the local dev receiver only.

| # | Item | Needs confirmation from backend | SSH side |
|---|---|---|---|
| 1 | Endpoint URL (host on team LAN, port, exact path incl. trailing slash), http/https | ☐ | Ready: `SOC_INGEST_URL`; redirects are reported, not followed |
| 2 | Auth scheme and token (must be required) | ☐ | Ready: `Authorization: Bearer $SOC_INGEST_TOKEN`; other headers via `[sinks.http] headers` |
| 3 | Body shape: envelope or array; field names | ☐ | Ready: `payload_format`, `field_map`; deeper changes in `encoders.py` |
| 4 | Accept `finding` records, or events only? | ☐ | Findings are always sent today. Sending events only needs a small code change (not done; no decision yet) |
| 5 | Honeypot-type vocabulary (`ssh`/`web`/`db`) and shared `event_type` names | ☐ (with Web/DB owners) | SSH emits `ssh` plus the vocabulary in the schema |
| 6 | Success = 2xx; retry codes (5xx/429/503); reject codes (400/422) | ☐ | Implemented as described in "Expected response" |
| 7 | De-duplication on `event_id` / `finding_id` | ☐ | IDs stable (verified) |
| 8 | Max body size / batch size / rate limit | ☐ | `batch_size` (default 100), `timeout_seconds` (5) |
| 9 | TLS: real cert, self-signed (lab `verify_tls = false`), or plain http on the isolated LAN | ☐ | Supported; https is **not tested** |
| 10 | NTP on all laptops | ☐ | — |
| 11 | Honeypot laptop runs Linux Docker Engine so `source_ip` is real | ☐ (team) | Docker Desktop masks IPs (verified) |

## How to verify integration once the endpoint exists

```bash
# on the honeypot laptop, in .env:
SOC_INGEST_URL=http://<soc-laptop-ip>:<port>/<path>
SOC_INGEST_TOKEN=<token if any>
docker compose up -d
docker compose exec collector cowrie-soc status --config /app/config/collector.toml
```

Integration is working when the `http` sink's `pending` reaches 0, `last_error` is null, `dead_letters` stays 0, and the backend shows the same `event_id`s as `normalized.jsonl`. Until that has been run against the real backend, describe the integration as **not done**.

## Local dev receiver (not the SOC backend)

`cowrie-soc dev-receiver`, or `docker compose --profile dev up -d` with `SOC_INGEST_URL=http://dev-receiver:8088/ingest` and `SOC_INGEST_TOKEN` set, starts a stand-in on 127.0.0.1:8088. Under compose it requires the token for `/ingest` and `/records` and refuses to start without one. It:

- validates each record against the contract above
- de-duplicates by ID
- appends records to JSONL
- prints one line per record

Its routes (`/ingest`, `/records`, `/health`) belong to this tool only and are **not** a proposal for the team API.
