# Architecture assessment: before the React migration (2026-11-01)

This assessment comes from reading the code, not from filenames. Baseline tests were all green before any change:

| Suite | Result |
|---|---|
| `services/database/tests/test_collector.py` + `services/ssh/tests/integration` | 295 passed, 6 skipped |
| `services/web` | 359 passed |
| `services/ssh/sensor` | 563 passed |
| `services/database/tests/test_sensor_unit.py` + `test_classify_evasion.py` | 114 passed |

## Existing services

| Service | What it is | Network |
|---|---|---|
| `database-honeypot` | MariaDB 11.4.9 with the `server_audit` plugin and the TransNova Logistics fiction | `lab_net`, `db_mgmt_net` |
| `db-sensor` | Tails the audit log, classifies SQL, runs adaptive GRANT reveals, posts events, heartbeats and adaptations | `db_mgmt_net`, `ingest_net` |
| `web-decoy` | FastAPI decoy. Middleware telemetry, redaction, P0/P1 detections, emitter with a JSONL spool. Sends no heartbeat | `lab_net`, `ingest_net` |
| `ssh-honeypot` + `ssh-sensor` | Cowrie and its translator (`services/ssh`). They run in their own isolated compose, and the sensor has `network_mode: none`, so SSH events never reach soc-lab | separate project |
| `collector` | FastAPI + SQLite (`collector/`). Ingest, deduplication, alert upsert, read API | `ingest_net`, `soc_edge` |
| `dashboard` | Streamlit, six tabs, refreshing every 5 s | `soc_edge` |

## Event pipeline as built

The sensor builds a `CanonicalEvent` (`collector/schema.py`) and POSTs it to `/api/events` in batches of 50 or fewer. `BodyGuard` checks framing and size, and `ssh_ingest` checks SSH identity. The collector validates with pydantic and stores with `INSERT OR IGNORE` on `event_id`. Then `detections.process_event` turns `raw_evidence_redacted.detections[]` into one alert per (rule, source), and `_correlate` raises X-CORR-01.

## Existing frontend

The Streamlit dashboard reads the collector with an optional read token and renders evidence only through `st.dataframe`, `st.json` and `st.text`. Features to carry over: the overview counts, sensor table, recent events, an events table filtered by service with JSON evidence, alerts with rationale and ATT&CK, a timeline per source, the database honeypot summary (logins, tables, categories, severity, sessions) and the adaptive-deception trigger → change → follow-up view.

## Authentication

- The dashboard has no login at all. Its only protection is the `127.0.0.1` port binding.
- Collector reads need a token only when `SOC_READ_TOKEN_FILE` is set. The team compose leaves it unset, so reads are open and SSH ingest is refused.
- SSH ingest needs `SSH_INGEST_TOKEN_FILE` plus the read token, optionally pinned to a peer. Web and Database ingest is unauthenticated: anyone on `ingest_net` can post.

## Data model

SQLite tables are `events(event_id, ts, service, source_ip, session_id, doc)`, `alerts(dedupe_key, alert_id, last_seen, doc)`, `adaptations` and `sensors`. Alerts are rewritten whole on every upsert. There is no alert workflow state, no audit trail and no analyst notes.

## Detections

The sensors decide and the collector trusts them. Problems against the brief:
- **W-AUTH-01** (a single failed web login) and **W-ENUM-01** (a single sensitive-path request) each create an alert. That makes one wrong password an alert, which breaks the false-positive requirement.
- **X-CORR-01** is raised at `high` severity on a shared IP alone, though its own rationale says a shared IP does not prove one actor.
- OWASP labels are the 2021 edition. The current edition is 2025.
- There is no rule catalogue with descriptions, false-positive notes or declared tests.

## Gaps

There is no pagination total, no filters beyond service, source and session, no alert detail or related-event API, no workflow actions, no real sensor-health model, no ingestion-error counters, no MITRE coverage, no OWASP view, no AI/XAI, no auth audit events and no real-time push. `/api/attackers` loads 5,000 events and groups them in Python.

## Migration risks

- Changing `CanonicalEvent` breaks the web decoy's and the SSH translator's contract tests. New sources must be added without changing existing fields.
- The Database sender retries a refused batch forever (INTEGRATOR_NOTES §10), so no new collector check may refuse a valid database batch.
- Raw attacker strings must stay text-only in React: no `dangerouslySetInnerHTML`, no Markdown rendering.
- Read and ingest privileges must stay separate. Analyst write actions need a third privilege.

## Plan of record

1. **Collector:** additive SQLite migration (virtual generated columns plus indexes, workflow and audit tables), filtered and paginated v2 read API, an analyst write API behind its own token, a rule catalogue with an alert policy, OWASP 2025 mapping, an ATT&CK index from MITRE's STIX bundle, and correlation records. Existing routes stay.
2. **`console/` backend (FastAPI):** login with scrypt-hashed users from a secret file, an HttpOnly session cookie, CSRF, auth audit events to the collector, a proxy holding the read and analyst tokens, SSE change notifications, and Anthropic XAI with the key held only server-side. It serves the built React app.
3. **`frontend/` (React + TS + Vite):** eight routes, React Query, no data except what comes from the API.
4. **Compose:** console replaces dashboard. Read, analyst and SSH tokens move to Docker secrets, and the SSH decoy and sensor join soc-lab under the Stage 5 gates.
