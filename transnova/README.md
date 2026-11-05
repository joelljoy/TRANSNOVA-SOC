# TransNova SOC: a three-honeypot Security Operations Center

The lab runs a web decoy, a MariaDB decoy and a Cowrie SSH decoy. Every interaction with them becomes a stored, immutable event. A collector raises evidence-backed alerts from those events, and the **TransNova SOC console** (React + FastAPI) is where an analyst reviews them.

Earlier assessment notes: [docs/ARCHITECTURE_ASSESSMENT.md](docs/ARCHITECTURE_ASSESSMENT.md). Product context: [PRODUCT.md](PRODUCT.md). Visual system: [DESIGN.md](DESIGN.md).

## Architecture

```
 lab_net (internal, no egress)              ingest_net (internal)                       soc_edge
 ───────────────────────────               ─────────────────────                       ────────
 web-attacker ─HTTP─▶ web-decoy ──events (no token)──────────▶┐
 db-attacker ─SQL──▶ database-honeypot ─audit log─▶ db-sensor ─events, heartbeats, adaptations─▶ collector ◀─read token── console ◀── browser
 ssh-attacker ─SSH─▶ ssh-honeypot ─cowrie.json─▶ ssh-sensor ─events + SSH ingest token──────▶│  (FastAPI,    ─console token─▶ (FastAPI +    127.0.0.1:8501
                                                                                              │   SQLite)                       React app)
                                                                                              └─ detections → alerts → workflow / audit
                                                                       console ─sign-in audit events (console token)─▶ collector
                                                                       console ─evidence only─▶ Anthropic API (optional XAI)
```

| Component | Path | Role |
|---|---|---|
| Web decoy | `services/web` | Decoy portal. Its telemetry middleware emits redacted events with OWASP and ATT&CK candidate detections |
| Database decoy | `services/database` | MariaDB with `server_audit`. A sensor classifies SQL and runs adaptive GRANT reveals |
| SSH decoy | `services/ssh` | Cowrie, plus a translator that delivers to the collector with its own token |
| Collector | `collector/` | Ingest, deduplication on `event_id`, alert policy (`rules_catalog.py`), correlation, the v2 read API and analyst actions |
| Console backend | `console/` | Sign-in (scrypt), HttpOnly session plus CSRF, sign-in audit events, an allowlisted proxy, SSE change notices and XAI |
| Console frontend | `frontend/` | React 18, TypeScript, Vite, React Router and React Query. It reaches nothing but the console backend |

**Event lifecycle:** decoy interaction → sensor normalises and redacts → `POST /api/events` (size guard, SSH identity check, schema validation) → stored before the 200 → detections evaluated against the alert policy → correlation → alert opened or updated (one per rule and source) → visible in All events, the source profile and alerts. A change notice reaches open consoles within about 2 s.

**An event is not an alert.** Single-occurrence signals (`W-AUTH-01` one failed web login, `W-ENUM-01` one sensitive path, `SOC-AUTH-00` one failed console sign-in) are recorded on the event as a *rule match* and never open an alert alone. Threshold rules (`W-AUTH-02`, `SOC-AUTH-01` ≥5 failures in 10 min, `SSH-BRUTE-001`, ...) open alerts and link the events that led up to them. A shared IP across decoys (`X-CORR-01`) is a medium-severity, low-confidence lead.

## Run it

```bash
cp .env.example .env
```

```bash
python scripts/make_secrets.py
```

```bash
docker compose up --build -d
```

Open http://127.0.0.1:8501 and sign in with the account you just created.

Generate real traffic from the attacker containers (all on `lab_net` only):

```bash
docker compose --profile attacker up -d db-attacker web-attacker
```

```bash
docker compose exec web-attacker curl -sk -X POST -d "username=jdoe&password=oops" https://web-decoy:8080/login
```

```bash
docker compose exec -e MYSQL_PWD=<DECOY_DB_PASSWORD from .env> db-attacker mariadb -h database-honeypot -u decoy_user transnova_logistics -e "SHOW TABLES"
```

```bash
docker compose --profile attacker run --rm ssh-attacker full
```

### Configuration

Tokens and accounts are Docker secrets in `./secrets` (git-ignored, created by `scripts/make_secrets.py`, never overwritten). Each one is a separate privilege, and the collector refuses analyst actions if the console token equals the read token or the SSH token.

| Secret / variable | Used by | Purpose |
|---|---|---|
| `secrets/read.token` | collector, console | Every non-POST collector route (`SOC_READ_TOKEN_FILE`) |
| `secrets/console.token` | collector, console | Analyst actions and sign-in audit events (`SOC_CONSOLE_TOKEN_FILE`) |
| `secrets/ssh.token` | collector, ssh-sensor | SSH ingest (`SSH_INGEST_TOKEN_FILE`, also pinned to the sensor's IP) |
| `secrets/users.txt` | console | `username:role:scrypt$…`. Roles are `viewer`, `analyst` and `admin`. Add accounts with `python -m console.users add NAME --role analyst --file secrets/users.txt` |
| `ANTHROPIC_API_KEY` (`.env`, optional) | console | AI explanations. Without it they say *unavailable* and nothing else changes |
| `SOC_AI_MODEL` | console | Default `claude-opus-5-5` |
| `SOC_COOKIE_SECURE` | console | `true` when served over HTTPS |
| `MARIADB_ROOT_PASSWORD`, `CONTROLLER_DB_PASSWORD`, `DECOY_DB_PASSWORD` | database | Unchanged |

The console refuses to start, naming the missing setting, if a token or users file is missing. No secret reaches the browser bundle: Vite has no secret variables, and the React app talks only to `/api/*` on its own origin.

### Local development without Docker

`scripts/dev-collector.sh`, `scripts/dev-console.sh` and `scripts/dev-web-decoy.sh` run the collector (:8000), the console (:8501) and a web decoy (:8081) natively, using the tokens in `secrets/`. Run `npm run dev` in `frontend/` for hot reload on :5173. It proxies `/api` to the console.

## Console pages

| Page | What it answers |
|---|---|
| Overview | Is the SOC working? What is waiting for review? A state strip in plain sentences, the newest events, 24 h activity and the alert queue |
| All events | Every stored event, filtered, searched and paginated on the server. Each event page shows raw evidence, determination slips and analyst classifications |
| Alerts | Triage with severity, status, rule, source and technique filters. The detail page has the rule conclusion, false-positive notes, evidence, workflow, history and XAI |
| Sources | One profile per observed address: timeline, sessions (bars drawn to real duration), commands, SQL, requests, techniques, correlations and alerts |
| Sensors | Heartbeat and last-event health (never assumed), ingestion refusals and adaptive deception |
| MITRE ATT&CK | Coverage against Enterprise v20.0 (MITRE's STIX data). Each technique is marked supported by evidence, inferred by a rule, ready but not seen, or a known gap |
| OWASP web | Web decoy traffic under OWASP Top 10:2025, keeping the 2021 label the sensor sent. Categories the decoy cannot observe are shown with the reason |
| Settings | Account, connection and token presence (never values), AI status and detection content |

## Collector API (v2)

Every GET needs the read token. The console proxies these routes as `/api/data/<route>`.

`GET /api/v2/summary` · `events` (`limit`≤200, `offset`, `order`, `service`, `source_ip`, `session_id`, `event_type`, `action`, `outcome`, `sensor_id`, `rule`, `technique`, `owasp` (2025 code), `detection` = observed|matched|alerted, `since`, `until`, `q`) · `events/facets` · `events/{id}` · `alerts` (`severity`, `status`, `rule`, `source_ip`, `service`, `technique`, `tactic`, `owasp`, `since`, `until`, `sort`) · `alerts/{id}` · `sources` · `sources/{ip}` · `sensors` · `ingestion` · `rules` · `mitre` · `owasp` · `cursor`

Analyst actions require the console token, and the actor is the signed-in user: `POST /api/v2/analyst/alert-status` (investigate, confirm, false_positive, resolve, reopen; confirming or marking a false positive needs a reason) · `alert-note` · `event-classification` · `explanation` · `POST /api/v2/console/auth-event`. Events are never edited. Classifications, statuses, notes and AI output are stored beside them with actor and time.

Legacy routes (`/api/events`, `/api/alerts`, `/api/attackers`, ...) are unchanged for existing senders and tools.

## Tests

Run these two groups **separately**: together, two different `conftest.py` files clash and collection fails.

```bash
python -m pytest collector/tests console/tests
```

```bash
python -m pytest services/database/tests/test_collector.py services/ssh/tests/integration
```

```bash
cd services/mainsite && python -m pytest
```

```bash
cd services/anonintel && python -m pytest
```

```bash
cd services/web && python -m pytest
```

```bash
cd services/ssh/sensor && python -m pytest
```

```bash
cd frontend && npm run lint && npm run typecheck && npm test && npm run build
```

```bash
python scripts/browser_check.py
```

`browser_check.py` drives the running console in headless Chrome. It signs in and visits every page at 1440 px and 390 px, then fails on console errors, failed requests, error states or horizontal overflow.

## Known limitations

- **Console sign-in source address.** Through the published port, Docker shows the console the gateway address (for example `172.20.0.1`), not your host's address. Natively it is `127.0.0.1`.
- **Sessions are in memory.** Restarting the console signs everyone out (sign-in audit events are unaffected).
- **Heartbeats.** The web decoy and SSH sensor send no heartbeat, so their health is *unknown* and judged from their last event. Only `db-01` reports heartbeats.
- **Web and database ingest are unauthenticated**, as before. Anything on `ingest_net` can post web or database events. SSH and console events are token-protected.
- **Coverage is rule-based.** It is not full ATT&CK or OWASP coverage. See the MITRE page's known gaps and `services/ssh/docs/detections.md`.
- **The OWASP 2021 → 2025 mapping** is maintained in `collector/rules_catalog.py`. SSRF (A10:2021) is reported under A01:2025.
