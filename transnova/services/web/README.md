# Web Decoy — TransNova Logistics Partner Portal

FastAPI web honeypot for the deception-driven SOC project. Everything in it is synthetic.
It never executes, evaluates, fetches or opens anything an attacker sends.

Every request becomes **one redacted canonical event** (HANDOFF_FINAL.md §6). It's written to a JSONL log
and POSTed in batches to the collector, with detections from 13 signature/behaviour rules.
Design: `../../PLAN.md`. Status and evidence: `../../PROJECT_STATUS.md`. Demo: `DEMO.md`.

## Run / stop / reset (from the repo root)

**Isolated (default, for the demo):** no internet, no access to the host, and no port published.
The simulator and collector reach the decoy at `172.28.0.10:8080` on `lab_net`.

```bash
docker compose -f docker-compose.web.yml up -d --build
docker compose -f docker-compose.web.yml ps          # wait for (healthy)
docker compose -f docker-compose.web.yml logs -f web-decoy
docker compose -f docker-compose.web.yml down
docker compose -f docker-compose.web.yml down -v     # destructive: also deletes the /data event log volume
```

**Browse mode (click-through testing from this machine):** publishes `https://127.0.0.1:8080`. The
container serves **HTTPS only**, with a self-signed certificate regenerated at every start, so the browser
warns once; accept it for the lab. Browse mode also attaches an extra network, so **the container can
reach the internet while browse mode is on**.

```bash
docker compose -f docker-compose.web.yml -f docker-compose.web.browse.yml up -d --build
docker compose -f docker-compose.web.yml -f docker-compose.web.browse.yml down
```

Synthetic login: `j.miller` / `TransNova#Spring26`.

**Without Docker** (development; from `services/web`, with the venv active). PowerShell:
```bash
$env:WEB_DECOY_HOST="127.0.0.1"; $env:WEB_DECOY_PORT="8081"; python -m web_decoy.serve
```
Always use `python -m web_decoy.serve`, as the container does. **Plain `uvicorn web_decoy.app:app` is unsafe
for testing:** it trusts a forged `X-Forwarded-For` from localhost and logs the fake IP (PLAN P13), and it lacks
the slow-header deadline (F1).

## Containment proof

```bash
docker compose -f docker-compose.web.yml exec -T web-decoy python - < services/web/scripts/isolation_check.py
```
Windows PowerShell:
```bash
Get-Content services/web/scripts/isolation_check.py | docker compose -f docker-compose.web.yml exec -T web-decoy python -
```
It checks: no egress to `1.1.1.1` / `8.8.8.8`, no external DNS, no default route, non-root, no capabilities,
no-new-privileges, read-only `/app`. Isolated mode must print `RESULT: ALL PASS`; browse mode correctly fails the egress checks.

## Watching events

```bash
docker compose -f docker-compose.web.yml exec web-decoy tail -f /data/web-events.jsonl
```
Detailed health (only from inside the container or other allowlisted `/32`s):
```bash
docker compose -f docker-compose.web.yml exec web-decoy python -c "import urllib.request,ssl;c=ssl.create_default_context();c.check_hostname=False;c.verify_mode=ssl.CERT_NONE;print(urllib.request.urlopen('https://127.0.0.1:8080/health',context=c).read().decode())"
```
Resend events that were spooled while the collector was down:
```bash
docker compose -f docker-compose.web.yml exec web-decoy python -m web_decoy.telemetry.replay
```

## Dependencies (hash-locked)

`requirements.txt` and `requirements-dev.txt` pin **every** package, indirect ones included, by version
**and** SHA-256 hash. pip switches to hash-checking mode automatically, and the Dockerfile uses
`--require-hashes`, so a changed or substituted package is refused. Edit only the `.in` files, then regenerate:
```bash
uv pip compile requirements.in --universal --python-version 3.12 --generate-hashes -o requirements.txt
uv pip compile requirements-dev.in --universal --python-version 3.12 --generate-hashes -o requirements-dev.txt
```
Vulnerability scan (re-run after any change):
```bash
python -m pip install pip-audit && pip-audit -r requirements.txt --require-hashes
```
Last result: **No known vulnerabilities found** (2026-10-31, PyPI advisory data). Full mapping: `OWASP.md`.

## Tests

From `services/web`, with the venv active:
```bash
python -m pytest -q
```
If you see "Wrong Python environment", the venv isn't active.

## Ports and environment

| Item | Value |
|---|---|
| Container port | 8080 |
| Host binding | none (isolated); `127.0.0.1:8080` (browse mode) |
| Lab network | `lab_net` 172.28.0.0/16, `internal`, host address inhibited; decoy at 172.28.0.10 |

| Variable | Default | Purpose |
|---|---|---|
| `SENSOR_ID` | `web-01` | Sensor ID in events |
| `DECOY_USER` / `DECOY_PASSWORD` | `j.miller` / `TransNova#Spring26` | Synthetic credential (protects nothing) |
| `HEALTH_ALLOWED_CIDRS` | `127.0.0.1/32` | Who sees detailed `/health`. Single `/32`s only; add the collector's IP |
| `COLLECTOR_URL` | `http://collector:8000/api/events` | Where batches are POSTed. Empty = JSONL only |
| `EVENT_LOG_PATH` | `/data/web-events.jsonl` (image), `data/web-events.jsonl` (local) | Every event, always |
| `SPOOL_PATH` | `/data/web-spool.jsonl` (image), `data/web-spool.jsonl` (local) | Undelivered batches |
| `SIMULATOR_SOURCE_CIDRS` | `172.28.0.50/32` | Who may set `X-Campaign-Id` |
| `CAMPAIGN_HEADER` | `X-Campaign-Id` | Campaign header name |
| `TRUST_PROXY` | `0` | Honour `X-Forwarded-For`, rightmost entry (keep 0) |
| `RATE_LIMIT_PER_S` / `RATE_LIMIT_BURST` | `20` / `60` | Per-IP request speed limit → 429 (0 = off) |
| `MAX_CONN_PER_IP` | `20` | Max simultaneous connections from one IP (out of 200) |
| `BODY_TIMEOUT_S` / `HEADER_TIMEOUT_S` | `15` / `10` | Slow-client deadlines |

## Acceptance criteria (`docs/handoff/02_WEB/claude.md`)

| Criterion | Evidence | Status |
|---|---|---|
| Starts with documented commands | This README; container healthy in both modes | Met |
| P0 routes and login events captured | `tests/test_telemetry.py`, `tests/test_detection_p0.py`; samples | Met |
| Suspicious inputs logged safely, never executed | `tests/test_safety.py` (AST checks), `tests/test_routes.py` traps | Met |
| Passwords, cookies, tokens redacted | `tests/test_redaction.py`; end-to-end leak checks | Met |
| Normalized events reach collector **and dashboard** | Delivery proven against a throwaway mock collector only | **Blocked**: no integrator collector/dashboard yet |
| Upload / SSRF / path traversal controls tested | `tests/test_routes.py`, `tests/test_detection_p1.py` | Met |
| Network isolation and synthetic data documented | Containment proof above; `fixtures.py` is all synthetic | Met |
| Tests pass | 402 passed (Python 3.12, local + Windows emulation; owner confirmed 358 on Windows) | Met |

## Known limitations

- **Integration is not done.** There is no real collector or dashboard yet, and the event schema is a local copy of HANDOFF §6.
- Browse mode removes egress isolation (Docker can't publish ports from an internal network).
- Detection state (brute-force/scan windows) and sessions are in memory and reset on restart.
- Signature rules are pattern-based. Obfuscated payloads can be missed, and unusual benign input can match.
- Security review fixes F1–F5 are applied (PLAN.md §8b). Slow clients are cut off after 10 s (headers) and 15 s (body). Uploads are capped at 960 KiB. Login accepts URL-encoded forms only.
- `/health` stays `degraded` after a manual replay until the next live delivery succeeds. Spooled events are not auto-replayed.
- The container uses a **self-signed** certificate (no CA in an isolated lab), so clients must skip verification for this one target. Local development runs (`python -m web_decoy.serve` without `WEB_DECOY_TLS=1`) are plain HTTP on 127.0.0.1.
- Traffic sent from the host arrives from a Docker gateway IP, not a real client IP. The simulator must run on `lab_net` (PLAN.md P9).
- The isolation setup has been verified on Linux Docker 29.9. It hasn't yet been verified on Docker Desktop for Windows.
