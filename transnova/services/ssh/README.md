# PS04: Cowrie SSH honeypot component

This is the SSH decoy part of **PS 04: Deception-Driven Threat Detection and Response**.

> **Integrated use:** this component now lives in `services/ssh` and runs from `docker-compose.isolated.yml` (project `soc-ssh-isolated`), on its own internal network with no published port. It is not connected to the shared SOC yet. Sensor identity is `ssh-01`. Tried passwords are not recorded. Commands below that use `docker compose ... collector`, `dev-receiver` or `127.0.0.1:2222` describe the original standalone project. See [docs/safety-and-isolation.md](docs/safety-and-isolation.md#what-is-stored-about-attacker-input).

It contains three pieces:

- A hardened Cowrie 3.1.4 SSH honeypot with a synthetic "backup server" filesystem and honeytokens.
- A collector (`cowrie-soc`) that turns Cowrie's genuine JSON logs into normalized events and explainable, ATT&CK-mapped findings.
- A durable delivery path for the future shared SOC backend.

> **Integration status:** the shared SOC backend and its schema/endpoint did not exist yet, so this component is **not integrated** with it. It works on its own, writes JSONL, and has a configurable HTTP sink that has been tested only against the bundled **local dev receiver**. See [docs/integration-contract.md](docs/integration-contract.md) for exactly what the backend teammate needs to provide.

## Quick start (local, localhost only)

You need Docker with Compose v2, and Python 3.11+ to run the tests.

```bash
# decoy + collector + local dev receiver (stand-in backend; it refuses to start without a token)
export SOC_INGEST_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(24))")
SOC_INGEST_URL=http://dev-receiver:8088/ingest docker compose --profile dev up -d --build

# real SSH traffic from the host's OpenSSH client (synthetic credential backup / Backup@2024)
ssh -p 2222 -o UserKnownHostsFile=/dev/null backup@127.0.0.1

# watch records arrive and inspect collector state
docker compose logs dev-receiver | grep finding
docker compose exec collector cowrie-soc status --config /app/config/collector.toml

# tests
cd collector && python -m pytest -q
```

Start with **[SSH-HANDOFF.md](SSH-HANDOFF.md)**, the one-page summary for teammates. For deployment on the honeypot laptop see [docs/deployment.md](docs/deployment.md), and for a demo script see [docs/demo-guide.md](docs/demo-guide.md).

The optional `demo` compose profile (`demo-attacker/`) is a scripted traffic generator. It is **not** the team's Demo Attacker module.

## Layout

| Path | What |
|---|---|
| `cowrie/` | Image build. `Dockerfile` (pinned upstream digest), `cowrie.cfg` (safety overrides), `userdb.txt` (synthetic credential policy), `decoy-fs/` (synthetic files and honeytokens), `build_fs.py` (merges `decoy-fs/` into Cowrie's emulated filesystem) |
| `collector/` | `cowrie_soc` Python package (stdlib-only at runtime), config, tests, and a real captured log fixture |
| `demo-attacker/` | Bounded traffic generator (paramiko) with a target allow-list and fixed scenarios. It is not part of the honeypot |
| `docker-compose.yml` | Cowrie, collector, plus `dev` and `demo` profiles. Hardened containers, named volumes only, published on localhost by default |
| `docs/` | Architecture, integration contract and JSON Schemas, detections, safety, deployment, demo guide, troubleshooting |

## What is implemented and how it was checked

| Area | Status | Evidence |
|---|---|---|
| Cowrie deployment | Done | Built from the pinned `cowrie/cowrie` digest. Runs non-root, read-only, `cap_drop: ALL`, no host mounts, bound to 127.0.0.1. Verified with `docker inspect` |
| Safety controls | Done (dev machine) | Outbound sockets from emulated commands fail (`out_addr=127.0.0.1`, EINVAL). `ssh -W` forwarding is refused. Telnet is off. See [docs/safety-and-isolation.md](docs/safety-and-isolation.md) |
| Real activity capture | Done | 104 genuine events from paramiko scenarios and an OpenSSH exec session, saved as `collector/tests/fixtures/real_capture_2026-10-31.json` |
| Parse, validate, normalize, preserve raw | Done | 18 Cowrie event IDs mapped (11 observed live); unknown IDs are kept. Review on 2026-10-31: 246 of 246 live log lines matched their normalized events (raw object, hash, key fields). Raw object, SHA-256 and file/offset are preserved. Deterministic IDs |
| Reliable collection | Done | Partial lines, rename rotation, truncation, restart checkpoints, a quarantine table, an atomic outbox, at-least-once delivery with backoff, dead-lettering and backpressure. Unit tests plus live restart and outage checks |
| Detections + ATT&CK | Done | 8 rules (brute force, decoy login, shell activity, discovery burst, credential/honeytoken access, ingress tool transfer, dropper sequence, history tampering). 14 findings on the real capture. See [docs/detections.md](docs/detections.md) |
| SOC integration adapter | Ready, not integrated | HTTP sink with a replaceable encoder and `field_map`. Proposed schemas are in `docs/schema/` |
| Tests | Passing | 144 pytest tests (19 fixture-based on a real Cowrie capture, 120 synthetic, 5 docs/contract; none live): parser, commands, normalize, detections, tailer, pipeline, HTTP, config, contract drift, review regressions |

## Known limitations

- **Source IP behind Docker Desktop.** The client IP is masked on the Windows dev machine (it shows as the bridge gateway, e.g. `172.18.0.1` or `172.19.0.1`). Use a Linux Docker host on the honeypot laptop and check `source_ip` first.
- **Decoy can reach host services and the internet.** On Docker Desktop, a process inside the Cowrie container reached 12 of 13 probed host services through `host.docker.internal`, including ones bound to 127.0.0.1. It also reached the internet, and the dev receiver by IP (verified with plain sockets). Do not run the decoy on a laptop with sensitive services. The SOC ingest endpoint must require a token.
- **Host firewall NOT applied (deployment prerequisite).** The Linux `DOCKER-USER` + `INPUT` rules in `docs/deployment.md` have never been executed. See [SSH-HANDOFF.md §0](SSH-HANDOFF.md).
- **No cross-service correlation or adaptive deception yet.** They are out of this component's scope. Detection state is not persisted across collector restarts.
- **Not every Cowrie event was seen live.** `file_download`, `file_upload` and `direct-tcpip` events were not observed, because the safety settings prevent them. They are mapped from Cowrie's documented fields and tested with fixtures.
