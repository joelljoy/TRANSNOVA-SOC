# Architecture: Cowrie SSH component

```
             decoy-net (bridge br-ps04-decoy)                         soc-uplink
 attacker ──ssh──▶ ┌──────────────┐  cowrie.json (named volume, ro)  ┌───────────────────────┐   HTTP POST   ┌──────────────────┐
 (laptop or        │ cowrie       │ ───────────────────────────────▶ │ collector (cowrie-soc)│ ────────────▶ │ SOC backend (TBD)│
  demo-attacker)   │ 3.1.4 pinned │                                  │ tail→parse→normalize  │               │ or dev-receiver  │
                   │ emulated sh  │                                  │ →detect→outbox→sinks  │ ──JSONL──▶ normalized.jsonl
                   └──────────────┘                                  └───────────────────────┘
```

- Cowrie writes its own genuine JSON audit log.
- The collector only **reads** that log. It never talks to Cowrie and never accepts events from the attacker side.
- The two containers share no volume except the read-only log volume, and they are on separate compose networks.
- Separate networks are **not** a security boundary on Docker Desktop: Cowrie could reach `soc-uplink` containers by IP. See [safety-and-isolation.md](safety-and-isolation.md).

## Collector pipeline (`collector/src/cowrie_soc/`)

| Stage | Module | Responsibility |
|---|---|---|
| Follow | `tailer.py` | Read complete lines from `cowrie.json`. Identify files by a first-line fingerprint, so after Cowrie's rename-based daily rotation it drains the old file and then moves to the new one. Detect truncation or missing files and report them loudly |
| Parse | `parser.py` | Validate each line as untrusted input: UTF-8, a JSON object, `cowrie.*` eventid, a timezone-aware timestamp, a session, a valid IP and ports. Lines that fail are quarantined with file, offset and reason |
| Normalize | `normalize.py` | Map Cowrie event IDs to the documented event types and categories. Assign a deterministic `event_id`. Keep the original object, SHA-256 and location in `raw`. Tag commands with evidence-backed ATT&CK techniques |
| Analyze | `commands.py` | Tokenize shell lines (never execute them) into individual commands with indicators |
| Detect | `detection.py`, `attack.py` | Eight configurable, explainable rules (see [detections.md](detections.md)). Bounded in-memory state, driven by event time |
| Store | `store.py` | SQLite (WAL, `synchronous=FULL`). Records and the new checkpoint are committed in **one transaction**. Also holds per-sink cursors, quarantine and dead-letter tables, and prunes the outbox |
| Deliver | `sinks.py`, `encoders.py` | JSONL sink (always available) and HTTP sink (when configured). In-order, at-least-once delivery with exponential backoff; permanent rejections are dead-lettered. The encoder is the replaceable wire-format layer |
| Control | `pipeline.py`, `cli.py`, `config.py` | Main loop with backpressure. CLI commands `run`, `replay`, `status`, `validate`, `dev-receiver`. Strict TOML config with environment overrides |
| Dev only | `devreceiver.py` | A stand-in HTTP receiver for local testing. **It is not the SOC backend** |

## Delivery guarantees

| Stage | Guarantee | Why |
|---|---|---|
| Log → outbox | Exactly once | The checkpoint offset and the records are committed atomically. A crash replays from the last committed offset, and the outbox `record_id UNIQUE` constraint absorbs re-reads (for example after a truncation) |
| Outbox → sink | At least once, in order | A sink's cursor advances only after a 2xx or a successful write. IDs are deterministic, so receivers de-duplicate |
| Loss | Never silent | Quarantine, dead-letter, `POSSIBLE DATA LOSS` errors for missing or truncated files, and a backpressure pause instead of dropping |

### Live verification on the dev machine (2026-10-31)

- **Outage recovery.** 118 records accumulated while the dev receiver was failing (a volume permission bug). All 118 were delivered after the receiver was fixed, and the collector container had been recreated in between.
- **Restart test.** After restarting both Cowrie and the collector and running more traffic, all 233 lines in `cowrie.json` arrived at the receiver exactly once (233 unique `event_id`s and raw hashes).

## Why these choices

- **Stdlib-only Python collector.** It needs nothing beyond Python 3.11+ (`tomllib`, `sqlite3`, `urllib`, `http.server`), so it deploys to the honeypot laptop with or without Docker and adds no supply-chain surface.
- **SQLite outbox rather than a message queue.** It gives a durable, atomic checkpoint plus queue in one file, which is suitable for one sensor and an 18-hour build. Kafka or Elasticsearch were explicitly out of scope.
- **Custom image built from the pinned upstream Cowrie digest.** Config, credentials and decoy files are baked in, so the honeypot needs no host bind mounts and builds are reproducible.
- **Detections at the sensor.** The handoff asks this component for explainable SSH detections. The raw normalized events are still sent, so the shared backend can apply its own cross-service rules.

## Not in this component

- The shared SOC backend and dashboard.
- Cross-service correlation.
- The web and DB decoys.
- Adaptive deception: changing the decoy at runtime. The decoy filesystem is static today, and `cowrie/build_fs.py` is the place to add approved templates later.
- Any automated response.
