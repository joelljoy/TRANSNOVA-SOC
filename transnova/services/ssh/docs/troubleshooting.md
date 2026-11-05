# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Cowrie log says `No operator config file found; using bundled defaults only` | `/etc/cowrie` is not readable. Rebuild the image (`docker compose build cowrie`). The Dockerfile sets the directory to 0555 and the files to 0444. This happened during development when `COPY --chmod=0444` also stripped the directory's execute bit |
| `ssh: connect ... Connection refused` | Check `docker compose ps` and `docker compose logs cowrie` for `Ready to accept SSH connections`. Make sure you are using `COWRIE_SSH_PORT` and `COWRIE_BIND_ADDR`; the default is 127.0.0.1, which is unreachable from other laptops |
| Host key warning after rebuild | Expected: host keys live in the `cowrie-state` volume and change if that volume is replaced. Use `-o UserKnownHostsFile=/dev/null` for lab SSH |
| `source_ip` is `172.x.0.1` / `192.168.65.x` | Docker Desktop is hiding the client IP. See [deployment.md](deployment.md#requirements) |
| Collector logs `sink http: cannot reach ... (retry N in Xs, P pending)` | The backend is down or the URL is wrong. Records are retained and retried. Fix the URL in `.env` and run `docker compose up -d collector` |
| Collector logs `backpressure: ... pausing ingestion` | Undelivered records reached `max_pending_records`. Ingestion resumes automatically once the sink recovers; Cowrie's own log still holds everything |
| `status` shows `dead_letters > 0` | The backend permanently rejected a batch (4xx). Inspect it with `docker compose exec collector python -c "import sqlite3; print(sqlite3.connect('/data/state/collector.db').execute('select error, body from dead_letter limit 1').fetchone())"`, fix the schema or `field_map`, then re-send those records (manual step) |
| `status` shows `quarantined > 0` | Lines that failed validation. Recent ones (with file/offset/reason) are shown by `cowrie-soc status`. Cowrie itself writes valid JSON, so check for manual edits to the log |
| Collector logs `POSSIBLE DATA LOSS: ... truncated` / `no longer exists` | The log was truncated, or a rotated file was deleted before it was fully read. Don't delete `cowrie.json.*` while the collector is behind |
| `docker compose exec cowrie sh` fails | The Cowrie image is distroless (there is no shell). Use `/cowrie/cowrie-env/bin/python3 -c ...` |
| Git Bash rewrites `/cowrie/...` to `C:/Program Files/Git/cowrie/...` | Prefix the command with `MSYS_NO_PATHCONV=1` |
| `PermissionError: /data/...` in the collector or dev receiver | Mount volumes at `/data/state` (owned by uid 10001 in the image). Root-owned volume paths are not writable |
| `config error: [detection.x] unknown keys` | A typo in `collector.toml`; the config is validated strictly on purpose |
| Tests | `cd collector && python -m pytest -q` (only pytest is needed) |
