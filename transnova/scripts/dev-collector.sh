#!/usr/bin/env sh
# Local development collector on 127.0.0.1:8000, with read, console and SSH tokens from secrets/.
cd "$(dirname "$0")/.." || exit 1
export COLLECTOR_DB_PATH="${COLLECTOR_DB_PATH:-data/dev/collector.db}"
export SOC_READ_TOKEN_FILE=secrets/read.token SOC_CONSOLE_TOKEN_FILE=secrets/console.token SSH_INGEST_TOKEN_FILE=secrets/ssh.token
exec .venv-soc/Scripts/python.exe -m uvicorn collector.app:app --host 127.0.0.1 --port 8000 --http h11 --no-server-header --no-access-log
