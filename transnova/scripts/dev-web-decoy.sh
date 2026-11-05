#!/usr/bin/env sh
# Local web decoy on 127.0.0.1:8081 that reports to the local collector.
cd "$(dirname "$0")/../services/web" || exit 1
mkdir -p ../../data/dev
export WEB_DECOY_HOST=127.0.0.1 WEB_DECOY_PORT=8081 COLLECTOR_URL=http://127.0.0.1:8000/api/events
export EVENT_LOG_PATH=../../data/dev/web-events.jsonl SPOOL_PATH=../../data/dev/web-spool.jsonl
exec ../../.venv-soc/Scripts/python.exe -m web_decoy.serve
