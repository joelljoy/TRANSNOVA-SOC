#!/usr/bin/env sh
# Local development console backend on 127.0.0.1:8501, serving frontend/dist.
cd "$(dirname "$0")/.." || exit 1
export COLLECTOR_BASE_URL=http://127.0.0.1:8000
export SOC_READ_TOKEN_FILE=secrets/read.token SOC_CONSOLE_TOKEN_FILE=secrets/console.token SOC_USERS_FILE=secrets/users.txt
[ -f secrets/anthropic.key ] && export ANTHROPIC_API_KEY_FILE=secrets/anthropic.key
exec .venv-soc/Scripts/python.exe -m uvicorn console.serve:app --host 127.0.0.1 --port 8501 --no-server-header
