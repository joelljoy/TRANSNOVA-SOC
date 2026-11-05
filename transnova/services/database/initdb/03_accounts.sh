#!/bin/bash
# Runs once, on first boot only, from docker-entrypoint-initdb.d.
# Without the executable bit the entrypoint sources this file, so its shell options would
# leak into the entrypoint. `set -u` there can abort first boot, so it stays out.
set -eo pipefail

: "${DECOY_DB_PASSWORD:?DECOY_DB_PASSWORD must be set}"
: "${CONTROLLER_DB_PASSWORD:?CONTROLLER_DB_PASSWORD must be set}"
: "${CONTROLLER_HOST:=172.29.0.21}"

# These values go into SQL text through sed, so restrict them instead of escaping them.
for value in "$DECOY_DB_PASSWORD" "$CONTROLLER_DB_PASSWORD"; do
  if [[ ! "$value" =~ ^[A-Za-z0-9_#.-]+$ ]]; then
    echo "DB passwords may only contain letters, digits and _ # . -" >&2
    exit 1
  fi
done

sed -e "s|@@DECOY_HOST@@|%|g" \
    -e "s|@@DECOY_PASSWORD@@|${DECOY_DB_PASSWORD}|g" \
    -e "s|@@CONTROLLER_HOST@@|${CONTROLLER_HOST}|g" \
    -e "s|@@CONTROLLER_PASSWORD@@|${CONTROLLER_DB_PASSWORD}|g" \
    /opt/honeypot/accounts.sql.tmpl \
  | mariadb --protocol=socket -uroot -p"${MARIADB_ROOT_PASSWORD}"
