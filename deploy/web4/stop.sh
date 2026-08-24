#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
docker compose --env-file .env -f compose.yaml down
