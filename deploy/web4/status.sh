#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
docker compose --env-file .env -f compose.yaml ps

set -a
. ./.env
set +a

curl --fail --silent --show-error "http://127.0.0.1:${SERVER_PORT}/health/ready"
printf '\n'
curl --fail --silent --show-error "http://127.0.0.1:${ADMIN_PORT}/healthz"
printf '\n'
