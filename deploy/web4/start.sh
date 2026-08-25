#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "Missing .env. Run ./prepare-env.sh first." >&2
  exit 1
fi

if grep -q 'CHANGE_ME_MYSQL_' .env; then
  echo "MYSQL_* values are not configured in .env; refusing to start." >&2
  exit 1
fi

if grep -q 'CHANGE_ME_ADMIN_PASSWORD_HASH' .env; then
  echo "ADMIN_PASSWORD_HASH is not configured in .env; refusing to start." >&2
  exit 1
fi

if grep -q 'CHANGE_ME_CLOUDFLARE_API_TOKEN' .env; then
  echo "CLOUDFLARE_API_TOKEN is not configured in .env; refusing to start." >&2
  exit 1
fi

if grep -q 'CHANGE_ME_STORAGE_MASTER_KEY' .env; then
  echo "STORAGE_MASTER_KEY is not configured in .env; refusing to start." >&2
  exit 1
fi

docker compose --env-file .env -f compose.yaml build
docker compose --env-file .env -f compose.yaml run --rm --no-deps server ./rn-server migrate
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
