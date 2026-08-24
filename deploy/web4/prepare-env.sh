#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if [ -f .env ]; then
  echo ".env already exists; leaving it unchanged."
  exit 0
fi

cp .env.example .env
admin_key="$(openssl rand -hex 32)"
sed -i "s/CHANGE_ME_ADMIN_KEY/${admin_key}/" .env
chmod 600 .env
echo "Created .env with a random admin key. Fill the MYSQL_* values before starting."
