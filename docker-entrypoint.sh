#!/bin/sh
set -e

token_file="/app/data/lucentmist-api-token"
mkdir -p /app/data

if [ -z "$LMIST_API_TOKEN" ]; then
  LMIST_API_TOKEN=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
  printf '%s' "$LMIST_API_TOKEN" > "$token_file"
  chmod 600 "$token_file"
  echo "Generated API token: $LMIST_API_TOKEN"
elif [ -f "$token_file" ]; then
  printf '%s' "$LMIST_API_TOKEN" > "$token_file"
else
  printf '%s' "$LMIST_API_TOKEN" > "$token_file"
fi
export LMIST_API_TOKEN

if [ -z "$LMIST_WEB_USER" ]; then
  LMIST_WEB_USER="admin"
  LMIST_WEB_PASSWORD=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
  echo "Generated Web credentials: $LMIST_WEB_USER / $LMIST_WEB_PASSWORD"
fi
export LMIST_WEB_USER
export LMIST_WEB_PASSWORD

exec "$@"
