#!/bin/sh
set -e

token_file="/app/data/lucentmist-api-token"
mkdir -p /app/data
umask 077

if [ -n "${LMIST_API_TOKEN:-}" ]; then
  printf '%s' "$LMIST_API_TOKEN" > "$token_file"
  chmod 600 "$token_file"
elif [ -s "$token_file" ]; then
  LMIST_API_TOKEN=$(cat "$token_file")
  echo "Reusing generated API token from $token_file"
elif [ -e "$token_file" ]; then
  echo "API token file exists but is empty: $token_file" >&2
  exit 1
else
  candidate_token=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
  if (set -C; printf '%s' "$candidate_token" > "$token_file") 2>/dev/null; then
    LMIST_API_TOKEN="$candidate_token"
    chmod 600 "$token_file"
    echo "Generated API token: $LMIST_API_TOKEN"
  else
    LMIST_API_TOKEN=$(cat "$token_file")
    echo "Reusing generated API token from $token_file"
  fi
fi
export LMIST_API_TOKEN

case "$*" in
  *"web/LucentMist.Web.dll"*)
    generated_web_credentials=false
    if [ -z "${LMIST_WEB_USER:-}" ]; then
      LMIST_WEB_USER="admin"
      generated_web_credentials=true
    fi
    if [ -z "${LMIST_WEB_PASSWORD:-}" ]; then
      LMIST_WEB_PASSWORD=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
      generated_web_credentials=true
    fi
    if [ "$generated_web_credentials" = true ]; then
      echo "Generated Web credentials: $LMIST_WEB_USER / $LMIST_WEB_PASSWORD"
    fi
    export LMIST_WEB_USER
    export LMIST_WEB_PASSWORD
    ;;
esac

exec "$@"
