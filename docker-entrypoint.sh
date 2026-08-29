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
  echo "Using API token stored at $token_file (value not written to logs)"
elif [ -e "$token_file" ]; then
  echo "API token file exists but is empty: $token_file" >&2
  exit 1
else
  candidate_token=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
  if (set -C; printf '%s' "$candidate_token" > "$token_file") 2>/dev/null; then
    LMIST_API_TOKEN="$candidate_token"
    chmod 600 "$token_file"
    echo "Generated API token at $token_file (value not written to logs)"
  else
    LMIST_API_TOKEN=$(cat "$token_file")
    echo "Using API token stored at $token_file (value not written to logs)"
  fi
fi
export LMIST_API_TOKEN

case "$*" in
  *"web/LucentMist.Web.dll"*)
    web_user_file="/app/data/lucentmist-web-user"
    web_password_file="/app/data/lucentmist-web-password"
    if [ -z "${LMIST_WEB_USER:-}" ]; then
      if [ -s "$web_user_file" ]; then
        LMIST_WEB_USER=$(cat "$web_user_file")
      else
        LMIST_WEB_USER="admin"
        printf '%s' "$LMIST_WEB_USER" > "$web_user_file"
        chmod 600 "$web_user_file"
      fi
    fi
    if [ -z "${LMIST_WEB_PASSWORD:-}" ]; then
      if [ -s "$web_password_file" ]; then
        LMIST_WEB_PASSWORD=$(cat "$web_password_file")
      else
        LMIST_WEB_PASSWORD=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
        printf '%s' "$LMIST_WEB_PASSWORD" > "$web_password_file"
        chmod 600 "$web_password_file"
      fi
    fi
    echo "Web credentials configured (values not written to logs)"
    export LMIST_WEB_USER
    export LMIST_WEB_PASSWORD
    ;;
esac

exec "$@"
