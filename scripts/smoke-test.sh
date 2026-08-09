#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== LucentMist smoke test ==="
docker compose up -d --build
trap 'docker compose down --remove-orphans' EXIT

for i in $(seq 1 30); do
    if curl -sf http://localhost:5050/api/v1/health >/dev/null 2>&1; then
        break
    fi
    if [ "$i" = "30" ]; then
        echo "API health check failed" >&2
        exit 1
    fi
    sleep 2
done

echo "=== API health ==="
curl -sf http://localhost:5050/api/v1/health

echo "=== Scan task ==="
TASK=$(curl -sf -X POST http://localhost:5050/api/v1/scan \
    -H "Content-Type: application/json" \
    -d '{"target":"127.0.0.1","scanType":"ping"}')
echo "$TASK"

echo "=== Web pages ==="
curl -sf http://localhost:5051/scan/history | grep -q "扫描历史"
curl -sf http://localhost:5051/agent | grep -q "Agent 对话"

echo "=== smoke test passed ==="
