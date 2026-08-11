#!/bin/bash
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

REPORT="docs/auto-check-latest.md"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S %z')"

SKIP_DOCKER=0
NO_RESTORE=0
for arg in "$@"; do
  case "$arg" in
    --skip-docker) SKIP_DOCKER=1 ;;
    --no-restore) NO_RESTORE=1 ;;
  esac
done

export MSBUILDDISABLENODEREUSE=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1

BUILD_OK=0
FORMAT_OK=0
TEST_OK=0
DOCKER_OK=0

echo "==> [1/4] dotnet build -c Release"
if [ "$NO_RESTORE" = 1 ]; then
  dotnet build LucentMist.slnx -c Release --no-restore
else
  dotnet build LucentMist.slnx -c Release
fi
if [ "$?" = 0 ]; then
  BUILD_OK=1
else
  echo "Build FAILED"
fi

echo "==> [2/4] dotnet format --verify-no-changes"
if dotnet format LucentMist.slnx --verify-no-changes --no-restore; then
  FORMAT_OK=1
else
  echo "Format FAILED"
fi

echo "==> [3/4] dotnet test -c Release --no-build"
if dotnet test LucentMist.slnx -c Release --no-build; then
  TEST_OK=1
else
  echo "Test FAILED"
fi

if [ "$SKIP_DOCKER" = 1 ]; then
  echo "==> [4/4] docker compose config (SKIPPED)"
else
  echo "==> [4/4] docker compose config"
  if docker compose config --quiet; then
    DOCKER_OK=1
  else
    echo "Docker config FAILED"
  fi
fi

mkdir -p "$(dirname "$REPORT")"
{
  echo "# LucentMist Auto-Check"
  echo ""
  echo "> Timestamp: $TIMESTAMP"
  echo ""
  if [ "$BUILD_OK" = 1 ]; then echo "- Build: PASS"; else echo "- Build: FAILED"; fi
  if [ "$FORMAT_OK" = 1 ]; then echo "- Format: PASS"; else echo "- Format: FAILED"; fi
  if [ "$TEST_OK" = 1 ]; then echo "- Test: PASS"; else echo "- Test: FAILED"; fi
  if [ "$SKIP_DOCKER" = 1 ]; then
    echo "- Docker config: SKIPPED"
  elif [ "$DOCKER_OK" = 1 ]; then
    echo "- Docker config: PASS"
  else
    echo "- Docker config: FAILED"
  fi
  echo ""
  if [ "$BUILD_OK" = 1 ] && [ "$FORMAT_OK" = 1 ] && [ "$TEST_OK" = 1 ] && { [ "$SKIP_DOCKER" = 1 ] || [ "$DOCKER_OK" = 1 ]; }; then
    echo "- Result: PASS"
  else
    echo "- Result: FAILED"
  fi
} > "$REPORT"

if [ "$BUILD_OK" = 1 ] && [ "$FORMAT_OK" = 1 ] && [ "$TEST_OK" = 1 ] && { [ "$SKIP_DOCKER" = 1 ] || [ "$DOCKER_OK" = 1 ]; }; then
  echo "Auto-check PASS: $REPORT"
else
  echo "Auto-check FAILED: $REPORT" >&2
  exit 1
fi
