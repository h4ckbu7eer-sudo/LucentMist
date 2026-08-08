#!/usr/bin/env bash
# LucentMist CI 本地检查脚本 (Bash)
# 模拟 GitHub Actions 流水线的完整流程

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "========================================"
echo "  LucentMist CI Check (Local)"
echo "========================================"
echo ""

START=$(date +%s)

# Step 1: Restore
echo -e "\033[33m[1/3] Restore dependencies...\033[0m"
dotnet restore
echo -e "\033[32m  => OK\033[0m"
echo ""

# Step 2: Build (Release)
echo -e "\033[33m[2/3] Build (Release)...\033[0m"
dotnet build -c Release --no-restore
echo -e "\033[32m  => OK\033[0m"
echo ""

# Step 3: Test (Release)
echo -e "\033[33m[3/3] Run tests...\033[0m"
dotnet test -c Release --no-build --verbosity normal
echo -e "\033[32m  => OK\033[0m"
echo ""

END=$(date +%s)
ELAPSED=$((END - START))
echo "========================================"
echo -e "\033[32m  ALL CHECKS PASSED\033[0m"
echo -e "\033[90m  Time: ${ELAPSED}s\033[0m"
echo "========================================"
