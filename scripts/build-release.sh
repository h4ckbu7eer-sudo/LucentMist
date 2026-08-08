#!/bin/bash
# LucentMist Release 构建脚本 (Linux/macOS)
# 用法: ./scripts/build-release.sh [version] [runtime]

set -e

VERSION="${1:-0.1.0}"
RUNTIME="${2:-linux-x64}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PUBLISH_DIR="$PROJECT_DIR/publish/$VERSION"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   LucentMist Release Builder            ║"
echo "║   Version: $VERSION                      ║"
echo "║   Runtime: $RUNTIME                     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Step 1: 清理
echo -e "\033[33m[1/6] 清理旧构建产物...\033[0m"
rm -rf "$PUBLISH_DIR"
rm -rf "$PROJECT_DIR/publish/latest"
echo -e "\033[32m       清理完成\033[0m"

# Step 2: 还原
echo -e "\033[33m[2/6] 还原 NuGet 包...\033[0m"
dotnet restore "$PROJECT_DIR/LucentMist.slnx"
echo -e "\033[32m       还原完成\033[0m"

# Step 3: 编译
echo -e "\033[33m[3/6] Release 编译...\033[0m"
dotnet build "$PROJECT_DIR/LucentMist.slnx" -c Release --no-restore
echo -e "\033[32m       编译完成 (0 errors)\033[0m"

# Step 4: 测试
echo -e "\033[33m[4/6] 运行测试...\033[0m"
dotnet test "$PROJECT_DIR/LucentMist.slnx" -c Release --no-restore --verbosity normal
echo -e "\033[32m       测试全部通过\033[0m"

# Step 5: 发布 CLI
echo -e "\033[33m[5/6] 发布 CLI ($RUNTIME)...\033[0m"
dotnet publish "$PROJECT_DIR/src/LucentMist.CLI/LucentMist.CLI.csproj" \
    -c Release \
    -o "$PUBLISH_DIR/cli" \
    --self-contained true \
    -r "$RUNTIME" \
    -p:PublishSingleFile=true \
    -p:Version="$VERSION"
echo -e "\033[32m       CLI 发布完成\033[0m"

# Step 6: 发布 API
echo -e "\033[33m[6/6] 发布 API ($RUNTIME)...\033[0m"
dotnet publish "$PROJECT_DIR/src/LucentMist.API/LucentMist.API.csproj" \
    -c Release \
    -o "$PUBLISH_DIR/api" \
    --self-contained true \
    -r "$RUNTIME" \
    -p:Version="$VERSION"
echo -e "\033[32m       API 发布完成\033[0m"

# 复制配置和文档
cp -r "$PROJECT_DIR/config" "$PUBLISH_DIR/config"
cp "$PROJECT_DIR/README.md" "$PUBLISH_DIR/README.md"

# 创建 latest 链接
mkdir -p "$PROJECT_DIR/publish/latest"
cp -r "$PUBLISH_DIR"/* "$PROJECT_DIR/publish/latest/"

# 设置 CLI 可执行
chmod +x "$PUBLISH_DIR/cli/lmist"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   ✅ 构建完成！                          ║"
echo "╠══════════════════════════════════════════╣"
echo "║   输出: $PUBLISH_DIR"
echo "║                                          ║"
echo "║   CLI: $PUBLISH_DIR/cli/lmist"
echo "║   API: $PUBLISH_DIR/api/LucentMist.API.dll"
echo "╚══════════════════════════════════════════╝"
echo ""
