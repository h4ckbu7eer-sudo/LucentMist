#!/bin/bash
# LucentMist 启动脚本 (Linux/macOS)

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

build() {
    echo -e "\033[36m编译 LucentMist...\033[0m"
    dotnet build "$PROJECT_DIR/LucentMist.sln"
}

test() {
    echo -e "\033[36m运行测试...\033[0m"
    dotnet test "$PROJECT_DIR/LucentMist.sln"
}

cli() {
    echo -e "\033[36m启动 LucentMist CLI...\033[0m"
    dotnet run --project "$PROJECT_DIR/src/LucentMist.CLI" -- "$@"
}

api() {
    echo -e "\033[36m启动 LucentMist API (http://localhost:5050)...\033[0m"
    dotnet run --project "$PROJECT_DIR/src/LucentMist.API"
}

help() {
    echo -e "\033[32m"
    echo "LucentMist - 智能网络分析助手"
    echo ""
    echo "用法: ./start.sh [command] [options]"
    echo ""
    echo "命令:"
    echo "  build   编译项目"
    echo "  test    运行测试"
    echo "  cli     启动 CLI 模式"
    echo "  api     启动 API 服务"
    echo "  help    显示此帮助"
    echo ""
    echo "示例:"
    echo "  ./start.sh build"
    echo "  ./start.sh cli scan 192.168.1.0/24"
    echo "  ./start.sh api"
    echo -e "\033[0m"
}

case "${1:-help}" in
    build) build ;;
    test)  test ;;
    cli)   shift; cli "$@" ;;
    api)   api ;;
    *)     help ;;
esac
