# LucentMist

> 🌫️ 基于 ReAct 模式的智能网络分析助手 — 融合网络扫描工具与 AI 推理能力

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com)
[![CI](https://github.com/<user>/<repo>/actions/workflows/ci.yml/badge.svg)](https://github.com/<user>/<repo>/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-132%2F132%20offline%20passed-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## ✨ 功能特性

- 🔍 **设备发现** — ICMP Ping 扫描，CIDR 子网支持，并发探测
- 🚪 **TCP 端口扫描** — TCP Connect 模式，自定义端口范围
- 📡 **UDP 端口扫描** — UDP 探测 DNS/SNMP/NTP 等 11 种服务
- 🔒 **SSL 证书校验** — SSL/TLS 证书获取、有效期、SAN、证书链检查
- 🛡️ **漏洞扫描** — 多源 CVE API + OS 指纹识别 + 风险验证
- 📊 **报告导出** — HTML/Markdown/CSV/JSON 多格式报告
- 🏷️ **服务识别** — Banner 抓取 + HTTP/SSH 检测 + 进程信息
- 🤖 **AI 推理** — ReAct 模式，自动调用工具分析网络
- 🔄 **双 LLM** — Ollama 本地推理 + Claude API 云端推理，随时切换
- 🌐 **Web 管理界面** — Blazor Server 仪表板，实时监控 + 扫描控制
- 📡 **双接口** — CLI 命令行 + RESTful API (SSE 流式)
- 💾 **持久化** — SQLite 存储扫描记录 + Redis 缓存（可选）

---

## 🚀 快速开始

### 系统要求

- .NET 10.0 SDK
- 可选：Ollama（本地 AI）或 Claude API Key

### 编译 & 测试

```bash
cd E:\LucentMist

# 编译
dotnet build

# 测试
dotnet test
```

### 开始使用

```bash
# 扫描网络
dotnet run --project src/LucentMist.CLI -- scan 192.168.1.0/24

# 漏洞扫描
dotnet run --project src/LucentMist.CLI -- vuln-scan 192.168.1.1

# 生成报告
dotnet run --project src/LucentMist.CLI -- report --target 192.168.1.1 --format html

# AI 对话
dotnet run --project src/LucentMist.CLI -- agent "分析我的网络安全性"

# 启动 Web 管理界面
dotnet run --project src/LucentMist.Web
```

---

## 🐳 Docker 部署

```bash
# 构建并启动（含 Redis）
docker compose up -d

# 仅构建镜像
docker build -t lucentmist:0.1.0 .

# 运行容器
docker run -d \
  --name lucentmist \
  -p 5050:5050 \
  -v ./config:/app/config \
  -v ./data:/app/data \
  lucentmist:0.1.0

# 验证
curl http://localhost:5050/api/v1/health
```

### 从发布包安装

```bash
# 下载对应平台的 release 包后
tar -xzf lucentmist-0.1.0-linux-x64.tar.gz
cd lucentmist-0.1.0
./cli/lmist status
```

---

## 📁 项目结构

```
LucentMist/
├── src/
│   ├── LucentMist.Core/     # 核心抽象层（Actor / Memory / Session）
│   ├── LucentMist.Agent/    # ReAct AI 智能体
│   ├── LucentMist.Tools/    # 网络扫描工具集
│   ├── LucentMist.CLI/      # 命令行入口 (lmist)
│   └── LucentMist.API/      # RESTful API (ASP.NET)
├── tests/
│   └── LucentMist.Core.Tests/
├── config/                  # 配置文件
├── docs/                    # 文档
└── scripts/                 # 启动脚本
```

---

## ⚙️ LLM 配置

编辑 `config/appsettings.json`：

```json
{
  "LucentMist": {
    "LLM": {
      "Provider": "ollama",
      "Model": "qwen2.5:7b",
      "OllamaEndpoint": "http://localhost:11434"
    }
  }
}
```

或使用 Claude API：

```json
{
  "LucentMist": {
    "LLM": {
      "Provider": "claude",
      "Model": "claude-sonnet-4-6",
      "ClaudeApiKey": "sk-ant-api03-..."
    }
  }
}
```

---

## 📖 文档

| 文档 | 说明 |
|------|------|
| [需求规格说明书](docs/01-需求规格说明书.md) | 功能需求与版本规划 |
| [技术设计方案](docs/02-技术设计方案.md) | C4 架构、ReAct 模式、数据流 |
| [数据库设计](docs/03-数据库设计.md) | ER 图、7 张表、Redis 缓存 |
| [API 接口设计](docs/04-API接口设计.md) | REST API + SSE 流式 |
| [编码规范](docs/05-编码规范.md) | 命名/异步/DI/测试规范 |
| [用户手册](docs/用户手册.md) | 安装、CLI 命令、场景示例 |
| [部署运维手册](docs/部署运维手册.md) | Docker/systemd、日志、备份、升级 |
| [常见问题](docs/常见问题.md) | FAQ 故障排查 |

---

## 🛠️ 技术栈

| 组件 | 技术 | 版本 |
|------|------|------|
| 运行时 | .NET | 8.0 LTS |
| Actor 模型 | Akka.NET | 1.5+ |
| 数据库 | SQLite | 3.x |
| 缓存 | Redis (可选) | 7.x |
| LLM | Ollama + Claude API | — |
| 测试 | xUnit | v3 |

---

## 📊 项目状态

```
Phase 0 ████████████ 需求分析    ✅ 5 文档
Phase 1 ████████████ 项目初始化  ✅ 5 项目
Phase 2 ████████████ Core 层     ✅ 4 Actor + 5 Model
Phase 3 ████████████ Tools 层    ✅ 4 工具
Phase 4 ████████████ Agent 层    ✅ ReAct + 双 LLM
Phase 5 ████████████ CLI + API   ✅ 6 命令 + 控制器
Phase 6 ████████████ 测试        ✅ 13/13 通过
Phase 7 ████████████ 文档        ✅ 4 文档
Phase 8 ████████████ 发布部署    ✅
Phase 9 ████████████ 项目复盘    ✅
```

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request。请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)（如果有）。

```bash
# 开发环境搭建
git clone <repo-url>
cd LucentMist
dotnet build
dotnet test
```

---

## 📄 许可证

MIT License © 2026 LucentMist
