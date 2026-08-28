# LucentMist

> 🌫️ 基于 ReAct 模式的智能网络分析助手 — 融合网络扫描工具与 AI 推理能力

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com)
[![CI](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/workflows/ci.yml/badge.svg)](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/ci-tests-218%2F218%20passed-brightgreen)]()
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
- 🤖 **AI 推理（实验性）** — ReAct 模式，自动调用工具分析网络
- 🔄 **双 LLM** — Ollama 本地推理 + Claude API 云端推理，随时切换
- 🌐 **Web 管理界面** — Blazor Server 仪表板，实时监控 + 扫描控制
- 📡 **双接口** — CLI 命令行 + RESTful API (SSE 流式)
- 💾 **持久化** — SQLite 存储扫描记录与 Agent 会话

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
# 国内网络建议指定华为云 NuGet 镜像
docker build --build-arg NUGET_SOURCE=https://repo.huaweicloud.com/repository/nuget/v3/index.json -t lucentmist:0.9.3 .

# 启动 API + Web
docker compose up -d

# API 健康检查
curl http://localhost:5050/api/v1/health

# Web 管理界面
curl http://localhost:5051/

# 扫描任务
curl -X POST http://localhost:5050/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","scanType":"ping"}'
```

默认 compose 会在启动时自动生成随机 API token 和 Web 凭据，并打印到容器日志。生产部署仍应通过 `.env` 显式设置 `LMIST_API_TOKEN`、`LMIST_WEB_USER`、`LMIST_WEB_PASSWORD`。

---

## 📁 项目结构

```
LucentMist/
├── src/
│   ├── LucentMist.Core/     # 核心模型与共享服务
│   ├── LucentMist.Agent/    # ReAct AI 智能体
│   ├── LucentMist.Tools/    # 网络扫描工具集
│   ├── LucentMist.Scanning/ # 扫描队列与持久化（API/Web 共享）
│   ├── LucentMist.CLI/      # 命令行入口 (lmist)
│   ├── LucentMist.API/      # RESTful API (ASP.NET)
│   └── LucentMist.Web/      # Blazor Server 管理界面
├── tests/
│   ├── LucentMist.Tools.Tests/
│   ├── LucentMist.Agent.Tests/
│   ├── LucentMist.Scanning.Tests/
│   ├── LucentMist.API.Tests/
│   └── LucentMist.Benchmarks/
├── config/                  # 配置文件
├── docs/                    # 文档
└── scripts/                 # 启动脚本
```

---

## ⚙️ LLM 配置

LLM 通过环境变量配置（代码实际读取 `LMIST_*`）：

```bash
# Ollama（默认）
export LMIST_LLM_PROVIDER=ollama
export LMIST_LLM_MODEL=qwen2.5:7b
export LMIST_LLM_ENDPOINT=http://localhost:11434

# 或 Claude API
export LMIST_LLM_PROVIDER=claude
export LMIST_LLM_MODEL=claude-sonnet-4-6
export LMIST_LLM_APIKEY=sk-ant-api03-...
```

数据库路径可用 `LMIST_DB` 覆盖，默认 `data/lucentmist.db`。

---

## 📖 文档

| 文档 | 说明 |
|------|------|
| [需求规格说明书](docs/01-需求规格说明书.md) | 功能需求与版本规划 |
| [技术设计方案](docs/02-技术设计方案.md) | C4 架构、ReAct 模式、数据流 |
| [数据库设计](docs/03-数据库设计.md) | ER 图、SQLite 表结构 |
| [API 接口设计](docs/04-API接口设计.md) | REST API + SSE 流式 |
| [编码规范](docs/05-编码规范.md) | 命名/异步/DI/测试规范 |
| [用户手册](docs/用户手册.md) | 安装、CLI 命令、场景示例 |
| [部署运维手册](docs/部署运维手册.md) | Docker/systemd、日志、备份、升级 |
| [常见问题](docs/常见问题.md) | FAQ 故障排查 |
| [Agent 实验状态](docs/agent-experimental.md) | Agent 深化能力边界与验证状态 |
| [产品验证协议](docs/product-validation-protocols.md) | 方向 A 的用户需求、报告、网段验证 |
| [已知问题](docs/known-issues.md) | 产品、Agent、测试、部署的已知边界 |

---

## 🛠️ 技术栈

| 组件 | 技术 | 版本 |
|------|------|------|
| 运行时 | .NET | 全部项目 net10.0 |
| 数据库 | SQLite | 3.x |
| LLM | Ollama + Claude API | — |
| 测试 | xUnit | v3 |

---

## 📊 项目状态

```
Phase 0 ████████████ 需求分析    ✅ 5 文档
Phase 1 ████████████ 项目初始化  ✅ 5 项目
Phase 2 ████████████ Core 层     ✅ ReAct + SQLite 持久化
Phase 3 ████████████ Tools 层    ✅ 8 工具
Phase 4 ████████████ Agent 层    ✅ ReAct + 双 LLM
Phase 5 ████████████ CLI + API   ✅ 6 命令 + 控制器
Phase 6 ████████████ 测试        ✅ 226/226 通过
Phase 7 ████████████ 文档        ✅
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
