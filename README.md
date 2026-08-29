# LucentMist

> 🌫️ 基于 ReAct 模式的智能网络分析助手 — 融合网络扫描工具与 AI 推理能力
>
> 当前稳定发布版：`v0.9.5`

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com)
[![CI](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/workflows/ci.yml/badge.svg)](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/local-tests-355%2F355%20passed-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## ✨ 功能特性

- 🔍 **设备发现** — ICMP Ping 扫描，CIDR 子网支持，并发探测
- 🚪 **TCP 端口扫描** — TCP Connect 模式，自定义端口范围
- 📡 **UDP 端口扫描** — UDP 探测 DNS/SNMP/NTP 等 11 种服务
- 🔒 **SSL 证书校验** — SSL/TLS 证书获取、有效期、SAN、证书链检查
- 🛡️ **漏洞扫描** — 多源 CVE API + OS 指纹识别 + 候选风险与置信度标注
- 📊 **报告导出** — HTML/Markdown/CSV/JSON，展示具体开放端口、服务与 SSL 信息
- 🏷️ **服务识别** — Banner 抓取 + HTTP/SSH 检测 + 进程信息
- 🤖 **AI 推理（实验性）** — ReAct 模式，自动调用工具分析网络
- 🔄 **双 LLM** — Ollama 本地推理 + Claude API 云端推理，随时切换
- 🌐 **Web 管理界面** — Blazor Server 仪表板，实时监控 + 扫描控制
- 📡 **双接口** — CLI 命令行 + RESTful API (SSE 流式)
- 💾 **持久化** — SQLite 存储扫描记录与 Agent 会话
- 🧾 **自用合规护栏** — 公网授权确认、允许范围、扫描审计与 WAL 安全备份

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

# 查看扫描审计并安全备份
dotnet run --project src/LucentMist.CLI -- audit --limit 20
dotnet run --project src/LucentMist.CLI -- backup --output backups/lucentmist.db

# AI 对话
dotnet run --project src/LucentMist.CLI -- agent "分析我的网络安全性"

# 启动 Web 管理界面
dotnet run --project src/LucentMist.Web
```

---

## 🐳 Docker 部署

> [!WARNING]
> **不要把未配置凭据的 LucentMist 暴露到公网。** 本地开发版会生成随机凭据，
> 但生产环境必须在启动前显式设置同一组
> `LMIST_API_TOKEN`、`LMIST_WEB_USER`、`LMIST_WEB_PASSWORD`。不要使用仓库示例值，
> 也不要提交 `.env`。

```bash
# 国内网络建议指定华为云 NuGet 镜像
docker build --build-arg NUGET_SOURCE=https://repo.huaweicloud.com/repository/nuget/v3/index.json -t lucentmist:0.9.5 .

# 私有 GHCR 包先登录；令牌需要 read:packages，且不要写入脚本
echo "$CR_PAT" | docker login ghcr.io -u YOUR_GITHUB_USER --password-stdin

# 拉取固定摘要，确保以后仍得到经过验证的 0.9.5 发布物
docker pull ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:48271745e38a425340004bf5852e84f8fc08e2cc03a7795d5bf4feb89c9bb698
docker tag ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:48271745e38a425340004bf5852e84f8fc08e2cc03a7795d5bf4feb89c9bb698 lucentmist:0.9.5

# 使用刚拉取的发布镜像启动 API + Web，不在本地重建
# 请先在未提交的 .env 中设置三项强凭据
docker compose up -d --no-build

# API 健康检查
curl http://localhost:5050/api/v1/health

# Web 管理界面
curl http://localhost:5051/

# 扫描任务
curl -X POST http://localhost:5050/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","scanType":"ping"}'
```

留空时容器会生成随机凭据，并让 API/Web 通过共享数据卷复用。凭据值不写日志；本地演示可按需用
`docker compose exec lucentmist cat /app/data/lucentmist-api-token`、
`docker compose exec lucentmist-web cat /app/data/lucentmist-web-user` 和
`docker compose exec lucentmist-web cat /app/data/lucentmist-web-password` 主动读取。
生产环境必须显式设置三项强凭据。

## 🔐 自用与数据边界

- 公网扫描在 CLI/Web 会要求授权确认；无交互自动化需在确认有权扫描后传 `--authorized`。
- 设置 `LMIST_ALLOWED_TARGETS=192.168.1.0/24,router.home,*.lab.example` 后，范围外目标会被所有入口拒绝。
- 扫描数据是明文 SQLite；建议使用全盘加密并限制 `data/`、报告和备份的文件权限。
- 默认不上传扫描结果或遥测；云端 LLM、外部 CVE、DNS 与 Sirius 的精确边界见
  [隐私与网络出口审计](docs/compliance-telemetry-audit.md)。
- 完整自用核验见 [自用资格清单](docs/self-use-checklist.md)，备份恢复见
  [数据安全与恢复](docs/data-security-and-recovery.md)。

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
| [0.9.5 发布说明](docs/RELEASE_0.9.5.md) | 核心变更、验证证据与部署要求 |
| [0.9.4 发布说明](docs/RELEASE_0.9.4.md) | 上一版本的历史发布证据与回滚信息 |

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
Phase 6 ████████████ 测试        ✅ 355/355 本地全量通过
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
