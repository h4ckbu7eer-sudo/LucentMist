# 隐私与运行时网络出口审计

审计日期：2026-08-31（默认云源行为更新）。范围为 LucentMist 当前 `main` 的 `src/`、运行项目依赖、
Docker 配置和日志/报告路径。本审计区分“扫描目标所必需的网络探测”与“把扫描数据上传给第三方”。

## 结论

LucentMist 没有遥测、使用统计、自动更新检查或崩溃上报代码，也没有对应的
Application Insights、Sentry、OpenTelemetry 或分析 SDK 依赖。程序空闲运行时不会主动联系
LucentMist 项目方或其他统计端点。扫描结果、报告、Agent 会话和审计记录默认只写本机 SQLite、
本机文件或用户主动选择的报告路径。

更精确的产品声明是：

> LucentMist 不上传完整扫描报告或遥测。漏洞扫描默认向免费云源发送标准服务关键词或产品 CPE（含版本）；
> 不发送目标 IP、原始 banner、凭据或会话。提供方仍可见请求出口 IP。设 `LMIST_CVE_EXTERNAL=false` 可关闭云源查询。
> 协议探测、系统 DNS 和用户显式启用的云端 LLM/Sirius 具有下列独立网络边界。

不能写成“任何情况下都没有数据包离开本机”：网络扫描本身、DNS 解析和用户显式启用的集成都需要网络。

## 全部运行时网络出口

| 出口 | 目的地/数据 | 触发条件 | 默认状态 |
|---|---|---|---|
| ICMP/TCP/UDP/TLS/HTTP/SMB/SSH 探测 | 用户指定且通过 TargetGuard 的扫描目标；只发送协议探测 | 用户发起扫描 | 不自动触发 |
| DNS | 操作系统配置的 DNS 解析器；发送用户输入的主机名 | 目标是主机名 | 仅该次扫描 |
| Web → LucentMist API | `LMIST_API_URL`，默认 `http://localhost:5050`；发送 Agent 对话 | Web 中主动使用 Agent | 本机地址 |
| Ollama | `LMIST_LLM_ENDPOINT`，默认 `http://localhost:11434`；发送提示词、对话和 Agent 观察结果 | 主动使用 Agent | 本机地址 |
| Anthropic Claude | `https://api.anthropic.com/v1/messages`；发送提示词、对话及 Agent 观察结果，可能包含扫描结果 | 显式设置 `LMIST_LLM_PROVIDER=claude` 并使用 Agent | 关闭 |
| DeepSeek / OpenAI-compatible | `OpenAIProvider` 默认 `https://api.deepseek.com/v1` 或显式 `LMIST_LLM_ENDPOINT`；发送提示词、对话与观察结果 | 显式选择 deepseek/openai provider 并主动使用 Agent | 关闭 |
| 外部 CVE 聚合 | CVETodo、Shodan CVEDB、NVD；仅标准服务关键词或白名单产品 CPE（版本） | 用户发起漏洞扫描；`LMIST_CVE_EXTERNAL=false` 可关闭 | 默认启用，无空闲后台调用 |
| OSV | `https://api.osv.dev/v1/query`；仅有明确 40 字符 commit 证据时发送 commit | 云源启用且存在 commit 证据 | banner-only 不查询 |
| CVE 详情 | `https://cvedb.shodan.io/cve/{id}`；发送用户输入的 CVE ID | 主动执行 `vuln-detail` | 不自动触发 |
| Sirius | `SIRIUS_API_URL`，默认本机 `http://localhost:9001`；提交目标并读取 Sirius 结果 | 配置 `SIRIUS_API_KEY` 且主动使用 Sirius | 未配置密钥即禁用 |

代码证据包括：`CveApiClient.IsExternalEnabled` 默认开启、显式 false 关闭；查询构造不使用调用方 target/service 字符串，
只用 `ServiceFingerprint` 白名单结果及端口映射。禁止 HTTP 重定向；测试断言 IP/凭据样本不在请求 URL；
`SiriusClient` 在没有密钥时禁用；API/Web 的 LLM 与内部 API 默认地址均为 loopback。

## 不属于运行时遥测的网络访问

- `dotnet restore` 联系 NuGet，Docker 构建会拉取基础镜像并安装构建依赖；这些只发生在构建/安装阶段。
- GHCR 拉取发布镜像是部署者主动执行的下载。
- 报告中的 NVD、软件升级链接只是文本，不会由报告生成器自动打开。

## 数据流边界

- SQLite `data/lucentmist.db`：扫描任务、结果、Agent 会话与扫描审计。
- `logs/`：本地运行日志；不包含 API token、Web 密码或 LLM API key 的值。
- HTML/Markdown/CSV/JSON 报告：只有用户执行 `report` 或 Sirius 报告导出时才创建；没有上传/分享代码。
- 使用 Claude 等云端 LLM 时，Agent 会把用户问题及已有 observation 发给提供商。希望扫描数据始终留在本机时，
  应保持默认 Ollama 且确认 `LMIST_LLM_ENDPOINT` 为 loopback，并设置 `LMIST_CVE_EXTERNAL=false`。

## 复核方法

本次用仓库文本搜索枚举 `HttpClient`、HTTP URL、socket、DNS、Ping 以及常见遥测 SDK 名称；再逐个追踪
构造函数、环境变量门禁和调用入口。发布前可重复：

```powershell
rg -n "HttpClient|https?://|TcpClient|UdpClient|Dns\.|Ping\(" src
rg -n "Sentry|ApplicationInsights|OpenTelemetry|Telemetry|Analytics" src Directory.Packages.props
rg -n "PackageReference" . --glob "*.csproj" --glob "Directory.Packages.props"
```

任何新增运行时网络依赖或固定域名，都必须先更新此清单再发布。
