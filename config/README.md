# LucentMist 配置

## CVE 热加载

`CveDatabase` 在首次使用时读取以下路径之一：

1. `LMIST_CVE_DB_PATH` 环境变量指向的 JSON 文件
2. 工作目录下的 `config/cve-database.json`
3. 应用基目录下的 `config/cve-database.json`

默认 `config/cve-database.json` 为空数组，不额外增加规则。需要自定义规则时，将 `config/cve-database.sample.json` 中的示例复制到 `config/cve-database.json`，按相同结构追加即可。

字段说明：

| 字段 | 必填 | 说明 |
|------|------|------|
| `Cve` | 是 | CVE 编号，如 `CVE-2024-3400` |
| `Name` | 否 | 漏洞名称，缺省使用 CVE 编号 |
| `Port` | 是 | 匹配的端口 |
| `Service` | 否 | 服务名，缺省为 `?` |
| `Risk` | 否 | `critical` / `high` / `medium` / `low`，缺省 `medium` |
| `MatchBanner` | 否 | 包含匹配或 `产品 < 版本` 格式 |
| `DetectProbe` | 否 | 验证探测类型，如 `http_version` |
| `Fix` | 否 | 修复建议 |

修改文件后需要重启进程，`CveDatabase` 只在静态初始化时加载一次。

## CLI 配置

根目录 `config/appsettings.json` 仅供 CLI 的 LLM 配置读取，目前只使用 `Provider`、`Model`、`OllamaEndpoint`、`ClaudeApiKey` 四个键。

API 和 Web 不读取该文件，统一使用环境变量：

- `LMIST_LLM_PROVIDER`
- `LMIST_LLM_MODEL`
- `LMIST_LLM_ENDPOINT`
- `LMIST_LLM_APIKEY`

Redis、文件日志、扫描默认参数等旧配置键已被移除，不再作为配置入口。

## 外部 CVE API

`CveApiClient` 默认查询 CVETodo、Shodan CVEDB、NVD；无需 API key。Shodan 的免费许可仅限非商业使用。
只发送标准服务关键词或识别出的产品/CPE，不发送目标 IP、原始 banner 或报告；服务提供方仍会看到出口 IP。
仅有明确 Git commit 才查询 OSV。离线使用请显式设置：

```bash
export LMIST_CVE_EXTERNAL=false
```

单源 8 秒总预算、最多 6 个并发请求；NVD 请求至少间隔 6.1 秒，超额跳过并显示限流。
失败不抑制其他源和内置规则，结果显示每源状态。云端关键词/CPE 候选不代表已确认漏洞或已验证目标版本。
