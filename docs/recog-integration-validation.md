# Recog 指纹集成与真实链路验证

验证日期：2026-09-01。

## 集成事实

- 上游：Rapid7 Recog，固定提交 `d3d20938da9f5f1e442c2419fe6c30cd651b6878`，BSD-2-Clause。
- 转换器：`tools/fingerprint-import/convert_recog.py`。
- 生成物：`src/LucentMist.Tools/Vulnerability/Data/recog-service-fingerprints.json`，950 条规则；本次 950/950 均可由 .NET 编译执行。
- 来源文件：HTTP Server、X-Powered-By、SSH、SMTP、POP、IMAP、DNS version.bind、FTP、MySQL 九个官方 XML 数据集。
- 运行入口：`ServiceFingerprint.FromBanner` → `ServiceFingerprintMatcher`；服务识别、CPE、内置 CVE 和云端查询共用同一入口。
- 安全边界：规则只处理已观测 Banner，不按端口猜产品；版本缺失不生成版本匹配结论；没有应用 CPE 的规则不会伪造 CPE。

## 真实 135/RPC 验证

在本机真实开放端口上执行 `vuln-scan 192.168.99.9`。Nmap 观测到
`Microsoft Windows RPC` 后，最终 CLI 行为为：

```text
端口  服务         已观测版本/协议                 证据
135   Windows RPC  版本未公开（Banner 已观测）    LucentMist observed banner
```

这不是 Windows 版本识别：RPC Banner 没有公开系统版本。结果保留服务身份，
`Version=null`、`HasApplicationCpe=false`，不会把端口 135 或 RPC 名称伪造成 Windows 版本/CPE。

## 真实 HTTP 验证与发现即修复

临时在 `127.0.0.1:8080` 启动 Python `http.server`，真实响应头为：

```text
Server: SimpleHTTP/0.6 Python/3.12.8
```

首次端到端检查发现 .NET `HttpClient` 将多个 Server 产品 token 表示为
`SimpleHTTP/0.6; Python/3.12.8`，而 Recog 原规则以空格连接，导致状态错误地成为
`version_not_disclosed` 并回退 Nmap。修复后，匹配器同时尝试原始 token 与等价的空格形式；
真实探测结果变为：

```text
Banner: HTTP Server: SimpleHTTP/0.6; Python/3.12.8
Status: version_observed
Reason: HEAD / 响应头公开了可识别服务版本（未经认证的 Banner 证据）
```

对应真实形式已加入回归测试。nginx、Apache、IIS、Tomcat 的 Server 头和
OpenSSH、Dropbear、Postfix、Exim、Dovecot、BIND、vsFTPd、ProFTPD、MySQL 的官方 Recog 样例也有测试。

## OS 指纹边界

- 目标与本机启用接口精确匹配时，来源是 `local_runtime`，输出运行时 OS 描述，置信度 100%。
- 远程目标优先采用 Nmap 服务返回的 `ostype` 线索；否则只组合 TTL 与已观测端口。
- TTL/端口结果明确标为 `heuristic` 和低置信度，理由逐条输出，不能据此排除另一平台 CVE，也不冒充 Nmap 主动 OS 探测。

## 验证结果

- `dotnet build -c Release --no-restore`：0 warnings，0 errors。
- `dotnet test -c Release --no-build --no-restore`：708/708 通过（Tools 486、Agent 161、API 30、Scanning 31）。
- `dotnet format --verify-no-changes --no-restore`：通过。
- `git diff --check`：通过。

真实网关 `192.168.99.1` 仍不公开 HTTP Server、DNS version.bind 或固件版本；
这属于目标证据边界，不会被写成“工具识别出了版本”。
