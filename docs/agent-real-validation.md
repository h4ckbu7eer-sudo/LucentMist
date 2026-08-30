# 真实云源、网关工具路径验证

本地日期：2026-08-31；脚本记录 UTC `2026-08-30T16:50:54.1351774+00:00`。

## 证据边界：不是 DeepSeek 对话验证

本轮用户消息没有实际 key；Process/User/Machine 三处 `LMIST_LLM_APIKEY configured=False`。
因此下列两条真实模型对话 **未执行，待环境配置**，没有伪造模型回答：

```powershell
$env:LMIST_LLM_PROVIDER='deepseek'
$env:LMIST_LLM_MODEL='deepseek-chat'
# LMIST_LLM_APIKEY 需用户在环境中配置；不要写入脚本、仓库或文档。
dotnet run --project src/LucentMist.CLI -c Release -- agent '分析 192.168.2.1 的安全风险'
dotnet run --project src/LucentMist.CLI -c Release -- agent '看看我的ip'
```

下面已执行的是 **真实生产工具 + 真实网关 + 真实云 API**，不是 TCP 模拟器，也不是 LLM 对话。
它不能证明真实模型会正确选择工具/参数或停止时机。

## 可复现命令

```powershell
$env:HTTP_PROXY='http://127.0.0.1:7897'
$env:HTTPS_PROXY='http://127.0.0.1:7897'
Remove-Item Env:LMIST_CVE_EXTERNAL -ErrorAction SilentlyContinue
dotnet run --file scripts/validate-cloud-gateway.cs -c Release -- --authorized-target 192.168.2.1
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll vuln-scan 192.168.2.1
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll ssl-check 192.168.2.1 --port 443
```

代理是本机验证环境，不是应用硬编码配置。脚本无参数不会扫描；只应指定自己获授权的目标。

## 脚本真实输出摘录

仅摘取字段便于评审；不是完整原始工具响应。命令退出码 0。

```json
{
  "evidenceType": "real tools + real APIs; not an LLM dialogue",
  "externalSetting": "unset (default enabled)",
  "llmKeyConfigured": false,
  "builtInRuleCount": 18,
  "primaryIp": "192.168.2.9",
  "primaryInterface": "WLAN 2",
  "openPorts": [53, 80, 443],
  "vulnerability": {
    "overallRisk": "未知",
    "totalFindings": 0,
    "cloudCandidateCount": 40,
    "portSelection": "caller_discovered"
  },
  "ssl": {
    "isExpired": false,
    "isTrusted": false,
    "trustErrors": ["ChainErrors", "NameMismatch", "OfflineRevocation", "PartialChain", "RevocationStatusUnknown"]
  },
  "publicOpenSshCoordinateQuery": {
    "count": 25,
    "allUnverified": true,
    "incorrectlyIncludesFixed201815473": false
  }
}
```

`injectedNetworkContext` 同样输出：`主接口: WLAN 2；主 IPv4: 192.168.2.9/24；网关: 192.168.2.1；另有 2 个虚拟网卡（非主接口）`。
这证明工具与注入来源一致，不证明未运行的模型会遵守它。

| 真实检查 | 结果 |
|---|---|
| 53 DNS | `DNS（版本未公开）`；`未观察到对当前扫描源开放递归`，不是互联网范围无放大风险证明 |
| 80 HTTP | `HTTP (无 Server 头)`；未知版本，不猜 nginx |
| 443 HTTPS | TLS 上完成 HEAD，`HTTP (无 Server 头)`；独立 ssl_check 返回证书信任错误，无“必须指定目标” |
| 复用端口 | `portSelection=caller_discovered`，来自实际 port_scan 的 53/80/443，不重复发现 |
| 云源默认开关 | 环境变量 unset，仍发生查询 |
| CVETodo | 53/80/443 均 `ok`，各返回 10 条关键词记录 |
| Shodan | 网关泛协议查询均 HTTP 404；实际响应 `{"detail":"No information available"}`，未隐瞒为成功 |
| NVD | 53 `ok` 返回 10 条；80/443 `rate_limited` 为本地 6.1 秒间隔跳过 |
| 目标 CVE 结论 | 40 条协议关键词线索、0 个目标漏洞匹配、风险未知；不把线索计成网关漏洞 |

单独查询公开软件坐标 OpenSSH 9.8p1（**不是网关 SSH 服务测试**）：CVETodo / Shodan / NVD 均 `ok`，各取 10 条，
合并及本地排除后 25 条，全部 unverified，未包含已修复的 CVE-2018-15473。OSV 未查：没有 Git commit 证据。
源内容随时间变化，40/25 不是固定断言。

## 真实请求定位的 CPE 格式问题

```text
GET https://cvedb.shodan.io/cves?product=openssh&limit=10
HTTP 200; fields=cves; count=10

GET /cves?cpe23=cpe:2.3:a:openbsd:openssh:9.8p1:*:*:*:*:*:*:*&limit=10
HTTP 404; {"detail":"No information available"}

GET /cves?cpe23=cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*&limit=10
HTTP 200; fields=cves; count=10
```

上面为可读性解码的 URL，实际请求对 CPE 做 URL 编码。修复后本地查询保留 upstream `9.8p1`，CPE 使用 version/update 分字段。

## 未完成项

- 两条真实 DeepSeek 对话待用户配置环境变量 key，不能报告为通过。
- 网关未公开服务/固件版本，不能从云端关键词结果确认其 CVE；需设备管理端导出的型号/固件证据或厂商公告对照。
- MySQL/MongoDB 数据访问授权未主动验证；仅输出暴露与待检查提示。
- 本轮源码/测试/工具验证不等于新镜像发布或远端 CI 成功。

实现与参考来源见 [cve-matching-sources.md](cve-matching-sources.md)。

## 本地回归门禁

```text
dotnet build LucentMist.slnx -c Release --no-restore
已成功生成。0 个警告，0 个错误。

dotnet test LucentMist.slnx -c Release --no-build --no-restore
Tools: 362 passed; Agent: 66 passed; Scanning: 31 passed; API: 26 passed
合计 485 passed，0 failed，0 skipped。

dotnet format LucentMist.slnx --verify-no-changes --no-restore
exit 0
docker compose config --quiet
exit 0
git diff --check
exit 0
```

新增覆盖包括：默认开关、显式离线、真实接口 JSON 契约、单源失败/超时隔离、请求隐私、
上游版本上下界、OpenSSH CPE update 编码、虚假产品 CPE 排除、泛关键词线索不计风险、
报告降级、CLI 版本状态/来源、HTTP 空响应头、数据库授权未知与 Redis 元数据只读证据。
