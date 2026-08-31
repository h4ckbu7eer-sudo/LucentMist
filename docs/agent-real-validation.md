# DeepSeek 真实对话、Web 与云端线索验证

验证日期：2026-08-31（Asia/Shanghai）。本节是本轮结果；文末保留上一轮“没有 key、仅工具验证”的历史记录，不把历史记录改写为模型实测。

## 当前结论与证据边界

真实 DeepSeek `deepseek-chat` + 本机网卡 + 获授权网关 `192.168.2.1` 已执行，**不是模拟服务器或 Mock LLM**。CLI、真实 REPL 代码路径、浏览器 Web `/agent` 均已走通。模型契约达标不等于模型判断天然正确；本轮确实复现并修复了乱码、非法 JSON、过早结束、DNS 结论矛盾和 Web 会话/流式输出问题。

- CLI “看看我的ip”：`get_my_ip` 与结论均为 WLAN 2 / `192.168.2.9/24`，网关 `192.168.2.1`；结论只说另有 2 个虚拟网卡。
- CLI 网关分析：53/80/443 全部进入 `vuln_scan`，实际调用 `open_ports=53,80,443`；自动执行 DNS 和 443 TLS 检查，无“必须指定目标”。最终结论列出信任错误、版本未知和 DNS 探测差异。
- REPL：“看看我的ip” → “分析那个子网的网关” → `/exit`，两条 user 消息同属 session `dae58d765ec84e15ab77288c876753d1`；第二轮正确分析 `192.168.2.1`。输入是 UTF-8 重定向至生产 REPL，不冒称真人手敲 TTY。
- Web：实际浏览器经实验性功能确认按钮输入问题，收到分析中的思考、工具动作/观察，再收到结论；`ssl_check` 成功，`vuln_scan` 包含全部三个端口。随后同一会话“看看我的ip”得到同一个主接口。
- 网关仍是 **0 个版本确认 CVE**，不是确认无漏洞。未公开固件/服务版本，不能把关键词结果升级成目标漏洞。TLS `NameMismatch/PartialChain/OfflineRevocation/RevocationStatusUnknown` 等进入观察和最终风险结论。

完整证据目录：[validation-evidence/deepseek-20260831](validation-evidence/deepseek-20260831/)。含网络拓扑、MAC、证书与模型文本；分享前按敏感扫描报告处理。
终端文本只归一化换行、去掉行尾填充空格及多余末尾空行；不删正文。原始模型字符串另以 JSONL 完整保存。

| 证据 | 内容 |
| --- | --- |
| [acceptance-cli-ip.txt](validation-evidence/deepseek-20260831/acceptance-cli-ip.txt) | CLI 完整本机 IP 对话 |
| [acceptance-cli-gateway.txt](validation-evidence/deepseek-20260831/acceptance-cli-gateway.txt) | CLI 完整网关分析 |
| [acceptance-cli-repl.txt](validation-evidence/deepseek-20260831/acceptance-cli-repl.txt) | 完整 REPL 两轮输入/输出 |
| [acceptance-cli-sessions.jsonl](validation-evidence/deepseek-20260831/acceptance-cli-sessions.jsonl) | 会话 ID、用户消息、完整工具结果、最终回答 |
| [confirmed-web-sessions.jsonl](validation-evidence/deepseek-20260831/confirmed-web-sessions.jsonl) | 最终 Web 两轮真实会话记录 |
| [web-stream-dom.txt](validation-evidence/deepseek-20260831/web-stream-dom.txt) | 按钮仍为“分析中”时已经出现模型思考的浏览器 DOM |
| [web-gateway-dom.txt](validation-evidence/deepseek-20260831/web-gateway-dom.txt)、[web-ip-dom.txt](validation-evidence/deepseek-20260831/web-ip-dom.txt) | 浏览器实际渲染的工具参数、最终回答、选中的同一会话 |
| [model-responses.jsonl](validation-evidence/deepseek-20260831/model-responses.jsonl) | 所有 74 次原始模型文本及逐条 JSON/action/input 校验，不只保留成功案例 |
| [contract-summary.json](validation-evidence/deepseek-20260831/contract-summary.json) | 可复算分批统计 |

## ReAct JSON 契约：真实 74 次调用

逐次检查：HTTP 200、JSON 对象含字符串 `thought`、`action` 属于实际注册工具或 `final_answer`、工具 `action_input` 是对象（或可解析为对象的 JSON 字符串），最终答案是字符串。全部原始响应均记录；**不先修复响应再统计**。

| 批次（含中间失败） | 实际调用 | 契约通过 |
| --- | ---: | ---: |
| baseline | 9 | 9 |
| fixed（尚未启用 JSON mode） | 11 | 10 |
| jsonmode | 10 | 10 |
| trial-cli | 12 | 12 |
| trial-web | 5 | 5 |
| acceptance-cli | 14 | 14 |
| web-dns-failure | 4 | 4 |
| confirmed-web | 9 | 9 |
| 合计 | 74 | **73（98.65%）** |

启用 JSON mode 后的 54 次全部符合契约；最终 CLI/Web 验收批次合计 23/23。样本只覆盖本环境/本模型/这些问题，不外推为长期可靠率。**语义正确率没有被包装成契约遵循率**：多个语法正确的回答仍错误或不完整，见下表。

早期记录器曾按不符合工具导出格式的正则提取 allowlist，将有效工具误记为 action invalid；导出器已依据每次实际请求中的 `- tool_name:` 定义重算，文件同时保留 `availableTools`。这是测量代码修正，不是隐藏模型失败。

## 真正复现的问题与修复

| 实测问题 | 修复/复验 |
| --- | --- |
| Windows 重定向 REPL 中文乱码，第二轮无法正确触发安全流程 | 重定向输入使用 UTF-8；最终 REPL 正确复用同一会话并分析网关 |
| 一次 `final_answer` JSON 字符串含未转义换行，旧解析器把整个坏 JSON 当答案 | ReAct 请求 JSON mode；严格检查结构，非法响应反馈模型并受总轮数限制，绝不当最终回答。保留 fixed 批次原始失败 |
| 模型传入 `open_ports=53`，遗漏已发现的 80/443 | 以同一目标当前轮真实 port_scan 结果补全，不重复发现端口；实际执行参数保存到观察 |
| 未完成安全检查或重复调用便直接总结 | 缺失检查反馈、重复操作不执行 IO、CLI/API 最多 8 轮；最终仍失败则明确未确认，并保留确定性证据摘要 |
| 模型忽略 TLS 信任错误，或选择 DNS 较安全的一次探测 | 结论一致性检查 + 确定性事实附录；最多两次结论纠正机会，之后降级，不无限重试 |
| 检查器误拒“不能断言未开放递归” | 纳入否定语境测试，保留 trial-web 失败证据 |
| Web 回答用证书名称“不一致”绕过 DNS 差异说明 | 限定为 DNS/递归语境；`web-dns-failure` 保留错误回答，`confirmed-web` 两次拒绝错误/不完整结论后得到明确差异说明 |
| Web 只在结束时回放、会话虽存储却未传给模型 | 真正 SSE Flush 增量进度、有界通道与断连取消；CLI/API 共用有界历史上下文，Web 接收 session ID |
| Web 输入事件未及时更新绑定字段 | 改为 oninput；浏览器实际点击发送已通过 |

最终 Web 网关用了 6 次模型调用，其中两次 final 被护栏拒绝，随后额外 UDP 检查并给出正确保守结论；不是第一次回答就正确。最终 Web IP 查询先试图仅依据快照回答，被护栏要求调用 `get_my_ip` 后完成。

## 线索质量改动

全量线索保留在工具结果和会话记录；面向用户/模型摘要按端口分组，每端口最多 3 条，显示总数与省略数。先比较已识别产品、协议、端口的可观察相关性，再比较引用数、年份、来源和稳定 ID。40 条混合线索测试验证：相关产品优先、53/80/443 三组、每组 3 条、其余 31 条不丢原始数据。

引用数/年份仅是同相关性排序依据，**不是“正在被利用”的热度证据**。不知道产品版本时，再排序也不能确认 CVE。每组给出下一步：从管理端取得厂商/型号/固件版本，对照厂商公告；不建议根据关键词直接运行利用。

## 复现方式与隐私

先构建；在调用进程环境中设置 `LMIST_LLM_APIKEY`，不要写到命令历史、配置、仓库或报告。脚本中没有 key。

```powershell
dotnet build -c Release
$env:HTTP_PROXY='http://127.0.0.1:7897'
$env:HTTPS_PROXY='http://127.0.0.1:7897'
python scripts/validate-deepseek.py --mode cli --output "$env:TEMP/lmist-private-cli-validation"
python scripts/validate-deepseek.py --mode web --recorder-port 8358 --api-port 15050 --web-port 15051 --output "$env:TEMP/lmist-private-web-validation"
# 浏览器打开 http://localhost:15051/agent；完成后在脚本终端输入 stop。
```

脚本是本轮专用、显式 opt-in：会实际探测获授权的 `192.168.2.1`，有模型调用费用。不要用于未授权环境。

- 客户端 endpoint 指向本机 8357/8358 透明记录器，后者实际转发到 `https://api.deepseek.com/v1/chat/completions`。没有替换模型回复，记录器不保存 Authorization/header/key；只保存脱敏模型文本及对话上下文。
- 本轮显式设置 `LMIST_INJECT_NETWORK_INFO=true`。本机网络信息、扫描观察和历史对话会发送给用户选择的 DeepSeek；这不是“数据完全不离家”的验证。云端 CVE 查询仍只用归一化服务/产品坐标。
- 原有 5050/5051 被用户进程占用，未停止它们。本轮验证隔离 API 15050 / Web 15051。Web 源码 DLL 用 Development 静态资源配置，**没有据此宣称 5050/5051 原进程或发布镜像通过**。
- SSE 指按思考/动作/观察/最终回答流式传递，不是 token-by-token 模型输出（上游请求 stream=false）。
- 临时记录器/本轮宿主已停止；key 仅存在验证进程环境与转发所需内存中。证据导出不包含数据库文件、请求头和应用日志。
- 导出完成后对整个工作区（含隐藏/忽略文件、排除 Git 对象目录）做精确 key 扫描，并检查本轮已提交/未提交 diff：两项均为 `ABSENT`。扫描模式经 stdin 输入，未打印匹配内容。该结论限仓库/交付物，不表示聊天中已经提供过的 key 从未出现过；建议验证结束后撤销并更换该测试 key。

## CI：实际查询，区分主工作流和自检

以下查询通过本机代理和 GitHub CLI 2.98.0 执行，认证来自现有 Git 凭据的进程内传递，未写入仓库：

```text
gh run view 33323937586 --repo h4ckbu7eer-sudo/LucentMist --json databaseId,headSha,conclusion,jobs,url
databaseId: 33323937586
headSha: ba5fc51c687b3c9fe75da2a24e2eab3466bbf602
conclusion: success
Build & Test (ubuntu-latest): success, job 99290655677
Build & Test (windows-latest): success, job 99290655777
Build & Push GHCR: success, job 99291064402

gh run view 33324176824 --repo h4ckbu7eer-sudo/LucentMist --json databaseId,headSha,conclusion,jobs,url
databaseId: 33324176824
headSha: ba5fc51c687b3c9fe75da2a24e2eab3466bbf602
conclusion: failure
Build, Test and Compose Validate: failure, job 99291288111

gh run view 33324176824 --repo h4ckbu7eer-sudo/LucentMist --log-failed
SslCertificateToolTests.ExecuteAsync_SanContainsBaiduDomains [FAIL]
Assert.Contains() Failure: Filter not matched in collection
Failed: 1, Passed: 361, Total: 362
```

上面是原始 JSON/日志字段的可读摘录。[主 CI](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33323937586) 三 job 成功；[Hourly Self-Check](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33324176824) 失败于真实外网百度证书 SAN 断言。主 CI 排除 External 类，自检未排除。本轮没有为变绿而删除/跳过测试。**这两个 run 都是任务前 ba5fc51，不是本轮新提交的远端验证**；本轮未推送、未发布镜像。

## 本轮本地门禁与剩余限制

```text
dotnet build -c Release --no-restore
0 warnings, 0 errors
dotnet test -c Release --no-build --no-restore
Tools 364, Agent 85, Scanning 31, API 28
Total 508 passed, 0 failed, 0 skipped
dotnet format --verify-no-changes --no-restore: exit 0
docker compose config --quiet: exit 0
git diff --check: exit 0
```

已知限制：

- DNS 递归观察随探测变化；未验证公网可达性，也不能用单次 UDP 响应证明递归开放。最终按多次证据保守说明差异。
- 模型仍可能作无证据推断，例如把设备归类为家庭/演示环境、把厂商 CA 签发笼统说成“自签”。信任错误是事实，自签性质/设备用途须另核验；本轮不宣称自然语言事实零错误。
- 结论冲突检查是有限启发式，不是通用语义证明；达到预算时仍可能返回带明确限制的确定性摘要。Agent 继续标为实验性。
- 外部源实测有 Shodan 404、NVD 限流/超时，来源列表表示咨询过，不保证每源贡献结果。不能从候选数量推断目标漏洞数量。
- Git 工作区预存的 `tests/LucentMist.Tools.Tests/packages.lock.json`（364 行新增）及 `.codex/`、`.workbuddy/`、`deliverables/` 均保留，不混入提交。

JSON mode 依据 [DeepSeek 官方说明](https://api-docs.deepseek.com/guides/json_mode/)；它约束语法，不保证安全判断正确。

---

## 历史：上一轮真实云源、网关工具路径验证（无模型 key）

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
