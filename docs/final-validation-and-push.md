# 最终提交真实复验与推送收尾

日期：2026-08-31（Asia/Shanghai）。这是对上一轮 6 个提交的重新验收，不沿用中间版本的结果。

## 先复验，再推送

| 被验证的代码提交 | 实际执行 | 结果 |
| --- | --- | --- |
| `e80b897e399d334134909c7eb4d1ccf0f5967c69`（原 6 提交最终版） | Release 重新构建；IP、网关两条单次对话及两轮 REPL | 两条单次对话通过；REPL 也完成；13 次模型响应均符合契约 |
| `b5a73f3420310cfaa6c42e336bdf6c55b62ee90d`（本轮 TLS 测试/解析修复） | 再次 Release 构建并执行同一真实脚本 | 两条单次对话通过；REPL 也完成；12 次模型响应均符合契约 |

之所以复验两次：本轮本地证书测试揭露了 SAN 格式化解析问题，修复涉及生产代码，不能把前一次实测冒充修复后的实测。后续证据文档提交不修改生产代码；用 `src`/`config` Git tree 校验源码等价，不把文档提交误称为重新执行了模型验证。

```text
git rev-parse b5a73f34:src b5a73f34:config
f91c3617db6f8c716ddcea11755c899bc5b78d37
331b6581e422fc9ffb269a59bf2aded745580124
```

本地实际测试产物 SHA256（仅用于识别本次本机构建，不要求不同构建环境产物相同）：

```text
lmist.dll            CFC6FEE2279CDD42D41617FEB90CDD13B807B6FF6811A0495B63C78CEFE1CA1C
LucentMist.Agent.dll 9A114EEDE11284F94B201B5FA05503D47B5996BED4D5EBD15C451724938B39FD
LucentMist.Tools.dll 71F0FFD5CD69DD1AB50EE4ACA73DAE5AF98DCE3CBE2D0F09AA3D1998D2C90A08
```

## 真实输出与判断

以下链接是完整文本/会话记录，不是手写的模拟输出。终端文本只清理行尾填充空格和多余末尾空行；原始模型文本保存在 JSONL。

- 原最终版：[IP](validation-evidence/final-push-20260831/final-e80b897e-ip.txt)、[网关](validation-evidence/final-push-20260831/final-e80b897e-gateway.txt)、[REPL](validation-evidence/final-push-20260831/final-e80b897e-repl.txt)、[会话/工具原始记录](validation-evidence/final-push-20260831/final-e80b897e-sessions.jsonl)。
- 本轮生产代码最终版：[IP](validation-evidence/final-push-20260831/final-b5a73f34-ip.txt)、[网关](validation-evidence/final-push-20260831/final-b5a73f34-gateway.txt)、[REPL](validation-evidence/final-push-20260831/final-b5a73f34-repl.txt)、[会话/工具原始记录](validation-evidence/final-push-20260831/final-b5a73f34-sessions.jsonl)。
- [全部 25 次原始模型响应](validation-evidence/final-push-20260831/model-responses.jsonl)、[逐批统计](validation-evidence/final-push-20260831/contract-summary.json)。

两次 IP 查询都调用 `get_my_ip`，工具和回答一致为 WLAN 2 / `192.168.2.9`，网关 `192.168.2.1`；虚拟网卡只在结论注明数量。

本轮最终代码的网关单次对话，实际工具记录摘录：

```json
{
  "ssl_check": {
    "input": { "target": "192.168.2.1", "port": "443" },
    "success": true,
    "trustErrors": ["ChainErrors", "NameMismatch", "OfflineRevocation", "PartialChain", "RevocationStatusUnknown"]
  },
  "vuln_scan": {
    "input": { "target": "192.168.2.1", "open_ports": "53,80,443" },
    "checkedPorts": [53, 80, 443],
    "totalFindings": 0,
    "cloudCandidateCount": 50
  }
}
```

53 确实执行 DNS 版本/递归检查；443 自动 TLS 检查成功，无“必须指定目标”。最终回答包含证书身份/信任风险、未知版本的限制、来源和管理端核查建议。该次两轮 DNS 观察均未看到递归；旧最终版复验中 DNS 观察不一致，护栏拒绝了过早否定递归的结论，再由模型纠正。不同运行结果不能混为一次，也不证明公网递归关闭。

复验没有暴露这两条指定对话的新回归。额外 REPL 的模型仍尝试过早结束，但被缺失漏洞分析的检查拦住，随后执行完整 `vuln_scan`。**25/25 是 JSON 契约遵循率，不是首次回答语义正确率。**

复现入口（凭据由调用进程环境提供，脚本没有 key）：

```powershell
git rev-parse HEAD
dotnet build -c Release --no-restore
python scripts/validate-deepseek.py --mode cli --output "$env:TEMP/lmist-private-final-validation"
```

脚本实际通过本机透明记录器转发到 DeepSeek `deepseek-chat`，执行真实生产 CLI，不替换模型/工具响应。两条单次命令分别是 `agent "看看我的ip"`、`agent "分析 192.168.2.1 的安全风险"`；额外 REPL 使用 UTF-8 重定向输入。仅适用于已获授权的此网关，本轮没有扩大扫描范围或重测 Web；上一轮 Web 证据单独保留。

## External 测试策略已统一

采用用户给出的方案 b：8 个百度 TLS 测试全部改为本地生成证书/loopback TLS/固定明文响应/纯默认参数测试。主 CI 移除 `Category!=External`，与 hourly、自检脚本一样运行全套测试。没有为了变绿删除 SAN/字段/日期/链/非 TLS 的断言。

新 SAN 测试在修改生产解析前真实失败，旧实现返回非规范 IPv6 展示字符串；该实现还依赖系统语言的 `DNS Name=` 格式。现直接解析 SAN DER 中的 DNS/IP 项。具体覆盖和限制见 [testing-strategy.md](testing-strategy.md)。

本地记录：

```text
修改生产解析前：SslCertificateToolTests，22 passed / 1 failed
ExecuteAsync_SanContainsExactGeneratedDnsAndIpNames:
Expected ["127.0.0.1", "::1", "validation.invalid"]
Actual ["0000:0000:0000:0000:0000:0000:0000:0001", "127.0.0.1", "validation.invalid"]

修改后：SslCertificateToolTests，23 passed / 0 failed
dotnet build -c Release --no-restore: 0 warnings, 0 errors
dotnet test -c Release --no-build --no-restore:
Tools 364, Agent 85, Scanning 31, API 28 = 508 passed, 0 failed, 0 skipped

./scripts/auto-check.ps1 -NoRestore
Build: PASS
Format: PASS
Test: PASS (508)
Docker config: PASS
Auto-check PASS: docs/auto-check-latest.md
```

已消除八项测试对外站证书/连通性的依赖，不承诺所有测试永远不 flaky；Windows/Ubuntu 差异仍须由本次远端 CI 验证。

## 用户核心诉求：部分达成，不夸大

**“真实 DeepSeek 下，分析我的网络能得到有用的安全评估吗？”——部分。**

- 已证实的价值：对指定真实网关，能列出暴露的 53/80/443，指出 HTTPS 证书身份/信任问题，呈现 DNS 观察边界，并给出核对固件、限制管理入口、复查 DNS 来源限制等可行动建议。这是有用的初步自检。
- 未证实的范围：本轮输入是“分析 192.168.2.1 的安全风险”，不是字面“分析我的网络”的整个子网端到端验收。单台网关的结果不能代表所有设备完成检查。
- 未达到的目标：不知道固件/服务版本时，仍无法确认 CVE、补丁状态、默认口令或真实公网可达性。没有验证是否已被攻击。不能交付“整个网络安全”的保证。
- 模型仍需要纠错护栏，安全报告仍需核对工具原始证据；JSON 合法不能证明判断全面、正确。

**“漏洞扫描对真实网关能出什么？”——暴露事实 + TLS 风险 + 待核实线索 + 建议，不是确认漏洞清单。**

最终单次网关查询获得 50 条线索、0 条版本匹配漏洞；后续 REPL 查询为 30 条线索、0 条版本匹配漏洞，受源可用性/限流影响。每端口最多展示 3 条优先线索，其余保留原始结果。泛关键词相关不等于目标受影响；需从设备管理端取得型号/固件、对照厂商公告才能继续缩小范围。因尚无这类版本证据，不能靠增加 CVE 数量宣称核心检测已完整。

## 推送与远端状态

已按本轮用户指示推送，实际触发 CI/GHCR。本轮未创建新版本号/tag；既有 0.9.5 版本 tag 未重写，主分支发布的是 main/latest/sha 镜像。

```text
git push origin main
ba5fc51c..522443ad  main -> main
# 原 6 个提交 + 本轮 TLS 测试修复 + 真实证据文档

git push origin main
522443ad..668c1c72  main -> main
# 本轮远端实际暴露的计时断言修复（仅测试/文档）
```

| 提交 | 实际工作流 | 结果 |
| --- | --- | --- |
| `522443ad` | [CI 33358159499](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33358159499) | Windows / Ubuntu / GHCR 全部 success |
| `522443ad` | [Hourly 33358190504](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33358190504) | **failure**，并发测试错误使用 250ms 速度阈值 |
| `668c1c72` | [CI 33358725600](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33358725600) | **Windows / Ubuntu / GHCR 全部 success** |
| `668c1c72` | [Hourly 33358759327](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33358759327) | **success**，完整 build / format / test / compose |

首次 hourly 失败不是 SSL 外网依赖：Tools 364/364、Agent 85/85、API 28/28；Scanning 30/31，失败是快任务 374ms 超过硬编码 250ms。慢任务 504ms、max-active=2。保留这一失败历史；随后以事件同步验证并发顺序，未修改生产调度器。本地重新 build/test/format/compose 全部通过后才推送 `668c1c72`。

实际查询命令与返回字段摘录：

```text
gh run view 33358725600 --repo h4ckbu7eer-sudo/LucentMist --json databaseId,headSha,status,conclusion,jobs,url
headSha: 668c1c72f742320ebf3b8e195a6482d78667d966
status: completed; conclusion: success
Build & Test (windows-latest), job 99385775120: success
Build & Test (ubuntu-latest), job 99385775231: success
Build & Push GHCR, job 99386205268: success

gh run view 33358759327 --repo h4ckbu7eer-sudo/LucentMist --json databaseId,headSha,status,conclusion,jobs,url
headSha: 668c1c72f742320ebf3b8e195a6482d78667d966
status: completed; conclusion: success
Build, Test and Compose Validate, job 99385870021: success

gh run view 33358759327 --repo h4ckbu7eer-sudo/LucentMist --log
0 Warning(s)
0 Error(s)
Passed! API: 28; Scanning: 31; Agent: 85; Tools: 364
Auto-check PASS: docs/auto-check-latest.md
```

完整状态字段另存 [final-ci.json](validation-evidence/final-push-20260831/final-ci.json) 和 [final-hourly.json](validation-evidence/final-push-20260831/final-hourly.json)；[首次 push CI](validation-evidence/final-push-20260831/first-push-ci.json) 也保留。JSON 文件通过 `gh run view --json ... --jq` 仅选择相关字段生成。查询过程中本机代理曾出现 TLS timeout/EOF，重试后才取得上述终态；未将查询失败等同于 CI 失败。

`668c1c72` 的生产 `src`/`config` tree 与真实复验的 `b5a73f34` 完全相同。本节的最终证据收尾提交只改文档；工作流已有 docs-only 路径忽略，因此不据此虚构又跑了一次 CI。远端实证精确对应 `668c1c72`，不是旧版 `ba5fc51c`。

## 密钥与工作区

key 仅用于验证进程环境与必要的请求内存，记录器不保存请求头；两个复验进程退出时全仓精确 key 检查均为 `ABSENT`。首次推送前仓库、暂存区和本轮提交历史均检查为 `ABSENT`，最终证据提交前再次扫描。用户任务前已有的 `tests/LucentMist.Tools.Tests/packages.lock.json`（364 行新增）及 `.codex/`、`.workbuddy/`、`deliverables/` 原样保留，未混入提交；不声称工作区从来没有用户自己的修改。
