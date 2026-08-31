# 网关分析收敛、HTTP 证据与线索降噪复验

后续更新：本页保留脚本化 Provider 阶段的原始边界。随后已进行四轮真实 DeepSeek 复现并修复残留，见[真实网关复现记录](gateway-deepseek-reproduction-20260831.md)；不能把两类验证混为一谈。

日期：2026-08-31。基线 `621708be`；最终生产修复提交 `2622bfda95485f0da4f3e427c9a67170220f95a5`。
本批仅本地提交，**未推送、未移动 v0.9.6 标签、未声称远端 CI 已覆盖这些修复**。

## 结论与核查修正

完成度机制原本有轮数上限，不是真正的无限循环；版本未知也没有直接列入 `FindIncompleteChecks`。
实际问题是失败检查被重复要求补齐、DNS 差异触发强制改写，以及兜底输出内部失败观察，导致用户拿不到简明评估。
DNS 两处原本已使用同一函数，但会独立发请求；“共享函数”不等于“同一次观察”。

本批行为：

- 未做的端口/漏洞/TLS/DNS 检查仍要求补查；已尝试但失败是有限结论的边界，不要求无限重试。
- DNS 差异本身不阻止有限结论，确定性事实会说明需复测；否定已观察到的递归、把 TLS 错误说成安全仍受拦截。
- 达到纠错或轮数上限后，输出暴露面、TLS 风险、未知项和下一步；不把 `analysis_completeness` 内部消息当报告。
- HTTP 两处统一使用有总预算的 HEAD / → GET /，不再先被动等待 HTTP 服务发 Banner。
  不跟随跳转，不读取完整响应体，最多读取 4096 字节响应头；超限/截断/超时为抓取不完整，不能写成未公开版本。
- `version_not_disclosed` 仅指 HEAD/GET / 响应头未公开**可识别**版本，不证明所有路径都隐藏版本；`probe_incomplete` 表示抓取不完整。
  无产品证据不凭端口猜 nginx 或其它 CPE。HTTP/TLS Banner 是未经认证的声明，不能代替证书信任检查。
- 2005 年前且无版本验证证据的云关键词线索折叠，原始结果保留；已验证版本的历史漏洞不因年份隐藏。
  按相关性、CVSS 是否可用、年份、引用/来源排序，模型与最终事实摘要最多展示 5 条，再按端口分组。
- DNS 快照仅存在于一次 `ReActEngine.RunAsync`，不同会话/下一轮分析重探测；通过 `evidenceId` 核对两处复用。
  无有效响应标为 `unknown`，不冒充递归关闭；响应校验事务 ID、响应标志和查询问题。

## 完整模拟分析：50 条线索 + DNS 矛盾 + 错误总结

这是**脚本化模型和模拟工具结果**，不是 DeepSeek、不是云源真实返回。CVE 编号与评分在此用作排序测试夹具，不能作为任何真实漏洞情报。

可复现命令：

```text
dotnet test tests/LucentMist.Agent.Tests -c Release --no-restore --filter FullyQualifiedName~GatewayAssessmentEndToEndTests --logger "console;verbosity=detailed"
```

完整流程：port_scan → 自动 service_identify / ssl_check → vuln_scan（复用 `open_ports=53,80,443`）→
模型连续声称安全 → 两次纠错 → 有限评估。测试硬断言最大 5 轮，端口/漏洞/TLS 各执行一次，
最终含证据与下一步，不含 CVE-1999、不含内部纠错工具名、不保留错误的“已确认安全”。

最终全量 TRX 中实际标准输出摘录：

```text
SIMULATED gateway + scripted model: rounds=5; tool calls: port=1,vuln=1,TLS=1; source leads=50
【有限安全评估】以下结论受限于未确认项；检查完成不等于目标安全。
暴露面 192.168.2.1：受检开放端口 53, 80, 443（仅本次扫描视角）。
  HTTPS 信任风险: NameMismatch, PartialChain
  判断依据: 版本未知，无法确认具体 CVE
  端口 53 优先核实（非目标漏洞）：CVE-2024-1012
  端口 80 优先核实（非目标漏洞）：CVE-2024-1010, CVE-2024-1013
  端口 443 优先核实（非目标漏洞）：CVE-2024-1011, CVE-2024-1014
192.168.2.1 DNS 多次探测结果不一致：至少一次观察到递归响应，不能据另一次无响应认定已关闭。请复查 ACL/解析策略，公网可达性未确认。
下一步：优先核对 HTTPS 设备身份和完整证书链，不绕过信任校验；限制管理端口仅授权网段可达。
```

另一回归 `UnknownVersionsAndConflictingDns_ConvergeOnFirstQualifiedFinal` 提供诚实但没有逐字解释差异的最终回答，
验证引擎自动补充差异事实，**3 轮直接结束、0 次完成度拦截**。故不是把所有请求都强制拖到预算耗尽。

复验还修复两项边界：端口发现失败仍须出现在有限评估中；5 条配额不能被端口排序靠前的 53/80 全占，必须先全局排序。

## 真实网关工具链（不是模型复验）

在上述最终生产代码上，用临时 C# 驱动器运行真正的 `ReActEngine` 和注册的
`PortScanTool` / `ServiceIdentifyTool` / `SslCertificateTool` / `VulnerabilityScanTool`。
Provider 只依次返回 port_scan、vuln_scan、有限 final_answer 三个固定步骤；**没有调用 DeepSeek、没有使用 key**。

为了隔离网络测量与云源波动，该次设置 `LMIST_CVE_EXTERNAL=false`。因此该次不能证明云源实时质量；
50 条混合年份云线索的处理由上面的完整模拟回归证明。

实际命令（临时驱动器不属于公开 CLI 入口，保存在本机忽略目录）：

```powershell
$env:LMIST_CVE_EXTERNAL='false'
dotnet run --project .tmp/gateway-convergence/validation.csproj -c Release --no-restore
```

结果：exit 0，`Calls=3`，`Success=true`。所有目标请求只涉及用户指定网关的 53/80/443，未修改网关配置。
初次和最终代码复验均通过；初次临时驱动器有一次缺少 logger 构造参数的编译失败，修正后才开始真实请求，不算产品执行失败或成功证据。

最终原始 JSON 的字段摘录（完整输出保留本机 `.tmp/gateway-convergence/real-result.json`，不发布无关 MAC/完整证书 DN）：

| 工具/字段 | 实际结果 |
| --- | --- |
| port_scan.openPorts | `[53,80,443]` |
| service_identify 80 / 443 bannerStatus | 两者均为 `version_not_disclosed` |
| 80 / 443 bannerReason | 服务器在 HEAD/GET / 响应头中未公开可识别版本；不代表其它路径也不公开 |
| DNS versionAssessment | DNS 响应未公开软件版本 |
| DNS recursionStatus | `not_observed`：未观察到对当前扫描源开放递归，不等于证明公网安全 |
| service_identify DNS evidenceId | `44cc0a1224614c5181180b68d716fdd3` |
| vuln_scan DNS evidenceId | `44cc0a1224614c5181180b68d716fdd3`（一致） |
| ssl_check.trustErrors | `ChainErrors, NameMismatch, OfflineRevocation, PartialChain, RevocationStatusUnknown` |
| vuln_scan.portSelection | `caller_discovered`，未重复端口发现 |
| vuln_scan.checkedServices ports | `[53,80,443]` |
| CVE 判断 | 未发现版本匹配项；版本未知不能确认具体 CVE |

所以现在可以给出“开放管理面 + HTTPS 信任问题 + 查固件/限制访问/复核 DNS ACL”的有限评估。
这不是确认网关存在某个 CVE，也不是证明 DeepSeek 新版本自然语言行为、Web/SSE 或公网攻击面已经复验。

## 测试与提交

- `dotnet build -c Release --no-restore`：0 警告、0 错误。
- `dotnet test -c Release --no-build --no-restore`：**551 通过，0 失败，0 跳过**（Tools 391、Agent 101、Scanning 31、API 28）。
- `dotnet format --verify-no-changes --no-restore`：exit 0。
- Python 检查器单测：14/14，独立统计。
- `git diff --check`：通过。
- `scripts/check-secrets.py` 启发式扫描：1 条 potential（既有 release-verification 工作流的固定测试 token），0 读取错误；没有把此结果声称为零命中。此轮不作历史精确 key 检查，也未重新使用旧 key。

生产修复独立提交：

1. `653d8647` 完成度与有限评估收敛。
2. `d4aa819b` 共享 HTTP HEAD/GET 抓取与失败/未公开区分。
3. `9ddf65f3` 历史未验证线索折叠、模型展示上限。
4. `0b2a8d68` 单次分析 DNS 快照、未知状态和关联校验。
5. `dd78de45` 复验补强：端口发现失败仍是可见限制。
6. `2622bfda` 复验补强：全局选择线索后再按端口分组。

后续完整回归测试/文档提交不改变生产逻辑。预存的锁文件依赖改动及未跟踪用户目录保留，不混入提交。
