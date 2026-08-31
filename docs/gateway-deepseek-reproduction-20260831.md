# 真实 DeepSeek 网关复现：先复现、修复、再复验

日期：2026-08-31。目标：`192.168.99.1`。模型：真实 `deepseek-chat`。
初始生产基线：`4fc5715c`；生产修复：`80af4fe9`；验证入口：`3afca3d9`。
本批仅本地提交，没有推送、移动发布标签或声称远端 CI 已验证这些变更。

## 先正面回答：核心功能是假的吗？

不是全部假的，但最初的模型结论确实有不受证据支持的说法，默认呈现也冗长。这些不是用户误解。

- **本次真实验证成立**：TCP 端口发现、53/80/443 全部进入漏洞分析、自动 TLS 检查、HTTP HEAD/GET 响应头探测、DNS 观察在同一次分析内复用、云源请求和线索/目标漏洞的区分。
- **发现并修复的真实缺陷**：只扫 TCP 1–1000 却声称“未发现 RDP”；把一次 DNS 响应比 2.1 推成“风险较低”；CLI 仍每端口展示 3 条的大表且重复打印来源详情；结论再次附加长证书 DN 和全部逐端口说明。
- **仍然不完整，不能包装成漏洞确认**：网关没有在本次 HTTP HEAD/GET `/` 响应头、DNS 版本查询中提供可识别软件版本。无法由此确认固件补丁状态或具体 CVE。云端返回的是协议关键词线索，不证明目标使用相应产品。部分云源超时、404、限流，覆盖不完整。
- **DNS 的边界**：同一次分析两个工具使用同一个 `evidenceId`，消除了重复请求造成的双重说法；这不证明不同时间/不同扫描源、公网和内网一定得到相同结果。没有测公网递归或实际反射能力。
- **Agent 的边界**：这次真实模型收敛通过，不是对所有提示、模型版本和设备的零幻觉保证。新断言守卫覆盖本次复现的措辞，并不是通用自然语言证明器。

所以用户现在能得到的是“受检暴露面 + HTTPS 身份/信任风险 + 未知项 + 下一步”，不是“已攻破网关”或“已证明网关安全”。

## 实际执行与证据来源

环境变量设置 provider/model 为 `deepseek` / `deepseek-chat`；已授权密钥经隐藏输入进入父进程的 `LMIST_LLM_APIKEY`，不进入命令参数或仓库文件。示例占位符：`<你的key>`。
验证器使用仅绑定回环的记录代理，将请求原样转发到 DeepSeek，不替代模型响应；不记录 Authorization。
各轮使用独立验证 SQLite 库，不覆盖日常扫描数据。云源启用，真实网关工具没有 mock。

执行入口（要求事先安全设置环境变量）：

```powershell
dotnet build -c Release --no-restore
python -B scripts/validate-deepseek.py --scenario gateway --output <空的私有验证目录> --recorder-port 18357
```

该入口实际执行：

```powershell
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll agent "分析 192.168.99.1 的安全风险"
```

`--scenario gateway` 是单场景语义复现，不能把它的最小调用数门禁称为“10 次契约基准通过”；默认 `--scenario all` 仍要求至少 10 次且 >=90%。

完整记录在 [validation-evidence/gateway-deepseek-20260831](validation-evidence/gateway-deepseek-20260831/)。
包含每轮完整 CLI 文本、每次原始模型回复、全部会话/工具记录（包括 50 条原始线索）。导出仅去除终端行尾填充空格、做密钥脱敏，不删失败、不挑选好的轮次。

| 轮次 | 生产代码 | 模型调用 / JSON契约 | 终端行数 | 最终答案字符数 | 实际结论 |
| --- | --- | --- | --- | --- | --- |
| initial | `4fc5715c` | 4 / 4 | 292 | 2768 | 正常结束，但 RDP 越界断言、DNS 风险推断、输出冗长，未通过 |
| recheck | 修复中间版 | 3 / 3 | 156 | 1717 | 范围已准确、线索变短；仍把 DNS 响应比称低风险，部分通过 |
| final | `80af4fe9` 同一最终源码，提交前构建 | 3 / 3 | 141 | 1042 | 六项语义标准通过，无完成度补查循环 |
| committed | `3afca3d9` 提交后重新构建 | 4 / 4 | 155 | 1093 | 六项语义标准再次通过；本次多一次单目标 ping，不是补查循环 |

上述字符数取保存的最终 assistant 消息，不是只统计模型短答。初始与 final 相比：终端行数减少约 52%，最终答案字符数减少约 62%；这不是扫描速度基准。
四轮 14 次调用的原始契约全部合法；JSON 合法不意味着语义正确，前两轮的问题照样记录为失败/部分通过。提交后复验比首轮减少约47%的终端行数、61%的答案字符。

## 六项收敛标准

| 标准 | initial | recheck | final | 证据 |
| --- | --- | --- | --- | --- |
| 3–8 轮收敛，不耗尽完成度预算 | 通过 | 通过 | 通过 | 4 / 3 / 3 次模型调用；工具记录无 `analysis_completeness` |
| 暴露面 + TLS 风险 + 未知项 + 下一步 | 部分通过 | 部分通过 | 通过 | 前两轮有越界/无依据评级；final 明确 TCP 1–1000、53/80/443、TLS 错误、版本未知与固件核查 |
| 内部完成度失败不作为结论 | 通过 | 通过 | 通过 | 保存的最终 assistant 消息 |
| DNS 一致或明确差异 | 通过 | 通过 | 通过 | 每轮 service_identify/vuln_scan 的 DNS evidenceId 相等，均为 not_observed |
| 老 CVE 折叠，仅呈现少量线索 | 部分通过 | 通过 | 通过 | 初始虽无1999编号但大表显示9条；修复后全局最多5条，历史条目保留在原始数据 |
| 输出收敛、不堆50条/重复全量结果 | 未通过 | 部分通过 | 通过 | 默认CLI短视图；精简事实补充仍保留来源、未命中原因和TLS错误 |

`not_observed` 只表示本次未观察到对当前扫描源开放递归，不是“已证明递归关闭”。
final 的 DNS 证据 ID：`07a834a051164b8280b22ee588771485`（两工具相同）。
final 的漏洞结果 `portSelection=caller_discovered`，`checkedServices` 和 `openPorts` 均为 `53,80,443`；没有再次进行全端口发现。

### 提交后最终复验（committed）

`3afca3d99e5bce4a97111cbdc1a8ceea7009a0aa` 上重新执行 Release 构建，再跑同一条真实 DeepSeek 对话。后续只修改验证文档/证据，不改生产代码。

- 四次模型请求：ping_scan → port_scan → vuln_scan → final_answer，HTTP均200，严格JSON/action/action_input均通过。自动补充三个service_identify与一次ssl_check；`analysis_completeness` 观察数0，未耗尽预算。
- DNS两处 `evidenceId=b87c30aa6ce4433b8deecee46ef43f5f`，均为 `not_observed`。
- `portSelection=caller_discovered`；`openPorts`/`checkedServices` 为53/80/443，TLS检查成功返回五项信任错误。
- 本次40条关键词线索（前几轮50条），说明外部源实时可用性/限流会改变覆盖；没有把这些结果伪装成确认漏洞。默认仍最多展示5条，无1999编号污染前列。
- 六项标准均通过。最终回答明确范围与WAN未知，指出TLS名称/链问题，要求可信渠道核实身份和固件；DNS字节比未被评级为低风险；没有用证书年份推断固件过旧。
- 有少量紧凑事实补充用于补齐模型遗漏的错误码与来源，不是删除原始工具数据。原始 `thought` 仍有“DNS未开放递归”的简写，最终给用户的结论明确限定为“本次未观察到”，默认不展示详细推理；不能把模型内部措辞视为额外测量证据。

对应构建文件 SHA256：

```text
lmist.dll: AC2DA6412892123181DD3F3B0BE623DBF890144F9FFB7026ADC442604C8D36C8
LucentMist.Agent.dll: 1B31D6AEB3403D8F3C49499C64958710911A0779F4F5171FD9E4E1CA8A28EFBE
```

这次只验证CLI网关路径，没有把早前Web、模拟Provider或已发布镜像验证冒充成本轮真实Web/远端CI证据。

## 问题 → 修复 → 复验

1. **扫描范围丢失**：port_scan 增加 `scannedPortRange`/`scopeNote`；最终结论守卫拒绝范围外常见端口的“未发现/已关闭”断言。提示词明确只扫1–1000不能排除RDP，不因纠错自动扩大扫描。final 明确范围外未知。
2. **DNS 单次测量被拔高成风险评级**：提示词区分字节比与攻击风险，断言守卫要求改写不受支持的低风险结论；否定句如“不能据此说明风险较低”不会误拦。final 仅报告比值，不再给低风险评级。
3. **呈现没有应用全局上限**：Agent 默认只显示检查过程、全局最多5条线索及简短云源失败信息；详细推理和表格用 `-v` 查看。全部原始工具结果仍写会话记录。零匹配、来源、覆盖不足未被隐藏。
4. **事实追加冗余**：模型已准确覆盖 TLS/DNS 时不重复追加；缺失时补简短必要事实，不再打印整段 DN。补充仍保留信任错误、中间人风险边界以及证书过期，真实漏洞条目不因精简丢失。

## 最终本地门禁

```text
dotnet build -c Release --no-restore
已成功生成。0 个警告，0 个错误。

dotnet test -c Release --no-build --no-restore
Tools: 392 passed; Agent: 113 passed; Scanning: 31 passed; API: 28 passed
Total: 564 passed, 0 failed, 0 skipped（基线551，新增13）

python -B -m unittest discover -s scripts -p "test_*.py"
Ran 14 tests. OK

dotnet format --verify-no-changes --no-restore
exit 0

git diff --check
exit 0
```

已执行精确密钥扫描，不是仅扫常见模式：工作树（含忽略文件）、暂存区对象、所有本地 Git 对象（含不可达对象）。每次真实调用后的扫描均为 ABSENT；最终提交后的复核另记于收尾段。
任务前已有的 Tools `packages.lock.json` 364行修改及未跟踪 `.codex/`、`.workbuddy/`、`deliverables/` 保留，不混入本批提交。

### 密钥检查的可复核输出

源码与验证入口提交后（`3afca3d9`），通过持有密钥的验证父进程执行 `python -B scripts/verify-key-absence.py`，命令本身没有密钥参数：

```json
{"workingTree":"ABSENT","index":"ABSENT","localGitHistoryAndObjects":"ABSENT","indexObjectsChecked":417,"gitObjectsChecked":2983}
```

证据文档纳入暂存区、提交后仍执行相同检查；不以这份早期对象数量替代最后复核。验证父进程结束会清除自身的密钥环境变量。
另跑启发式 `check-secrets.py` 有1个既有命中：`release-verification.yml:63` 的公开工作流测试凭据，不是本次授权密钥；不能把这个检查说成“零启发式命中”。
