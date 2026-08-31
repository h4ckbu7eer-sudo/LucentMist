# 授权后的真实 DeepSeek 复验：发现、修复、再运行

日期：2026-08-31（Asia/Shanghai）。不是模拟 LLM、模拟网关或历史验证的重述。

## 运行方式与证据口径

- 用户明确授权提供的 key。本次通过隐藏标准输入交给私有父进程，只设置进程环境 `LMIST_LLM_APIKEY`；没有把值放进命令参数、文件、提交或本文。
- `LMIST_LLM_PROVIDER=deepseek`、`LMIST_LLM_MODEL=deepseek-chat`、`LMIST_INJECT_NETWORK_INFO=true`。透明 loopback 记录器只转发到 `https://api.deepseek.com/v1/chat/completions`，记录真实响应，不替换响应、不保存 Authorization 请求头。
- 使用当前源码构建的 Release CLI。最终生产代码提交 `df6d827abf8dff1b7f9b3f6b0dd80f517e5c31b9`，`src` tree `b803a0d5b48836fe56264e546a2ac50bac2f0b89`，系统提示词 blob `71d0ee832630e5b28b9ce55ceb3e5821820d90d4`。后续证据文档提交不改变这些内容。
- 每轮使用独立 `.tmp/deepseek-authorized-*/validation.db`，不覆盖日常数据库。没有停止用户已有 API/Web，也没有修改目标配置、口令、证书或防火墙。
- 本轮验收是 CLI 三个单次问题和真实 REPL 两轮；不把历史 Web/SSE 或 CI 成功算作本轮复验。

命令（工作目录为仓库根目录；key 已在进程环境，命令不包含值）：

```text
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll agent "看看我的ip"
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll agent "分析 127.0.0.1 的安全风险"
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll agent "分析 192.168.2.1 的安全风险"
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll agent
```

REPL 实际标准输入为 `看看我的ip` → `分析那个子网的网关` → `/exit`，不是两次独立单次调用。

## 修复闭环（失败没有删掉）

| 轮次 | 实际问题 | 修复与回归证据 |
| --- | --- | --- |
| initial，HEAD `7791f860` | VMware Authentication Daemon 1.10/1.0 仅凭厂商名被映射成 Workstation；本机出现 32 个未验证匹配项，并被汇总为“严重” | `2f4d4315`：只有明确 Workstation 产品名才生成对应 CPE；认证协议标识不能当产品版本。泛厂商结果归关键词线索，不计为目标漏洞。新增指纹/云查询测试 |
| initial | 网关叶证书主体与签发者不同，模型仍断言“自签/自签根”；本机建议把 SMB 签名与 SMBGhost 缓解混淆 | `88751f05`：模型观察与最终工具事实包含证书身份依据，检查无证据自签断言；提示词明确 SMBGhost 补丁/服务端压缩缓解边界。第一批新增测试中 10 项修复前失败、修复后通过 |
| retry1，生产代码 `88751f05` | 出现一次空 `final_answer`；DNS 跨句说明差异和“非自签”措辞触发误拦截，最终降级为工具摘要 | `bc27ee9e`：空最终答案按契约错误反馈；DNS 差异识别允许同一行跨句但不拿 TLS 名称不匹配冒充 DNS 差异；支持“非自签”否定。新增 3 项测试在旧实现失败，修复后通过 |
| retry1 | 本机回答未经监听地址证据就称 VMware 实际绑定在虚拟网络 | 系统提示词明确回环可连接不证明物理/虚拟接口绑定；最终轮核对模型不再作此断言 |
| retry2，HEAD `bc27ee9e` | 空最终答案已被纠正，但网关回答仍建议“忽略浏览器告警需谨慎”，不适合给非专家使用 | `df6d827a`：将不绕过证书校验的处置边界送入模型观察、提示词、最终工具事实与结论检查。新增 3 项回归测试旧版失败，修复后通过 |

SMBGhost 的禁用压缩缓解只保护服务端，不保护 SMB 客户端；安装修补更新和限制 445 才是这里应说明的措施，SMB 签名不能替代。依据：[CERT/CC VU#872016](https://kb.cert.org/vuls/id/872016/)。本轮没有执行这些系统变更。

## 契约门槛

每次真实 HTTP 响应独立计数，不只挑最后一次回答：HTTP 200、合法 JSON 对象、字符串 thought、action 属于该请求实际工具清单或 final_answer、action_input 可解析为参数对象；最终答案必须为非空字符串。修复后的重试也单独计数，失败样本不消失。

门槛保持 **至少 10 次且通过率 ≥90%**；还需人工核对交付结论与实际工具事实，不能拿契约通过代替语义通过。

- initial：23/23，100%；但语义失败，不能作为完成证据。
- retry1：17/18，94.44%；空字符串虽可反序列化，按最终非空契约计为失败。旧记录器当时打印 18/18，只检验结构；这里保留原始响应并按更严格最终规则重新统计。该轮仍因结论误拦截未通过语义验收。
- retry2：18/19，94.74%；一次空答案被自动重试纠正。三组安全分析完整执行，但证书处置建议仍需上述修复，不冒充最终通过。
- final：**17/17，100%**（IP 2 次、本机 3 次、网关 6 次、REPL 6 次），全部 HTTP 200，四个 CLI 退出码均 0。四轮总计 77 次，严格契约 75 次通过；最终验收只使用最后一轮，不混算出一个更好的数字。

原始响应逐条保存在 [model-responses.jsonl](validation-evidence/authorized-deepseek-20260831/model-responses.jsonl)，保留 `capture`、`run`、每次实际工具清单、原始模型文本和重新计算的三项契约标记。
[contract-summary.json](validation-evidence/authorized-deepseek-20260831/contract-summary.json) 可独立复算上述数字。所有轮次均保留，不删掉不合格回答。

## 最终轮逐项结论

| 项目 | 最终轮实际证据 | 结论 |
| --- | --- | --- |
| 我的 IP | `get_my_ip.primaryIp=192.168.2.9`；模型称主接口 WLAN 2、子网 192.168.2.0/24、网关 192.168.2.1；虚拟网卡只提 2 个 | 通过；无 12.1/2.9 主接口矛盾 |
| 本机分析 | 135/445/902/912；`vuln_scan.open_ports="135,445,902,912"`；`totalFindings=0`、风险未知，12 条云线索不计为目标漏洞；明确 VMware 1.0/1.10 非产品版本，回环可连接不证明其它接口绑定 | 通过；不再把泛 VMware 结果汇总成 32 个目标匹配项 |
| 网关全链路 | 53/80/443 全进入 `checkedServices`；`vuln_scan.open_ports="53,80,443"`；自动执行 `service_identify` 三个端口及 `ssl_check(target=192.168.2.1,port=443)`，均 Success=true | 通过；没有“必须指定目标”，未重复端口发现 |
| DNS 证据 | 独立网关问题：service_identify=false，而 vuln_scan 观察到递归；最终结论说明差异、至少一次响应及公网可达性未确认。REPL 中两处均观察到递归 | 通过；不把一次无响应当安全，不把本机视角当公网证明 |
| TLS 风险与处置 | 两次网关 TLS 均读到 ChainErrors、NameMismatch、OfflineRevocation、PartialChain、RevocationStatusUnknown；最终答案突出身份信任风险，说明叶证书主体/签发者不同，禁止忽略告警/跳过校验 | 通过；获取证书成功不等于信任通过 |
| REPL 复用 | session `1d5cc2473c0c400f84b674a5fba80a33` 同时保存两个 user 消息；第二问不含 IP，实际工具输入仍为 192.168.2.1；`/exit` 正常退出 | 通过；不是两次单独调用冒充会话 |
| 来源与边界 | 实际来源 CVETodo API + NVD + Shodan API + 内置库；网关两次均 0 个版本匹配、20 条云线索；最终提示查固件/厂商公告，而非宣称确认漏洞 | 通过，但云源覆盖仍受限 |

最终完整 CLI 输出：[我的 IP](validation-evidence/authorized-deepseek-20260831/final-ip.txt)、[本机](validation-evidence/authorized-deepseek-20260831/final-local.txt)、[网关](validation-evidence/authorized-deepseek-20260831/final-gateway.txt)、[REPL](validation-evidence/authorized-deepseek-20260831/final-repl.txt)。
[最终会话与工具原始记录](validation-evidence/authorized-deepseek-20260831/final-sessions.jsonl) 可核对工具参数、结果及 session_id。

**这不是“模型第一遍就全答对”。** 最终网关对话仍有两次被拒绝的候选总结：一次忽略 DNS 差异，一次建议绕过证书校验；引擎反馈并阻止一次重复 DNS 调用后，模型给出的第三个总结才被交付。最后交付的是完整模型分析加工具核验事实，不是空答案或降级工具摘要。这正是本轮要验证的“发现 → 修正 → 再确认”路径。

模型的“中度关注/中风险”是证书和暴露面的定性建议，不能当作工具确认的 CVE 分数；工具 `overallRisk=未知` 仍表示漏洞状态缺少版本证据。不能把正文个别笼统措辞扩大解释为已做登录、口令强度检查或公网暴露验证。

## 构建、测试与密钥检查

```text
dotnet build -c Release --no-restore
0 警告，0 错误

dotnet test -c Release --no-build --no-restore
Tools 379 + Agent 95 + Scanning 31 + API 28 = 533 通过，0 失败，0 跳过

dotnet format --verify-no-changes --no-restore
通过

python -B -m unittest discover -s scripts -p test_*.py
14 passed（Python 测试单独统计，不混入 .NET 总数）

python -B scripts/verify-key-absence.py
使用继承的 LMIST_LLM_APIKEY 精确检查，不把 key 放进参数或输出
```

最终模型轮结束时精确检查真实输出：

```json
{"workingTree":"ABSENT","index":"ABSENT","localGitHistoryAndObjects":"ABSENT","indexObjectsChecked":388,"gitObjectsChecked":2787}
```

精确扫描范围：工作树含忽略文件、二进制及 Git 元数据，暂存区 blob，全部本地 Git 对象（含不可达旧对象）。无权限/读取错误不能算 ABSENT。检查器有合成样本回归：忽略文件、NUL 后二进制数据、Git 元数据、仅暂存区、仅历史、跨读取分块。

该保证是“指定 key 的字节值未在上述范围发现”，不是“没有任何其它秘密”，也不覆盖聊天记录、操作系统内存、远端服务记录或另行编码/加密副本。本文不保存真实 key，示例仅可使用 `<你的key>`。

## 交付边界

真实网关不公开 HTTP/DNS 服务版本，能交付的是开放面、TLS 信任错误、关键词线索与核实建议，不是确认 CVE 或利用证明。外部源限流/超时/404 会明确保留，不能把未检查等同安全。

**用户核心诉求：在本次真实设备和对话样本上，“发现设备 → 分析 → 得到可操作建议”已达成；“自动确认网关具体漏洞”仍未达成。** 验收通过指本次四组应用链路、输出证据边界和 ≥90% 契约要求通过，不代表漏洞覆盖穷尽或未经防护的模型原始答案全部正确。

533 个测试和有限次真实对话不等于所有模型回复永不犯错。真实对话中的语义校正与有界保守降级仍有必要。

原工作区已有的 `tests/LucentMist.Tools.Tests/packages.lock.json` 改动、`.codex/`、`.workbuddy/`、`deliverables/` 保留，不混入本轮提交，不通过删除它们伪造干净工作区。本轮没有推送或发布动作。
