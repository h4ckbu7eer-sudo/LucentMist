# 用户真实输出修复：不把“未知”当作识别能力

日期：2026-09-01。只对用户授权的本机和 `192.168.99.1` 验证；没有发布新版本或核实新远端 CI。
最终运行代码提交：`8408dfa2`。此后的提交仅保存验证产物和文档勘误。

## 先核实，而非照单全改

四根因初查见 [设备识别核实](device-id-deepseek-final.md)。OS 工具原已注册，现在引擎会自动补一次低置信度指纹；
HTTP 已有 HEAD/GET；DNS version.bind 查询格式正确；OUI 是 20 个前缀的小型离线兜底。
继续重复注册 OS、把 DNS 无响应硬解释为未公开、或者只增加 CVE 数量，都不能解决用户截图中的问题。

本轮以用户贴出的 scan/vuln-scan/Agent/REPL/report 输出为输入，独立请求真实网关并与 Nmap 对照。
发现有实际可读的网页身份被遗漏：HTTP/HTTPS 首页返回 `中兴智能路由器` 标题，但旧实现只看软件头。
另外发现 CLI 使用另一轮 Banner 探测展示、从 Windows 推测虚构 RPC 版本、VMware Auth Daemon 公布版本丢失、
REPL 第二轮把内部历史 JSON 当作问题打印，以及纯协议关键词结果挤进优先核实列表。

## 具体修复与边界

| 修复 | 可得结果 | 不能推导 |
|---|---|---|
| 有界 HTTP 标题/realm 识别，支持分块/压缩、HEAD→GET | 名称“网页：中兴智能路由器”、ZTE 厂商线索；错误页不作为设备名 | 标题不是确切型号、固件版本或 CPE |
| 单次分析共享 HTTP 快照；vuln-scan 表格使用匹配器的 checkedServices | 展示与匹配采用同一份实际 Banner，减少重复请求 | 不缓存到下一次分析，不保证跨次网络状态相同 |
| 删除 RPC 的 OS 继承版本，保留 VMware authd 版本 | 本机 135=未知；902/912 实际公布 1.10/1.0 | authd 协议版本不是 VMware 宿主软件版本 |
| CLI/HTML/Markdown/CSV 传递设备身份；REPL 只打印当前问题 | 报告能看见名称/厂商/依据，多轮上下文仍保留 | 本轮未重新做 Web 浏览器或完整真实 REPL 验证 |
| 云线索要求实际产品关联或版本证据才优先展示 | 1999 年及仅靠 DNS/HTTP/端口命中的结果折叠，原始记录保留 | 未展示不是“确认无漏洞” |
| Nmap 进程有界、可取消，显式 --use-nmap 结果进入匹配路径 | 可选补充真实产品/版本证据 | 默认不运行 Nmap，不调用漏洞 NSE，不保证一定识别 |
| 严格契约统计与生产解析保持一致 | 重复 JSON 属性不再被后值覆盖而算通过 | 自动重答成功不能抹去第一次契约失败 |

HTTP 总预算最多 10 秒，身份补充默认 2 秒；头上限 32KiB、解压正文上限 64KiB，最多 HEAD+GET，
不使用代理/Cookie/凭据、不跟随重定向、不保存原始正文。TLS 读取首页不代表信任通过，另由 ssl_check 评估。

## 开源参考与独立实测

依用户要求已拉取到 `tools/`，固定提交和完整来源见 [参考清单](../tools/README.md)。
Recog `xml/http_wwwauth.xml` 的 **3 条 ZTE realm 规则**转换为 C#，保留 BSD 声明。
WhatWeb 的 `plugins/title.rb` / `plugins/zte-iad.rb` 用于对照识别思路，未复制 GPL 代码；本机未运行 WhatWeb。
Nmap `http-title.nse` / `http-server-header.nse` / `upnp-info.nse` 用于核对探测边界，未复制 NPSL 代码。

独立真实 Nmap 7.95 命令（17.28 秒，exit 0）：

```powershell
& 'D:\1tools\Nmap\nmap.exe' -sT -Pn -n -sV --version-light -p 53,80,443 --script http-title,http-server-header --host-timeout 40s 192.168.99.1
```

安全摘录：53=domain、未识别版本；80=HTTP、标题“中兴智能路由器”、Server 空；443=tcpwrapped、
该次 NSE 取得 400 错误页。独立只读 HTTP GET 和原生新实现均在 80/443 取得 200 与路由器标题，未取得固件版本。
Nmap 原始输出可能含 Set-Cookie，因此不将其未经处理复制进文档。定向 SSDP 未响应；不是设备没有 UPnP 的证明。
没有 DHCP Option 来源，不伪造型号。真实 HTTP 软件版本仍未知，不能承诺“成熟工具一定识别出来”。

## 真实 DeepSeek：保留失败，修复后重跑

运行 Release CLI，真实 DeepSeek API，经本地仅转发的记录器采集，不使用脚本模型替代：

```powershell
# LMIST_LLM_APIKEY 由隐藏输入交给父进程环境，不在命令行、文档或文件中提供。
$env:LMIST_LLM_PROVIDER = 'deepseek'
$env:LMIST_LLM_MODEL = 'deepseek-chat'
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll agent '分析 192.168.99.1 的安全风险'
```

| 捕获 | 严格契约 | 实际问题/结论 |
|---|---|---|
| first | 3/3 | 名称、三端口、TLS、有限结论走通；中间代码，不能替代最终复验 |
| rejected（临时目录曾名 final） | **4/5，80%** | 第 4 条重复 action_input；旧统计器误算 5/5。另有“服务版本均未公开”混淆 DNS 无响应，**不通过** |
| strict-recheck | **4/4，100%** | ping_scan→port_scan→vuln_scan→final_answer，150 行，无 response_contract/analysis_completeness 补查；名称/OS线索/53、80、443/TLS/未知项/下一步齐全 |
| committed | **4/4，100%** | 在上述代码提交重新构建后复验，156 行；同样四轮、无契约重答或完成度补查，40 条仅关键词线索收起，给出有限评估 |

原始证据：[全部模型回复](validation-evidence/upstream-device/model-responses.jsonl)、
[严格统计](validation-evidence/upstream-device/contract-summary.json)、
[修复后完整终端输出](validation-evidence/upstream-device/strict-recheck-gateway.txt)、
[工具与会话记录](validation-evidence/upstream-device/strict-recheck-sessions.jsonl)。失败与首轮完整输出在同目录，未删除坏样本。
最终提交复验：[完整终端输出](validation-evidence/upstream-device/committed-gateway.txt)、
[完整会话](validation-evidence/upstream-device/committed-sessions.jsonl)。引擎自动 OS、三端口服务识别和 TLS 均成功，
vuln_scan 复用 open_ports；外部源错误仍被如实披露，不算“全源成功”。

strict-recheck 观察：低置信度 Linux；DNS 版本查询无有效响应、未观察到对当前源开放递归，比值 2.1 不评级；
HTTP/HTTPS 首页有标题但软件头未披露版本；TLS NameMismatch/PartialChain/吊销查询错误进入结论。
50 条关键词检索均无产品关联证据，优先展示 0 条，明确下一步查管理端型号/固件；Shodan 错误、NVD 限流仍提示覆盖不完整。
首轮曾观察到递归响应，后续轮未观察到；各轮内部共享快照一致，但不能宣称 DNS 跨时间始终一致或公网开放/关闭。

本机 `vuln-scan 127.0.0.1` 实际显示 RPC 版本未知、SMBv3.1.1、authd 1.10/1.0，没有 OS 继承的假版本。
真实 `report --target 192.168.99.1 --format html --output .tmp/upstream-gateway-report.html` 在 39.9 秒完成，
1 台设备/3 个开放端口/0 个 CVE 匹配，状态 **partial**（外部覆盖受限），报告包含网页名称、ZTE、未知型号及 TLS 风险。
命令 exit 0 表示报告已生成，不表示扫描覆盖完整或目标安全。
最终代码又生成了一份[实际 HTML 报告](validation-evidence/upstream-device/gateway-report.html)：36.7 秒、1 台设备/3 端口、partial，
新增 OS“Linux（启发式线索，置信度 30%，非确认）”。尝试用 Browser 检查实际渲染时，
浏览器安全策略拒绝本地 file URL；未换端口/浏览器绕过，因此 **视觉验收未完成**，只确认真实生成、字段和格式回归测试。

## 历史契约统计勘误

对已有原始输出按新规则复算，发现两处额外的旧“通过”实际有重复 action：

- `authorized-deepseek-20260831` final 第 5 条：最终轮 **16/17（94.12%）**，非 17/17；所有阶段 **74/77**，非 75/77。
- `device-id` first 第 4 条：**3/4**，非 4/4；该批所有阶段 **14/18**，非 15/18。repaired-a 和 committed 仍各 3/3。

旧原始文件保留以便审计，不重写坏回复。命令可独立复算（不会请求模型或输出密钥）：

```powershell
python -B scripts/audit-react-contract.py docs/validation-evidence/authorized-deepseek-20260831/model-responses.jsonl docs/validation-evidence/device-id/model-responses.jsonl
```

不能把不同代码版本的调用凑成最终版 10 次基准。本轮 strict-recheck 是定向真实回归，不承诺任意目标或模型都 100% 遵循契约。

## 门禁与诚实结论

本轮构建 0 警告/0 错误；.NET **656** 通过（Tools 441、Agent 156、Scanning 31、API 28）；Python **20** 通过。
`dotnet format --verify-no-changes --no-restore`、`git diff --check` 均 exit 0。
最终代码提交后的真实验证已完成，精确 key 检查工作树/暂存区/全部本地 Git 对象均 **ABSENT**（507 个索引对象、3359 个 Git 对象）。
通用 `check-secrets.py` 仍报 3 个既存匹配：发布工作流的固定 CI 健康检查测试凭据及两份历史日志中的相同值；
不是 DeepSeek key，不将这个启发式扫描写成全绿。它们只用于回环发布端口的 CI 测试，不可作生产凭据。
用户任务前已有的 lockfile 修改、`.codex/`、`.workbuddy/`、`deliverables/` 均未混入本轮提交；上游工具 checkout 按要求保留在 tools 并忽略，不捆绑到产品。

核心功能不是全假的：TCP 发现、网页标题/OUI 身份线索、TLS 信任检查都有真实证据。
但旧展示确实漏掉可读取信息、曾臆造版本，验证统计也曾高估成功率，这些不能用“测试很多”掩盖。
现在能交付的是有名称的有限安全评估、真实暴露面、TLS 风险和明确下一步；**不是网关型号/固件识别成功，更不是确认具体 CVE 或全面安全证明**。
