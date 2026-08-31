# 设备识别：先核实、修复、真实 DeepSeek 复验

日期：2026-09-01（UTC+8）。目标为用户授权的 `192.168.99.1`，扫描源 Windows `192.168.99.9`。
最终运行代码提交：`a042893a7b1522d9ea3e79026dd185da4de0fb09`。
此后仅补验证文档；本批未发布新版本、未推送，也未宣称新的远端 CI 或 GHCR 通过。

## 1. 修改前四根因核实

基线 `82fc9c69`，既有真实记录见 [0.9.8 网关会话](validation-evidence/release-0.9.8/gateway-sessions.jsonl)。

| 项目 | 代码与既有实测 | 决策 |
| --- | --- | --- |
| OS 指纹 | ToolRegistryFactory 已注册 OsFingerprintTool；ReActEngine 只自动补服务识别/TLS；既有网关会话未调用 OS 工具 | 不重复注册。安全分析在 port_scan 成功后补一次 OS 探测，复用开放端口，写入观察/审计 |
| HTTP | HttpBannerProbe 已有 HEAD→GET 和 Server/X-Powered-By，非完全没读头；上限 4KiB，无 Via 收据 | 提升完整头预算至 32KiB，保留方法/状态行/头长度及三个公开软件字段；不保存 Cookie/正文 |
| DNS | version.bind TXT CH 格式正确；已有单次分析共享快照；没有 hostname.bind/SOA | 增加查询及独立状态，身份/SOA 不当作版本；保留一致快照 |
| OUI/mDNS/呈现 | OUI 内置 17 前缀/14 个厂商名称标签，支持外部离线表；ZTE/Huawei/TP-Link 已有，D-Link/小米缺失。mDNS 仅反向 PTR。ARP/ip-neigh 只有 IP/MAC；线索展示上限已存在 | 补已核实前缀，限定 PTR→TXT 查询；不编造 DHCP Option。保留线索限量；补端口不确定性与 TLS 中文说明 |

OS 不是可靠的硬过滤条件：同一 TTL 可能对应多种系统，SMB 也可能运行于 Linux。
本批 **不实现按 TTL 删除 Windows/Linux CVE**；OS 只给相关线索小幅排序加分，所有候选及版本证据保留。
`vuln_scan` 接收同目标 `os_evidence` 并返回 `osEvidence`，不把 OS 推测发送给云源冒充 CPE。

开源借鉴及可运行路径见 [fingerprint-sources.md](fingerprint-sources.md)：
Recog `xml/http_servers.xml` 精确转换 2 条；独立 Redis INFO 规则 1 条。
Nmap 当前对应 `dns-nsid.nse`，不是假称导入不存在的 dns-version.nse。
OUI 补到 20 前缀/16 个厂商名称标签，远非完整厂商库。

## 2. 真实模型执行，不隐去失败

执行 Release CLI：

```powershell
# LMIST_LLM_APIKEY 仅在父进程环境变量中由隐藏输入提供，不放在命令参数/文件中。
$env:LMIST_LLM_PROVIDER = 'deepseek'
$env:LMIST_LLM_MODEL = 'deepseek-chat'
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll agent "分析 192.168.99.1 的安全风险"
```

验证脚本的回环记录器只转发到真实 DeepSeek API，不替换模型响应。完整记录包含失败回答、工具结果和最终回答；
导出器仅脱敏密钥模式并去掉终端行尾填充，不删坏样本。

| 捕获 | 原始契约 | 实际结果 |
| --- | --- | --- |
| first | 4/4 | OS 确已调用，但首次结论把 DNS 比值 2.1 推成低风险，被守卫纠正；另有无响应被写成版本未公开 |
| failed（临时目录曾名 final，不代表通过） | **5/8，62.5%** | 强化 DNS 解释后暴露 JSON 不合法和 TLS 同义表述被误拦；本轮不通过 |
| repaired-a | 3/3 | 修复后 3 轮，无补查/契约重答，有限评估完成 |
| committed | **3/3** | 在上述最终代码提交上重新构建并运行，3 轮，无补查/契约重答，147 行原始终端输出 |

原始记录：[契约统计](validation-evidence/device-id/contract-summary.json)、
[所有模型回复](validation-evidence/device-id/model-responses.jsonl)、
[最终 CLI 输出](validation-evidence/device-id/committed-gateway.txt)、
[最终会话/工具记录](validation-evidence/device-id/committed-sessions.jsonl)。
first/failed/repaired-a 的完整会话与 CLI 文件也在同目录。

本次所有阶段合计 15/18，不写成全程 100%；修复后两次为 6/6。
这两次是定向回归，不是最终代码 10+ 次契约基准，也不能保证任意模型/目标永不回归。

### 实测发现 → 修复 → 复验

- DNS 无响应不等于目标隐藏版本；比值不是攻击评级：向模型提供明确解释，并保留事实核验/有限纠正，不要求无限复扫。
- JSON 重复字段、末尾分号、非法换行：工具参数对象与最终答案字符串分别给合法示例；DeepSeek 温度设为 0；客户端继续严格拒绝坏 JSON，不宽松计作成功。
- “证书不可信”已表达风险，却因缺少“信任”两字被重答：认可准确同义表述，仍拒绝无风险/绕过校验等无依据断言。
- 新指纹最初把 Apache Tomcat 抢先识别为 Apache HTTP Server：既有回归捕获后修正，带版本的具体产品证据优先。
- 自动 OS 探测补充 TCP 存活证据：ICMP 被挡时不将已知 TCP 存活设备写成不可达。

## 3. 最终提交上的工具证据

实际 LLM 动作是 `port_scan → vuln_scan → final_answer`。
引擎在第 1 轮自动执行 `os_fingerprint`、三个 `service_identify` 和 `ssl_check`，不是只在提示词里要求模型做。
`vuln_scan` 输入复用 `open_ports="53,80,443"` 和同目标 OS JSON。

| 项目 | 真实观测 | 可得结论 |
| --- | --- | --- |
| TCP | 扫描 1–1000；开放 53/80/443 | 其它受检端口未连接成功，不等于已关闭；范围外及 WAN 可达性未知 |
| OUI | MAC 00:11:22:33:44:55，IEEE 对应 ZTE | 有厂商线索，不证明型号/固件 |
| OS | TTL=64，Linux 得分/置信度 30，evidenceType=heuristic | 仅低置信度推测，不排除其它平台 |
| HTTP 80 | HEAD 400、完整头 220 字节；GET 200、486 字节；Server/X-Powered-By/Via 均为空 | GET / 确有完整响应，本次软件头未公开；不是读到一半。其它路径/虚拟主机不在证明范围 |
| HTTPS 443 | HEAD 400/220 字节；GET 200/516 字节；三个软件头均为空 | 与 HTTP 相同边界，不能从端口猜 nginx 或设备版本 |
| DNS 版本/名称/SOA | version.bind TXT CH、hostname.bind TXT CH、2.168.192.in-addr.arpa SOA IN 均无有效响应 | **未知**，不能证明目标永远不公开版本 |
| DNS 递归 | 同一 evidenceId `5a5981785e31437298af88f1184c84c7`；not_observed；请求 29/响应 61 字节，比值 2.1 | 本次源未观察到递归开放；未验证公网反射能力，不评级为低风险 |
| mDNS / DHCP | 定向 mDNS 无有效响应；邻居表无 DHCP Option，未监听 DHCP | 名称、型号未知；不能说设备没有广播或没有 DHCP |
| TLS | 名称不匹配、链不完整、吊销状态未知/查询不可用；叶证书 UTC 到期 2031-07-10 01:32:15 | 证书身份/信任风险真实；主体与签发者不同，不能称叶证书自签；不证明已遭攻击 |
| CVE | 0 个版本匹配，40 条关键词线索，10 条历史线索折叠；Shodan HTTP 错误、NVD 限流 | 有限覆盖下的线索与建议，**非确认漏洞、非安全证明** |

另作三次独立小型 UDP 查询（每次等 1800ms，只检查是否有报文）：version.bind、hostname.bind、反向区域 SOA 均超时。
因此本机视角确实未收到这些查询的回复；不能推断设备的固件、永久策略或其它访问位置的表现。

最终结论已给出暴露面、TLS 风险、未知项及登录管理端确认型号/固件、核对证书链、限制管理访问等下一步。
没有反复强制扫来“凑出”版本。型号未知未被伪装成某款 ZTE 型号。

## 4. 门禁与交付边界

在最终代码提交重新运行：

```text
dotnet build -c Release --no-restore
  0 warnings, 0 errors
dotnet test -c Release --no-build --no-restore
  Tools 421 + Agent 148 + Scanning 31 + API 28 = 628 passed, 0 failed, 0 skipped
dotnet format --verify-no-changes --no-restore
  exit 0
git diff --check
  exit 0
python -m unittest discover -s scripts -p 'test_*.py'
  14 passed
```

新增 38 项 .NET 用例，含本机 UDP 服务驱动的真实 mDNS PTR→TXT 发送路径、DNS 压缩/坏报文、
大 HTTP 头、CPE 不臆测、OS 传递、TLS 中文解释、契约与语义守卫回归。
本轮测试/真实模型运行于 Windows；未声称完成新的 Linux 运行时或 Web 浏览器实测。

密钥精确核查覆盖工作树（含隐藏/忽略文件）、暂存区、全部本地 Git 对象（含不可达对象），
最终运行检查均 ABSENT；文档提交后再次核查。密钥未放入代码、文档、命令参数，父进程退出时清除环境变量。
不把用户预先修改的 `tests/LucentMist.Tools.Tests/packages.lock.json`、`.codex/`、`.workbuddy/`、`deliverables/` 纳入提交或清除。

五个代码提交：`f3b91203` HTTP/指纹；`96658a08` DNS/mDNS/OUI；`bed51ff3` OS 链路；
`462e3cbb` TLS/端口说明；`a042893a` 真实模型回归修复。验证材料独立提交。
有依赖的代码提交应按逆序回滚；不要只撤销共享解析器而保留依赖方。

**结论：可以得到有依据的有限安全评估；不能自动获得未公开/未响应的型号和版本，也没有确认该网关存在具体 CVE。**
