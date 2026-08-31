# 自用回归演练：真实输出与未完成边界

日期：2026-08-31，Windows / .NET 10 / Python 3.12.8。
最终生产修复提交：`1da03785`（后续收尾提交仅补文档）。使用 Release CLI DLL，
不是模拟扫描工具或旧发布镜像；未发布新 tag，未在本轮推送。

## 范围与隔离

- 所有本轮扫描/会话/审计写入新建的 `.tmp/self-use-20260831-155729/lucentmist.db`。
- 不使用、覆盖或清理日常 `data/lucentmist.db`；报告、备份、恢复目标都留在同一个演练目录。
- `LMIST_CVE_EXTERNAL=true`，授权公网列表仅 `example.com`（一次普通 TLS 检查），局域网目标 `192.168.2.1`，本机 `127.0.0.1`。
- 诊断 API/Web 在临时 loopback 端口启动，测试结束只关闭本轮创建的子进程；没有重启用户已有 5050/5051。
- `LMIST_LLM_APIKEY` 和 `DEEPSEEK_API_KEY` 当前进程均未配置。**未复用聊天里曾泄露的旧 key**；没有“假模型通过”。

实际命令前缀为 `dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll`，下面简写 `lmist`。
数据库由 `LMIST_DB` 指向上述绝对路径，命令工作目录是仓库根目录。

## 逐步记录

| 步骤 | 命令/操作 | 本轮结果 |
| --- | --- | --- |
| 配 DeepSeek → 主 IP | `agent "看看我的ip"` | **受限，未执行模型调用**：无当前有效环境 key。操作系统枚举有 WLAN 2 `192.168.2.9`、VMnet8 `192.168.12.1`、WSL `172.17.80.1`；这不是本轮模型主接口一致性的证明 |
| Agent 本机评估 | `agent "分析 127.0.0.1 的安全风险"` | **受限，未执行**：同上。不能拿之前网关对话代替这次本机对话 |
| REPL 进入/退出 | `agent`，标准输入 `/exit` | **通过**：打印交互提示、等待/读取输入、正常退出；不涉及 LLM，不证明多轮语义记忆 |
| 本机确定性扫描 | `scan 127.0.0.1 --ports 135,445` | **通过**：1/1 在线，135/RPC、445/SMB 开放；名称/厂商/型号未知仍显示未知 |
| 网关漏洞分析 | `vuln-scan 192.168.2.1` | **通过但覆盖受限**：发现 DNS/HTTP/HTTPS 53/80/443，零版本匹配 CVE，云线索单独展示并给查固件/厂商公告建议；不是确认漏洞 |
| 公网域名证书 | `ssl-check example.com --port 443 --timeout-ms 10000` | 完成真实 TLS 检查；证书与信任状态见下文。不是扫描任意公网端口 |
| 网关证书 | `ssl-check 192.168.2.1 --port 443 --timeout-ms 10000` | **检查完成，发现风险**：名称不符/链不完整等错误，未把“未过期”等同“受信任” |
| HTML 报告 | `report --target 192.168.2.1 --format html --output <演练目录>/gateway-report.html` | 生成可读报告；1 台在线、3 端口、TLS 错误、零 CVE、`partial`。本轮发现并修正的总览误导见下文 |
| 审计 | `audit --limit 20` | 可见本轮 CLI 请求/完成的成对记录；状态含义是命令生命周期，不替代报告状态 |
| 备份 | `backup --output <演练目录>/backup.db` | checkpoint、在线备份和完整性检查完成 |
| 恢复到独立路径 | `restore <演练目录>/backup.db --database <演练目录>/restored.db --yes` | 恢复成功，切换 `LMIST_DB` 后重新 `audit --limit 20`，并直接查询 SQLite 逐条比较 |
| API/Web 启动 | 隔离端口实际启动 DLL，HTTP 查询 health 和 `/agent` | 只核实进程/HTTP/页面存在性；不是本轮浏览器交互、SSE 或真实 Web 模型验证 |

## 输出中的重要证据

### 1. REPL 与网关判断边界

```text
LucentMist Agent 交互模式。输入 /exit、exit 或 quit 退出。
agent>

未发现漏洞匹配项；不代表已确认安全。
CVE；部分开放服务未提供可验证版本，因此无法确认其漏洞状态。
53  DNS    DNS（版本未公开）   未观察到对当前扫描源开放递归
80  HTTP   HTTP (无 Server 头) 版本未知，无法确认漏洞
443 HTTPS  HTTP (无 Server 头) 版本未知，无法确认漏洞
```

记录是关键行摘录，未把终端换行后的 CVE 编号拼成新的证据。云源可能返回旧年公告、关键词不相关项、
缺少评分，不能依靠线索数量判断扫描“找到漏洞”。DNS 结论只适用于这次扫描源，不证明公网可达性。

### 2. TLS 不是只有“证书未过期”

最终域名/网关输出摘要在末节。修复前的第二轮已读到：

```text
example.com:443
CN=example.com
SAN: example.com, *.example.com
到期: 2026-10-28T06:17:21.0000000+08:00
信任状态: 可信

192.168.2.1:443
CN=192.168.1.1; issuer CN=ZTE-ROOT-CA
到期: 2031-07-10T09:32:15.0000000+08:00
ChainErrors, NameMismatch, OfflineRevocation, PartialChain, RevocationStatusUnknown
需处理：证书虽未过期，但信任校验未通过
```

第一次域名握手的撤销查询曾出现 `OfflineRevocation/RevocationStatusUnknown`，耗时 25.55 秒；
第二次 2.17 秒并显示可信。第三方网络/本机链缓存会影响结果，不把前一次失败删掉。
`--timeout-ms` 不能被当作包含平台证书链/撤销检查的严格总耗时上限。没有由此断言外站证书受攻击。

### 3. 演练发现并修复的真实问题

提交 `9c3e8073` 的实际网关报告同时存在：

```text
扫描状态：部分完成，结果不完整
部分云源失败/限流；服务版本未知
TLS: NameMismatch / PartialChain / ...
综合风险：安全
```

最后一行来自“零 CVE = 安全”的汇总，忽略报告完整性与 TLS，不适合作为自用判断。
新增 8 个回归用例，**旧实现 8/8 失败，修复后 8/8 通过**，覆盖 partial、failed、TLS 信任失败、
过期、临期、完成且无命中、已有高危但扫描不完整。修复独立提交 `1da03785`：

- 不完整时显示琥珀色“无法完整评估”，存在 TLS 风险则追加“TLS 需处理”。
- 已完成但 TLS 异常显示“需处理（TLS）”。
- 完成且没有匹配只写“范围内未命中 CVE”，不声称网络安全。
- 已知高危仍显著显示，并注明“结果不完整”，不把已有风险降为无结论。

没有扩 CVE 库、加探测功能或把线索转成确认漏洞。

### 4. 备份不能只看“文件存在”

```text
备份完成：<演练目录>/backup.db
已执行 WAL checkpoint、SQLite 在线备份与完整性检查。
恢复完成：<演练目录>/restored.db
```

使用 SQLite 只读连接执行 `PRAGMA quick_check`，再读取 `scan_audit ORDER BY id`，
比较原库、备份、恢复库的完整记录，不只比较行数。第二轮额外覆盖恢复了**自己的演练 restored.db**，
确认旧库保留在 `pre-restore-20260831074837-7bf568c70ac941bebb5e459821752d63/restored.db`；日常库未触碰。
最终轮数据比较见末节。没有做磁盘断电或库损坏注入，不能声称本轮实测了所有崩溃场景。

## 密钥与验证边界

- 新文档无真实 key，旧手册仿真 key 字串已清空；检查器自身使用拼接的不可用合成测试数据。
- 默认检查范围只剩发布验证工作流的固定 CI 测试 token 命中，脚本退出 1，人工核实不是云提供商 key；没有把警告静默忽略。
- 扩大到忽略文本时，本地 Sirius 部署目录还有示例/测试字串命中，并有超过 16 MiB 的二进制未扫描；属于不完整检查，不宣称全盘/历史零秘密。
- 已扫描文本未命中 provider-key 模式。Git 历史、数据库、压缩包、聊天不在这个保证内；已经暴露的旧 key 仍应由用户撤销。
- 缺 key 的两步仍是**未完成验证**。之前的真实 CLI/REPL/Web 证据只作为历史链接：
  [真实模型记录](agent-real-validation.md)、[上一轮最终验证](final-validation-and-push.md)。

## 本轮门禁

```text
dotnet build -c Release --no-restore
0 警告，0 错误

dotnet test -c Release --no-build --no-restore
Tools 372 + Agent 85 + Scanning 31 + API 28 = 516 通过，0 失败，0 跳过

python -B -m unittest discover -s scripts -p test_check_secrets.py
8 passed（独立 Python 检查器测试，不混进 .NET 数字）

dotnet format --verify-no-changes --no-restore
通过

docker compose config --quiet
docker compose -f docker-compose.yml -f docker-compose.self-use.yml config --quiet
通过；额外解析结果确认两服务 host_ip=127.0.0.1，允许列表转发为 true
```

当前工作区预存的 Tools `packages.lock.json`（364 行新增）和 `.codex/`、`.workbuddy/`、`deliverables/`
保持原样，不混入提交。原始本机演练产物留在忽略的 `.tmp/`，含敏感网络数据，不自动上传。

## 最终提交版本的实测摘要

最终轮：2026-08-31 15:57 开始（Asia/Shanghai）；HEAD `1da03785b4c711d725262640b595485cd7d3ff45`，
生产 `src` tree `684ece334e1b9584acbf085a9b4ecafe562561a4`。
此前第一轮记录器把 Windows CP936 输出按 UTF-8 解码，出现乱码；第二轮修正记录器重跑并发现报告误导，
第三轮才是这里的最终代码演练。没有用乱码文本或中间版报告替代最终证据。

| 命令 | 退出码 | 实测秒数 |
| --- | --- | --- |
| scan-local | 0 | 2.14 |
| repl-exit | 0 | 0.23 |
| vuln-gateway | 0 | 45.33 |
| ssl-domain | 0 | 0.83 |
| ssl-gateway | 0 | 0.45 |
| report | 0 | 39.08 |
| audit-before | 0 | 0.30 |
| backup | 0 | 0.22 |
| restore | 0 | 0.22 |
| audit-restored | 0 | 0.33 |

```text
vuln-scan：53 / 80 / 443，30 条待核实线索，0 个版本匹配 CVE。
来源：CVETodo API + NVD + Shodan API + 内置库。
部分来源失败：53 CVETodo 网络连接失败，Shodan HTTP 404；继续其他源/内置匹配。
example.com TLS：CN=example.com，SAN example.com / *.example.com，未过期，信任校验通过。
网关 TLS：未过期；ChainErrors, NameMismatch, OfflineRevocation, PartialChain, RevocationStatusUnknown。

扫描状态 partial: 1/1 设备, 3 端口, 0 漏洞, 耗时 38.8s
格式: html | 大小: 10100 字符
HTML 综合风险卡片：无法完整评估（TLS 需处理）
has_honest_card=True
has_false_safe_card=False

lucentmist.db : quick_check=ok, scan_audit=10
backup.db    : quick_check=ok, scan_audit=10
restored.db  : quick_check=ok, scan_audit=10
全部审计记录逐项比较：auditIdentical=true

API http://127.0.0.1:11843/api/v1/health : HTTP 200，包含 healthy
Web http://127.0.0.1:11844/agent         : HTTP 200，包含实验性说明
```

原始摘要 `.tmp/self-use-20260831-155729/summary.json`，可读命令输出在同目录。
报告 `gateway-report.html` 的 SHA-256：
`8e0f79b661fae11dc42a077881fab2544c5880a7babca254d2d840ae01358f86`。
网关报告是重新查询，不是前一条 `vuln-scan` 的快照，线索数量可能不同；这种变化不改变零确认漏洞的边界。

## 自用结论

**确定性扫描 → 理解线索/TLS → 生成报告 → 查询审计 → 备份并恢复，已实际执行。**
网关得出的仍是“暴露信息、证书风险、线索和下一步”，不是确认漏洞。
本轮真实 DeepSeek 两个问题因缺当前 key 未验证，不能把全部验收写成通过。
用户下一步优先照手册完成 key 撤销/新建和这两步，而不是继续扩功能。
