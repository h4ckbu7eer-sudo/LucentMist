# 家庭监控实测记录 — 2026-09-06

范围：当前源码的 `monitor`、白名单/告警/审计和 `diagnose`，不是 GHCR 发布验证。
实现提交：`cd47cb49`（基线/告警/信任）、`51077cc4`（分层诊断）、`e1825a86`（有界调度/CLI 接入）。
未使用 LLM、DeepSeek key，也未尝试登录、改写或隔离网关设备。
运行环境：Windows，实际物理接口是 `WLAN 2 / 192.168.99.5/24`，不是历史记录中的 `.2.9`。
本轮使用独立的 `LMIST_DB` 验证数据库，不改变日常数据库中的信任列表。

## 1. 真实家庭网段，两轮监控

执行命令（项目根目录，已完成 Release 构建）：

```powershell
$env:LMIST_DB = Join-Path (Get-Location) 'data/home-monitor-validation-20260906.db'
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll monitor --interval 1 --subnet 192.168.99.0/24 --ports 22,53,80,443 --cycles 2
```

真实 stdout 摘录，时间为本机 UTC+8：

```text
2026-09-06 04:56:07 观测 3 台设备，产生 0 条告警；completed
已建立首轮基线（不自动代表可信），请核对设备并使用 --trust 标记。
2026-09-06 04:57:22 观测 3 台设备，产生 0 条告警；completed
```

两轮设备表相同，文档省略 MAC，原值保留在本地验证数据库：

| IP | 名称 / 厂商证据 | TCP 22,53,80,443 结果 |
| --- | --- | --- |
| 192.168.99.1 | 网页：中兴智能路由器 / ZTE Corporation | 53,80,443 |
| 192.168.99.5 | DESKTOP-DEV / Generic PC Vendor | 所选端口无成功连接；不是全端口无服务 |
| 192.168.99.10 | 名称未知 / 本地管理或随机 MAC，无法由 OUI 确认厂商 | 所选端口无成功连接 |

结论：首轮基线写入、下一轮恢复与对比通过；无变化没有重复告警。
本次没有发现历史命名的 android-99.local，不能凭历史记录补入本轮设备表。

代码提交到 `e1825a86` 后，另跑 `monitor --once --ports 22,53,80,443`（省略 `--subnet`）：
实际自动选择 `192.168.99.0/24`，`10:26:57` 仍为 3 台、0 告警，退出码 0；
本机信任标记保留。自动选网段没有使用历史 `.12.0/24` 虚拟网段。

## 2. 信任、持久化查询与审计

仍使用上述验证库和相同范围：

```powershell
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll monitor --subnet 192.168.99.0/24 --ports 22,53,80,443 --trust 192.168.99.5
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll monitor --subnet 192.168.99.0/24 --ports 22,53,80,443 --devices
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll monitor --subnet 192.168.99.0/24 --ports 22,53,80,443 --alerts
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll audit --limit 5
```

实际：信任命令返回“已信任 MAC …”，新进程查出的 `.2.5` 显示“观测到/可信”；
其余设备未信任。告警查询显示“当前范围暂无已记录告警”，不是“没有漏洞”。
`audit` 查到两条 `cli-monitor / monitor / completed`，UTC 时间分别为
`2026-09-05 20:56:07`、`20:57:22`，摘要均为 3 台设备、0 条告警。

可信新设备不告警、未信任新设备高告警、IP 被新 MAC 复用不继承信任，由确定性单测验证；
未把写入白名单本身冒充“真实手机加入已验证”。

另外执行现有 `backup --output data/home-monitor-backup-validation-20260906.db`，实际返回
“已执行 WAL checkpoint、SQLite 在线备份与完整性检查”。随后将 `LMIST_DB` 指向该备份文件，
`monitor --devices` 仍读出同样 3 台设备、时间戳及本机可信标记。
这是备份包含新增表的实证；未覆盖或恢复日常数据库。

## 3. 真实 TCP 端口变化告警（本机受控监听）

使用另一独立数据库 `data/home-monitor-port-validation-20260906.db`、
范围 `127.0.0.1/32`、端口 `55125`。这是真实 TCP 监听，不是伪造扫描结果；
它验证端口变化链路，不验证新硬件加入 Wi-Fi。

首个测试夹具有误：用端口 0 建 `TcpListener`，停止后再次启动会获得另一个动态端口，
而扫描仍指定原端口，所以最初三轮都是无连接、无告警。未将该次记为通过。
修正夹具为显式绑定原端口，并输出 `ACTUAL_LISTEN_ENDPOINT=127.0.0.1:55125` 后复验：

```powershell
$env:LMIST_DB = Join-Path (Get-Location) 'data/home-monitor-port-validation-20260906.db'
# 先确保所选本机端口未占用；若占用请选择其他端口，所有轮次须使用同一个值。
$monitorTestPort = 55125
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll monitor --once --subnet 127.0.0.1 --ports $monitorTestPort
$monitorTestListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $monitorTestPort)
try {
    $monitorTestListener.Start()
    $monitorTestListener.LocalEndpoint
    dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll monitor --once --subnet 127.0.0.1 --ports $monitorTestPort
} finally { $monitorTestListener.Stop() }
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll monitor --once --subnet 127.0.0.1 --ports $monitorTestPort
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll monitor --alerts --subnet 127.0.0.1 --ports $monitorTestPort
```

真实关键输出：

```text
ACTUAL_LISTEN_ENDPOINT=127.0.0.1:55125
2026-09-06 10:12:40 观测 1 台设备，产生 1 条告警；completed
#1 09-06 10:12:40 medium 127.0.0.1 port_added：新增可连接 TCP 端口
55125；核对是否启用了新服务，不据此认定被入侵。
2026-09-06 10:12:41 观测 1 台设备，产生 1 条告警；completed
#2 09-06 10:12:41 low 127.0.0.1 port_not_observed：TCP 端口 55125
本次未连接成功；可能关闭、过滤或暂时不可达，不能确定已关闭。
```

`--alerts` 新进程读到这两条记录。测试监听已在 finally 中停止，没有留下常驻服务。

## 4. 真实网关的可选漏洞检查

```powershell
$env:LMIST_DB = Join-Path (Get-Location) 'data/home-monitor-vuln-validation-20260906.db'
$env:LMIST_CVE_EXTERNAL = 'false'
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll monitor --once --subnet 192.168.99.1 --ports 53,80,443 --check-vulns
```

真实输出 `2026-09-06 10:13:38 观测 1 台设备，产生 0 条告警；completed`，
网关名称为中兴智能路由器，端口 `53,80,443`，退出码 0。
这只验证监控适配器能走现有漏洞工具、处理真实返回结构；离线规则没有新增候选，不证明网关安全。
另有单测明确断言传 `open_ports`、`port_scan_status=succeeded`、`use_nmap=false`，
只将 `findings` 转为候选告警，排除泛关键词 `cloudCandidates`；不是声称这次实机命中过漏洞。

## 5. 真实网络诊断

```powershell
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll diagnose
$LASTEXITCODE
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll diagnose --no-external
$LASTEXITCODE
```

两次完整表格的关键字段：

```text
interface ok      WLAN 2: 192.168.99.5/24
gateway   ok      192.168.99.1
dns       ok      本机解析器查询 example.com（可能命中缓存）
internet  failed  TCP 1.1.1.1:443；未取得成功结果（失败/超时），不是确定故障原因
listeners ok      本机 TCP 监听 32 项（不等于公网暴露）
DIAGNOSE_NATIVE_EXIT=2

--no-external：internet skipped；接口、网关、DNS、本地监听仍为 ok
NO_EXTERNAL_NATIVE_EXIT=0
```

实际建议明确指出“网关可达，但单个公网端点不通”，建议用其他站点交叉验证，
**不能据此判整个互联网断网**。此环境 `1.1.1.1:443` 两次未连接成功，没有美化成通过。
`--no-external` 没有把 skipped 算作公网通过；DNS 仍运行。

## 6. 回归与诚实边界

- 本批新增测试覆盖：首轮/重复基线、陌生/可信设备、设备未见/恢复、DHCP IP 变化与信任不转移、
  端口失败保留时间戳、空/失败扫描不全量消失、重复 MAC 身份歧义、服务/厂商变化、候选失败不假修复、
  不重叠调度、取消不提交空结果、同范围租约、设备并发上限、端口复用、默认不调用云漏洞、分层诊断和参数错误。
- 本地最终门禁：`dotnet build -c Release --no-restore` 为 **0 警告 / 0 错误**；
  `dotnet test -c Release --no-build --no-restore` 为 **812 通过 / 0 失败 / 0 跳过**，
  其中 Tools 551、Agent 166、Scanning 65、API 30；相对任务基线新增 43 项。
  `dotnet format --verify-no-changes --no-restore` 及 `git diff --check` 均退出 0。
  最初格式检查发现新适配器的换行问题，已格式化并重新验证，不隐去这次失败。
- 只读 `check-secrets.py` 对工作树扫描，发现 3 处既有 `literal-secret` 模式命中：
  `release-verification.yml` 及 0.9.7/0.9.8 历史健康日志。均非本批新增文件，未更改；
  本批新增文件未命中。该启发式检查不等于 Git 历史/二进制/数据库的全面秘密审计，不宣称全仓零风险。
- **真实新手机加入同一 Wi-Fi 尚未执行**：已请求用户配合，未收到实际接入事件确认。
  新设备/信任逻辑的 mock 单测已过，但不能替代该物理验收。android-99.local 本次也未被观测到。
- 尚未做长时间全天候运行、Linux 真网段、Web 监控页、通知推送或 GHCR 发布测试；均不冒充已完成。

下一项真实验收：首轮建立后，用户将一台原先未连接的设备接入**同一被扫描的 Wi-Fi**，
在下一轮查看 `new_device/high`；核对 MAC 后 `--trust`。手机热点若另建子网，不算接入这个网段。
需要设备对存活探测有响应；若睡眠/防火墙不答，应保留漏发现边界，不伪造事件。
