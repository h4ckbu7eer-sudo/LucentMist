# Monitor CLI 回归与真实演练 — 2026-09-07

## 1. 先复现，再修复

新增 `MonitorCliIntegrationTests`，每一步启动独立 `dotnet` 子进程，经过真实 `CliApp.RunAsync`、
参数解析、默认网段选择调用点、SQLite、文件租约、信任逻辑和终端呈现。
测试专用 `LucentMist.CLI.TestHost` 只替换网络扫描快照与本机网段来源，不给发布程序添加 mock 参数或 mock 环境变量。
它不是物理设备测试，也不是仅调用 MonitorStore 的单测。

修复前运行：

```text
dotnet test tests/LucentMist.Tools.Tests -c Release --filter FullyQualifiedName~MonitorCliIntegrationTests
失败 1，通过 0
RealCommandSequence_CustomPorts_QueryWithoutPorts_Trust_NewDeviceAlert
Assert.Contains(): Not found: "192.168.77.1"
```

首条 `monitor --once --subnet 192.168.77.0/24 --ports 80` 成功写基线；
第二条 `monitor --devices --subnet 192.168.77.0/24` 空表，真实复现不同 ports 导致范围分裂。

修复后的进程序列包括：

1. 自定义端口 80 写首轮基线；`--once` 无等待下一轮提示。
2. 不带 ports 的 `--devices` 查到设备；首轮 `--alerts` 无变化告警（预期）。
3. `--trust <IP>` 不带 subnet/ports，通过同一默认网段入口选范围；设备对应行显示可信。
4. 改扫描边界夹具，加入第二台随机 MAC 设备；再扫，`--alerts` 显示该 IP 的 `high new_device`。
5. 信任第二台设备，再查该设备行确实可信。
6. 将扫描范围改成 443；无虚假 `port_not_observed/new_device`，保留未扫描的 80 历史证据。
7. 第二个进程测试重复制造 NVD timeout：显示检查状态，不写 `analysis_incomplete` 告警；加入设备后新设备高告警仍可见。

没有将首轮基线伪造成“新接入事件”来凑非空告警。旧范围迁移另有 SQLite 集成测试：
多份 `subnet|ports` 合并、事件 ID/信任/逐端口时间保留、重启幂等、损坏 JSON 时整个事务回滚。

## 2. 发布 CLI 二进制的真实家庭网络演练

使用本轮 Release 构建的 `src/LucentMist.CLI/bin/Release/net10.0/lmist.dll`，不是测试宿主。
`LMIST_CVE_EXTERNAL=false`，未设置或使用任何 LLM key。
新建隔离数据库 `data/monitor-cli-smoke-20260907-1d1b5782e4814aec95bf82d0eacba9cd.db`，
未修改日常 `data/lucentmist.db`。下列命令前缀均为 `dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll`。

| 实际命令 | 实际结果（均退出 0） |
| --- | --- |
| `monitor --once --subnet 192.168.99.0/24 --ports 80,443` | 03:38:07，4 台，0 告警，completed；建立首轮基线；提示“仅执行一轮，完成后退出” |
| `monitor --devices --subnet 192.168.99.0/24` | 不带 ports 查出同样 4 台，网关端口 80/443 可见 |
| `monitor --trust 192.168.99.5` | 不带 subnet/ports，使用实际物理主接口网段；成功信任隔离库内本机 MAC |
| `monitor --devices --subnet 192.168.99.0/24` | 本机行显示“观测到/可信”，仍有 4 台 |
| `monitor --alerts --subnet 192.168.99.0/24` | 无历史变化告警，正确提示“不代表已完成全面安全检查” |
| `monitor --once --subnet 192.168.99.0/24 --ports 80` | 03:40:10，4 台，0 告警，completed；没有重建基线、没有误报 443 关闭；网关保留 80/443 并标不同轮次历史 |

实际设备证据：

| IP | 本轮观测 | 不能声称的结果 |
| --- | --- | --- |
| 192.168.99.1 | 网页名称“中兴智能路由器”、ZTE、80/443 开放 | 未取得型号，不能猜 F660 等型号 |
| 192.168.99.5 | 本机 DESKTOP-DEV、Generic PC Vendor、MODEL-0001 | 80/443 无成功连接不等于所有端口关闭 |
| 192.168.99.6 | android-99.local，随机 MAC | 未取得型号，未观察到 ADB 型号声明 |
| 192.168.99.10 | 有响应、随机 MAC | 无有效名称/型号响应，不能推断品牌 |

这轮未实际接入一台新手机；新设备高告警由进程级扫描夹具验证，不能描述成真实手机接入验收。
mDNS Android/ADB 查询另用本机 UDP 应答器验证生产报文路径；随机 MAC 的型号解析用关联 PTR/TXT/SRV 证据测试。
ADB 使用 TCP，未实现没有合法协议依据的 UDP 5555 探测；已有只读 UPnP 1900 路径继续复用。

## 3. 真实 diagnose：单端点不通不再判整体断网

```text
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll diagnose
interface  ok  WLAN 2: 192.168.99.5/24
gateway    ok  192.168.99.1
dns        ok  本机解析器查询 example.com（可能命中缓存）
internet   ok  公网 TCP 2/3 个端点可达
               1.1.1.1:443=failed（失败/超时）；8.8.8.8:53=ok；223.5.5.5:53=ok
               部分端点失败，但已有可达证据，不是整体断网。
listeners  ok  32 项；优先核查非回环、非高位端口
               折叠回环 6 项、高位端口 14 项；高位不等于安全
退出码 0
```

上面为实际输出的紧凑转录，保留端点、结果和限定语，非原始终端表格截图。
TCP 连通只能证明这些端点可达，不证明所有互联网服务、DNS 正确性或整网安全。

## 4. 本地门禁与边界

- `dotnet build -c Release --no-restore`：0 警告、0 错误。
- `dotnet test -c Release --no-build --no-restore`：854 通过、0 失败、0 跳过
  （Tools 564、Scanning 85、Agent 166、API 39）。
- `python -m unittest discover -s scripts -p "test_*.py" -v`：20 通过。
- `dotnet format --verify-no-changes --no-restore`、`git diff --check`：通过。
- 最后加强的 CLI 断言按具体 IP 所在行核对“可信”，再跑全套仍为 854 通过，避免另一台设备已可信导致测试误过。
- `python scripts/check-secrets.py`：扫描无读取错误，返回 1，仍有 3 个既有 `literal-secret` 提示
  （旧 release-verification 工作流及两份旧健康检查记录），未命中本轮新增/修改文件；
  不将此结果宣称为“整个历史零密钥”。本轮没有使用或记录 LLM key。
- 不需要 DeepSeek/Ollama，不进行外网漏洞查询或漏洞利用；真实 diagnose 访问的是明示的三个固定连通端点。
- 本轮不推送，不把本地构建/测试或局域网结果冒充 GHCR/远端 CI 实证。

升级/回滚方式、状态与告警区别见 [家庭监控手册](HOME_NETWORK_MONITOR.md)。
