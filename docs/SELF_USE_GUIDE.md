# LucentMist 自用手册（0.9.8）

适用日期：2026-08-31。目标：在自己有权测试的网络上发现暴露、阅读证据、保存报告、备份和恢复。
不需要先使用 Agent；确定性扫描与报告不依赖 LLM key。

当前源码新增家庭网络定时监控、变化告警和 `diagnose`：见 [家庭网络监控手册](HOME_NETWORK_MONITOR.md)。
这是监控/建议能力，不是自动隔离或修复，也不表示旧发布镜像已经包含新命令。

> **先分清版本与边界。** 本手册对应 0.9.8；旧发布镜像不自动包含后续修复。
> 先记下 `git rev-parse HEAD`；镜像部署核对 [0.9.8 发布实证](RELEASE_0.9.8.md)中的摘要。
> 漏洞扫描默认查询免费云源；使用 DeepSeek 会把问题和工具观察（可能含 IP/拓扑）发送给提供商。
> 不想外发这些数据，就不用云端 Agent，并设 `LMIST_CVE_EXTERNAL=false`。

## 1. 第一次启动：推荐 Windows 原生、仅本机访问

需要 Git、.NET 10 SDK；可选 Python 3.12+ 用于密钥卫生检查。下面在 PowerShell 中操作。
把仓库路径改成你的路径。不要为了阅读手册的示例去扫描不属于你的设备。

```powershell
Set-Location E:\LucentMist
git rev-parse HEAD
dotnet build -c Release
dotnet test -c Release --no-build

# 固定绝对数据路径：避免三个程序因工作目录不同，各自建立一份数据库。
$env:LMIST_DB = Join-Path (Get-Location) 'data/lucentmist.db'
$env:LMIST_DB_MAINTENANCE_OWNER = 'api'
$env:LMIST_BIND_ADDRESS = '127.0.0.1'
$env:LMIST_WEB_BIND = '127.0.0.1'
$env:LMIST_API_URL = 'http://127.0.0.1:5050'
$env:LMIST_CVE_EXTERNAL = 'true' # 离线兜底改为 false

# 只有使用 DeepSeek Agent 才需要以下配置。
$env:LMIST_LLM_PROVIDER = 'deepseek'
$env:LMIST_LLM_MODEL = 'deepseek-chat'
$env:LMIST_LLM_ENDPOINT = 'https://api.deepseek.com/v1'
$secretInput = Read-Host '输入新建的 DeepSeek key（不回显）' -AsSecureString
$env:LMIST_LLM_APIKEY = [System.Net.NetworkCredential]::new('', $secretInput).Password
Remove-Variable secretInput
```

输入发生在 `Read-Host` 提示符里，不要把 key 拼在命令、脚本或聊天里。
环境变量仍是进程内明文，不是加密保险箱；同账户调试工具、管理员和子进程可能读取。
不需要 Agent 时跳过全部 LLM 配置。

从**同一个已配置的 PowerShell** 打开两个运行终端，让它们继承环境（引号适用于含空格的路径）：

```powershell
Start-Process powershell -WorkingDirectory (Get-Location).Path -ArgumentList '-NoExit', '-Command', 'dotnet run --project src/LucentMist.API -c Release --no-build --no-launch-profile -- 5050'
Start-Process powershell -WorkingDirectory (Get-Location).Path -ArgumentList '-NoExit', '-Command', 'dotnet run --project src/LucentMist.Web -c Release --no-build --no-launch-profile -- 5051'
Invoke-RestMethod http://127.0.0.1:5050/api/v1/health
```

等待终端提示开始监听后再查健康；预期 JSON `status=healthy`。浏览器打开
[本机 Web](http://localhost:5051)，扫描用 `/scan`，历史用 `/scan/history`，Agent 用 `/agent`。
Agent 默认折叠，必须先点击“我了解限制，启用实验性 Agent”。**Web 的 Agent 需要 API 同时运行**。
进程已有监听时不要重复启动；用各终端 Ctrl+C 停止自己启动的服务。

Linux 同样使用 .NET 10，在仓库目录 `export LMIST_DB="$(pwd)/data/lucentmist.db"`，
其余变量用 `export 名称=值`。Bash 可用 `read -rs -p 'DeepSeek key: ' LMIST_LLM_APIKEY; export LMIST_LLM_APIKEY` 隐藏输入，
然后分别在继承这些环境的终端运行上面两个 `dotnet run` 命令。

### `.env` 与 Docker：不要混用两套配置方式

原生 CLI/API/Web **不会自动读取 `.env`**。上面的原生方式使用当前进程环境变量；
Docker Compose 才会读取项目 `.env` 做变量替换。`.env` 是明文且被 `.gitignore` 忽略，忽略不等于加密。
优先使用环境变量/密码管理器注入；如果选择 `.env`，只在本机受限权限下保存，示例值仅用 `<你的key>`。
DeepSeek 必须同时设置 provider、model、endpoint，特别是 Compose 不会替你把 Ollama endpoint 默认值换掉。

仓库默认 Compose 将 5050/5051 发布到所有宿主接口。自用请叠加本机限定配置：

```powershell
# 在配置好上面的环境后运行；先停止占用 5050/5051 的原生进程。
docker compose -f docker-compose.yml -f docker-compose.self-use.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.self-use.yml up -d --build
```

此命令构建当前源码，不是拉取历史镜像。`!override` 必须被本机 Compose 支持；
若配置校验失败，升级 Compose 或使用原生方式，不要省掉 override 后暴露所有接口。
override 也将 `LMIST_ALLOWED_TARGETS` 传入 API/Web（仅在宿主 `.env` 中写任意变量并不等于容器会收到它）。

当前 main 在共享数据卷生成/复用 API token 与 Web 密码，**日志只说明位置，不打印值**。
Web 用户默认 `admin`，密码随机。需要登录时，在自己的私密终端读取（不要录屏、截图或粘进问题单）：

```powershell
docker compose -f docker-compose.yml -f docker-compose.self-use.yml exec lucentmist-web cat /app/data/lucentmist-web-user
docker compose -f docker-compose.yml -f docker-compose.self-use.yml exec lucentmist-web cat /app/data/lucentmist-web-password
```

凭据是数据卷中的明文文件，权限为当前容器账户限定；旧发布镜像的日志行为不同。
不要执行 `docker compose down -v`，它会删除含数据库和凭据的数据卷。
Docker 内的 `127.0.0.1` 是容器自己；扫描宿主/局域网用真实局域网 IPv4。

## 2. 日常命令：从小目标开始

仍在已配置 `LMIST_DB` 的仓库 PowerShell 中定义一个方便的调用函数：

```powershell
function lmist { dotnet run --project src/LucentMist.CLI -c Release --no-build -- @args }
```

下面的 IP 是本项目自用环境示例，换成你获准测试的目标。端口、漏洞、耗时会随环境变化，
“预期”描述输出结构，不承诺必有漏洞。默认仅 Error 日志；排障时加 `--verbose`/`-v`，不要公开原始日志。

| 想做什么 | 可执行示例 | 预期看到什么 |
| --- | --- | --- |
| 小范围发现+端口 | `lmist scan 127.0.0.1 --ports 135,445` | 存活探测结果、开放端口与服务名；不是必然开放 |
| 跳过 Ping | `lmist scan 192.168.99.1 --no-ping --ports 53,80,443` | 直接端口扫描；发现 TCP/53 时补 DNS 检查 |
| 漏洞分析 | `lmist vuln-scan 192.168.99.1` | 端口、证据来源、候选/版本状态、按端口排序的线索和下一步建议 |
| TLS 状态 | `lmist ssl-check 192.168.99.1 --port 443` | subject、issuer、有效期、SAN、信任错误，或明确连接/握手失败 |
| HTML 报告 | `lmist report --target 192.168.99.1 --format html --output data/gateway-report.html` | 本地报告路径与扫描完成/部分完成状态；输出目录须已存在 |
| 单次 Agent | `lmist agent "看看我的ip"` | 主接口 IPv4、网关/网段；虚拟接口不能冒充物理主接口 |
| 多轮 Agent | `lmist agent` | 等待输入；连续输入复用会话，`/exit`、`exit`、`quit` 或 Ctrl+C 退出 |
| 查会话/继续 | `lmist agent --list`，`lmist agent --resume <会话ID> "继续解释证书问题"` | 从已有会话继续，不创建无关联的新上下文 |
| 审计 | `lmist audit --limit 20` | UTC 时间、CLI/API/Web/Agent 发起者、目标、类型、状态、摘要 |
| 备份 | `lmist backup --output backups/self-use.db` | 完成 WAL checkpoint、在线备份、完整性检查；已存在则拒绝覆盖 |
| 恢复演练 | `lmist restore backups/self-use.db --database data/restore-check.db --yes` | 恢复到独立文件；不会替换日常数据库 |

大子网会更慢。`scan` 不加 `--ports` 只做发现；`--no-ping` 也要配端口或服务参数。
ICMP 超时/拒绝会尝试常见 TCP 端口，但无响应不证明设备离线。
`report` 不是查看以前扫描的快照：它会重新扫描，TCP 1–1000 加漏洞阶段指定高风险端口，未覆盖所有 TCP/UDP。

部分 CLI 工具内部失败仍可能返回命令退出码 0，审计中的 `completed` 也可能仅指命令结束。
**同时看输出错误、报告 ScanStatus/警告和覆盖范围，不把退出码或审计状态当安全证明。**

## 3. Agent 怎么问、怎么验

- “看看我的ip”：核对工具面板与结论的主 IP 一致；多网卡时以有网关的物理接口为先，无合适物理接口可能无法确定。
- “分析 192.168.99.1 的安全风险”：期望发现开放端口，复用端口结果做漏洞分析，53 做 DNS 检查、443 做 TLS；检查失败必须保留在结论里。
- 在同一 REPL 再问：“解释刚才网关的 HTTPS 信任问题，给我下一步建议”：应引用上一轮证据，不凭空声称漏洞已确认。

云端 Agent 会收到主动调用 `get_my_ip` 或扫描产生的观察。`LMIST_INJECT_NETWORK_INFO=true`
另外允许自动把本机网络信息注入提示词，默认未开；不用该开关也不意味着工具观察不外发。
版本未知的网关通常只能得到**暴露信息、证书风险、待核实线索和建议**，不是确认漏洞或“网络绝对安全”。
上一轮真实模型验证是历史证据，本轮是否重跑见 [回归演练](self-use-walkthrough.md)。

## 4. 如何看报告、做下一步

先看“扫描状态/覆盖范围/警告”，再看开放端口和 TLS，最后才看漏洞表。
总览卡片现在会显示“无法完整评估（TLS 需处理）”等证据状态；只有已完成且无匹配才写
“范围内未命中 CVE”，不会把零 CVE 一律显示为“安全”。

1. 暴露了什么：哪个设备开放哪个端口/服务，是否确实有业务需要。
2. 哪个先处理：真实证书过期、名称不符、信任链失败先核对正确管理域名/设备证书；不要靠忽略浏览器警告解决。
3. 漏洞条目：区分确认、版本匹配候选、版本未验证线索；优先登录管理端查固件/包版本，对照厂商公告。
4. 收敛暴露：在有维护权限和备份后关闭不必要服务、限制管理口到可信网段，再复扫对比。

HTML/Markdown/CSV/JSON 都是主动导出的本地文件，含敏感 IP、端口、服务、证书及 CVE。
报告可帮助自己安排检查/更新、给管理员转述证据，但不能当渗透证明、合规认证或补丁已安装证明。
未知版本/未检查/失败必须保留，云源无返回也不是安全结论。分享前做脱敏。

## 5. 数据、备份与恢复

默认 `data/lucentmist.db` 是相对进程工作目录的**明文 SQLite**；本手册用绝对 `LMIST_DB` 统一位置。
Docker 是命名卷中的 `/app/data/lucentmist.db`，不是宿主仓库 `data/`。
没有 `LMIST_DB_ENCRYPTION`；用账户权限、BitLocker/LUKS 等全盘加密保护数据库、日志、报告、备份。
不要只复制运行中的 `.db`，最新记录可能仍在 WAL。

备份建议：大扫描后、升级前各留一份带日期的备份，另存到自己控制的加密介质；定期实际恢复到另一个路径。
数据库备份**不包含** `.env`、随机凭据文件、报告、日志、配置；这些需另行安全备份，key 更建议由密码管理器保管。

```powershell
lmist backup --output backups/self-use.db
lmist restore backups/self-use.db --database data/restore-check.db --yes
$dailyDatabase = $env:LMIST_DB
try {
    $env:LMIST_DB = Join-Path (Get-Location) 'data/restore-check.db'
    lmist audit --limit 20 # 与备份前记录核对
} finally { $env:LMIST_DB = $dailyDatabase }
```

真正覆盖恢复前：**停止所有访问该库的 API/Web/CLI/容器任务**，确认 `LMIST_DB` 的绝对路径，保留原备份，
再执行 `lmist restore backups/self-use.db --yes`。旧库与 WAL/SHM 会移入同目录 `pre-restore-*` 安全副本，
不是让你手工盲删 sidecar。重启、查询历史和会话确认成功后再决定清理。
不要复制本段恢复命令去覆盖不明路径的库。
Docker 数据库可在停止写入后，用挂载同一卷的 CLI 容器执行同样命令；宿主 CLI 的默认库不是容器库。
详细机制见 [数据安全与恢复](data-security-and-recovery.md)。损坏隔离只让程序重新启动，不会自动找回损失的数据。

## 6. 安全默认值与故障排查

- 原生默认 loopback；跨机器开放需同时配置 API token、Web 用户/强密码，配 HTTPS 反向代理和防火墙。Basic Auth 不加密明文 HTTP，不推荐自用直接暴露公网。
- RFC1918/回环默认可扫，不等于自动获得法律/组织授权。Agent 公网目标必须列在 `LMIST_ALLOWED_TARGETS`。
  例如自己拥有 `scan.example.com` 才设置 `$env:LMIST_ALLOWED_TARGETS='scan.example.com'`。支持逗号/分号分隔 IP/CIDR/域名。
  CLI/Web 公网还有显式确认路径；CLI 非交互 `--authorized` 是你确认授权，不是绕过许可。列表当前**不是私网隔离策略**，不会禁止其他私网。
- Web 显示“无法确认扫描结果”：监控超时不是扫描失败，点击扫描历史核对，不要连续重复发起任务。
- Agent 401/余额不足：检查当前启动 API/CLI 的进程环境和 key 状态；改变量后需重启进程。不提供 key 给诊断人员。
- Agent 指向 Ollama：确认 provider/model/endpoint 三项都设置；新开的独立终端不继承之前终端临时变量。
- 云源超时/限流：会回退内置库并显示覆盖不完整；离线模式减少联网，不增加覆盖。
- 报告 `partial`/零命中：读未知版本和失败原因，不解读成安全；`--verbose` 输出也含拓扑，不公开上传。

完整边界以 [known-issues.md](known-issues.md) 为准：18 条离线规则非穷尽、OSV 需要明确 commit、
SMB 方言不能证明补丁、UDP closed 是推断、证书 Unspecified 时间依赖扫描机时区、Agent 实验性、虚拟接口单独标识。
密钥与分享前检查见 [安全清单](SECURITY_CHECKLIST.md)。
