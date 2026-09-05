# 自测问题修复与真实复测（2026-09-05～06）

结论：nmap 执行可见性、云线索默认筛选、DNS 呈现和 Ollama 不可用处理已修复；设备型号采集链路已增强，但真实 ZTE 网关和 Android 设备的型号仍未取得，不能宣称全部问题解决。

## 逐项结果

| 用户问题 | 代码与实测结果 | 验收边界 |
| --- | --- | --- |
| `--use-nmap` 无效（第 1/6 项重复） | 原来已存在真实进程调用，但找不到程序/超时/无识别结果缺少可见说明。现在输出状态、PID、退出码、参数及耗时；默认仍不自动运行。真实网关两次执行均返回 0。 | 程序必须在 PATH、标准安装目录或由 NMAP_PATH 指定；不能把同样的版本结果当作没有调用。 |
| 老 CVE 污染 | 云端推荐要求产品证据、CVSS ≥ 4、实际发布日期在 2018 年之后；评分或日期缺失也不推荐。默认每端口最多 3 条、全局最多 5 条。 | 这是待核实云线索的展示策略，不按年份删除已确认/版本规则风险。原始结果保留，过滤后零推荐不代表安全。CVE 编号年份不等于发布日期。 |
| DNS 相反结论 | 同次分析沿用共享 DNS 快照；两次包证据不足或不同，唯一结论为“递归配置未确认”，附限制访问建议。单包 RA/RCODE 保留在原始证据，不再塞进用户结论或模型观察。 | 不强行把不确定判成开放或关闭；真实网关的递归配置仍未确认。 |
| ZTE 型号 | 新增定向 SSDP → UPnP 设备描述，读取 manufacturer/modelName/modelNumber；网页明确出现 `ZTE F660` 时可解析。 | 真实 `.2.1` 仍仅有 ZTE OUI 厂商证据，本次未取得型号。不据此猜 F660。 |
| Android 型号 | mDNS 增加 `_googlecast._tcp.local` / `_device-info._tcp.local` PTR/TXT 查询；`scan` 与端口扫描共用设备识别链路。 | 真实 `.2.6` 返回 `android-99.local` 名称，本次未取得型号。主机名和随机 MAC 无法推出手机型号。 |
| Ollama 不可用 | 区分服务不可达、超时和模型请求失败；CLI 检查失败结果，不输出空结论框，不记录预期连接失败的 Error 堆栈。 | 不偷偷更换云端 Provider、不伪造 AI 报告；扫描/报告命令仍能独立使用。 |

## 真实 nmap 证据

在 E:\LucentMist，Release CLI 运行：

```powershell
$env:LMIST_CVE_EXTERNAL = 'false' # 隔离云源变量，仅本次进程环境
$env:NMAP_PATH = 'D:\1tools\Nmap\nmap.exe' # 此机器实际安装位置，不是代码默认路径
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll vuln-scan 192.168.99.1 --use-nmap --ports 53,80,443
```

第二次真实运行输出摘录（命令退出码 0）：

```text
Nmap: completed
程序: D:\1tools\Nmap\nmap.exe；PID: 16812；退出码: 0；耗时: 16288ms
参数: -sT -Pn -n -sV --version-light -p 53,80,443 --host-timeout 45s -oX - 192.168.99.1
53 DNS：DNS 返回占位值“unknow”，未提供可用的软件版本
80 HTTP：HTTP 已响应但未公开 Server 头版本
443 HTTPS：HTTP 已响应但未公开 Server 头版本
DNS 递归配置未确认，不能视为已关闭；建议仅允许可信局域网访问 DNS，并在管理端核对递归设置
```

第一次运行同样成功：PID 24012，退出码 0，17112ms。Nmap 的 host-timeout 从原 15 秒调整为 45 秒，父进程另给 3 秒退出/读取窗口。显式失败不会伪装成成功；重复分析复用快照时标注 reused_analysis_snapshot，不冒称启动了新进程。

未设置 NMAP_PATH 的实际环境找不到 nmap：输出 `Nmap: unavailable`，明确提示安装/加入 PATH/设置 NMAP_PATH，仍保留原生扫描。此轮复测还发现 `where nmap` 的本地化错误污染终端，已替换为直接查找 PATH 文件，不再启动 where/which。

CMD 用户可在当前窗口执行：

```bat
set "NMAP_PATH=D:\1tools\Nmap\nmap.exe"
dotnet run --project src/LucentMist.CLI -- vuln-scan 192.168.99.1 --use-nmap
```

## 云源与设备实测

开启云源后对 53/80/443 的一次实际运行：原始元数据 50 条，推荐 0 条；53 收起 10 条、80/443 各收起 20 条。未显示用户列出的旧 CVE。CVETodo 的 53 查询超时，NVD 返回结果，Shodan 返回空结果；界面保留来源状态和覆盖不完整提示。不能将这一结果描述为“查到 50 个漏洞”，也不能描述为“确认安全”。

`scan 192.168.99.0/24` 的最终链路实测：254 地址、5 台在线、18.1 秒；完整列出 `.2.1/.2.11/.2.3/.2.5/.2.6`。ZTE 厂商及 Android 名称仍可见；型号均标“本次 mDNS/UPnP 未取得型号，需管理端确认”。前一轮 16.6 秒的扫描暴露了 ping_scan 没有走 UPnP 的独立旧路径，已修复并用这次复测确认接线。

UPnP 查询是定向、只读、有 2.5 秒总预算的设备发现，不执行 SOAP 配置操作。描述 URL 必须指向受检 IP；拒绝跨主机 URL、用户信息、重定向、DTD，正文上限 32 KiB。mDNS 限 8 个查询/1.2 秒。只响应多播或未启用相应公告的设备仍可能无法通过这种定向方式获取型号；无响应不等于证明设备从不公告。

新增的本机 UDP+HTTP 测试服务器实际发送 SSDP 响应和 UPnP XML，验证型号字段贯通；它是模拟设备测试，不是把真实网关识别成 F660 的证据。

## Ollama 真实复测

```powershell
$env:LMIST_LLM_PROVIDER = 'ollama'
$env:LMIST_LLM_ENDPOINT = 'http://127.0.0.1:11434'
dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll agent '看看我的ip'
@('看看我的ip', '/exit') | dotnet src/LucentMist.CLI/bin/Release/net10.0/lmist.dll agent
```

服务不可用时实际显示：

```text
AI 暂不可用 · 未生成分析结论
Ollama 连接超时；请先运行 ollama serve，再重试。扫描和报告命令仍可独立使用。
```

单次命令退出 1（明确未完成，不是崩溃）；REPL 回到 `agent>`，`/exit` 正常退出 0。没有异常堆栈或空答案。本轮没有使用 DeepSeek key，也没有进行真实 LLM 推理成功率验证。

## 验证与提交

- 独立代码提交：`c0d261de` nmap、`66c2e7b7` 云线索、`521ded79` DNS、`b373d945` 设备型号、`d819205c` Ollama。
- 最终 `dotnet build -c Release --no-restore`：0 警告、0 错误。
- 最终 `dotnet test -c Release --no-restore`：769/769 通过、0 跳过（Tools 542、Agent 166、Scanning 31、API 30；基线 746，新增 23）。
- `dotnet format --verify-no-changes --no-restore` 与 `git diff --check` 均返回 0。拆分测试文件时曾有一处缩进未通过格式检查，已修正并重新运行这两项与全量测试，不拿之前版本的检查代替最终检查。
- 密钥启发式扫描发现 3 个既有文件的潜在匹配：`.github/workflows/release-verification.yml:63`、两份历史 release health 日志的第 145 行；未输出其值，本轮未改这些文件。因此不声称“全仓零 secret”，该扫描也不等于历史 Git 对象审计。
- 本轮不推送、不发布。真实型号尚未取得和 DNS 配置未确认是保留限制，不通过提高置信度或编造型号凑验收。

协议参考：[UPnP Device Architecture](https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf)、[Nmap version detection](https://nmap.org/book/man-version-detection.html)、[Nmap host timeout](https://nmap.org/book/man-performance.html)。UPnP 代码是依据协议实现，不冒称引入了新的型号数据库。
