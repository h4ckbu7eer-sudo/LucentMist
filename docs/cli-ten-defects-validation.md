# 十项 CLI 问题：修复与真实复测

基线 `63ebf58f`（720测试），最终代码 `87123108`（746测试）。本轮不推送、不发布、不调用LLM、不使用历史聊天中的密钥。

## 逐项结论

命令前缀统一为 `dotnet run --project src/LucentMist.CLI -c Release --no-build --`，从仓库根目录执行。

| 问题 | 复现命令 | 修复后实际结果与边界 |
| --- | --- | --- |
| 1. RPC退回未知 | `vuln-scan 127.0.0.1` | 135显示DCE/RPC endpoint mapper，版本未公开，证据为有效Bind ACK。不是把TCP端口开放伪造为Windows banner；已有Microsoft Windows RPC产品证据仍可识别 |
| 2. authd版本未解析 | 同上 | 902=1.10，912=1.0，依据明确来自VMware authd banner。这是daemon协议版本，不等于Workstation/ESXi/vCenter产品版本，不编造宿主CPE |
| 3. RPC云源假失败 | 同上，启用云源 | 135显示not_applicable：无足够具体的产品/版本关键字，跳过云端检索。未证明旧输出每个http_error都是假失败，真实连接错误继续保留 |
| 4. 本机OS缺型号 | `os-fingerprint 127.0.0.1` | Windows、100%本机运行时证据；名称DESKTOP-DEV、厂商Generic PC Vendor、型号MODEL-0001。回环地址也读取已有BIOS/DMI清单；不拿网卡OUI冒充整机厂商 |
| 5. TTL+SSH评分过低 | `os-fingerprint 47.119.138.105 --authorized` | 最终实测TTL=51、SSH、Linux 60%。60是启发式证据评分，不是统计概率；矛盾线索上限45，单TTL上限45 |
| 6. HTTP两处状态矛盾 | `vuln-scan 192.168.99.1` | 80/443表格与Banner均显示HTTP已响应但未公开Server头版本；限于已执行的HEAD/GET /，不能推断所有路径均无版本 |
| 7. DNS两模式相反 | 上条及追加`--use-nmap` | 最终两模式均显示两次采样不一致、无法确认递归。保存RA、RCODE、答案数、两次样本；不能把回答外部域名直接视为开放递归或已关闭 |
| 8. nmap线索数翻倍 | 同上两条 | 同次分析相同HTTP/HTTPS产品与版本只查一次云源，443明确标注复用；原始元数据与优先线索分开。最终原始数仍40/50，两次均0优先线索、0目标CVE；来源失败和节流见原始输出，不伪造恒定数量 |
| 9. /24只有数量 | `scan 192.168.99.0/24` | 最终4台逐台列出：192.168.99.1、192.168.99.18、192.168.99.3、192.168.99.5，IP不拆行，网关OUI识别ZTE。在线数量会变化；随机MAC不能确认厂商；无型号证据仍未知 |
| 10. 缺key默退Ollama | provider=deepseek、key为空白，运行`agent "看看我的ip"` | 退出码1：LMIST_LLM_APIKEY未配置、Agent未启动、不会静默回退。未指定provider时依现有配置使用Ollama，并提示ollama serve；本轮没调用模型 |

完整采集输出（从初始发现进度之后开始，未筛掉失败行；仅规范换行和去除行尾空格）：

- [本机漏洞扫描，云源开启](validation-evidence/cli-ten-defects/localhost-vuln-scan.txt)
- [最终网关默认/nmap对照](validation-evidence/cli-ten-defects/gateway-default-and-nmap.txt)
- [最终子网设备列表](validation-evidence/cli-ten-defects/subnet-scan.txt)

## 找到的实际根因

### RPC、authd与本机型号

RPC服务等待客户端发送请求，不能用被动读banner的方法保证识别。增加了只做绑定协商的endpoint-mapper探测，不枚举端点、不调用业务过程；验证RPC版本、包类型、长度、call-id、接受结果和NDR transfer syntax。协议依据：[Microsoft MS-RPCE bind_ack](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/87964b3c-1785-4aae-a993-734999441ed3)。本轮中间实现曾把TCP/135开放直接映射为Windows RPC，严格复核后已撤掉该错误做法。

authd的`220 VMware Authentication Daemon Version 1.10/1.0`已进入共享指纹匹配器。但有协议版本不代表有VMware宿主产品版本，“没有适用内置CVE规则”也不等于没解析到版本；现在把这两个事实分别呈现。

回环目标此前在DeviceDiscovery中提前返回，跳过了本来就有的BIOS/DMI读取，现在复用该读取方法，实际取得Generic PC Vendor/MODEL-0001。

### DNS不是简单的“开/关”

真实网关收到一次29字节的`example.com IN A, RD=1`查询，返回61字节：

```text
Flags=8100; RA=false; RCODE=0; ANCOUNT=2
4C4D81000001000200000000076578616D706C6503636F6D0000010001C00C00010001000000C80004AC4293F3C00C00010001000000C800046814179A
```

它回答了外部域名，但没声明RA。后续真实采样出现RA=true。因此不能把两次不同结果简单归因于nmap或“网络超时”。最终实现每次有界采样两次；结果不一致则保留未知和两份证据。不会缓存一个人为固定答案来伪装稳定。此真实报文、RA变化、SERVFAIL、错误答案计数和无响应都已有回归测试。

DNS版本查询实收占位值`unknow`，不能当软件版本。HTTP已响应但HEAD/GET /没有公开可识别软件版本；这些是目标证据的限制，不是已确认安全。

### 云源计数变化

80/443相同关键词过去分别请求，会碰到不同NVD节流时机。现在在单次扫描内共享原始云源快照，再各自执行按端口的内置版本过滤；不同产品/版本不共用，下一次扫描重新采集。测试证明相同nginx版本的80/443共3请求，而不是6请求；换版本或新扫描会重新查询。

真实对照仍有外部连接失败、超时和NVD本地6.1秒节流，因而原始数40/50并不相等。输出明确显示各源缺失情况；两次均0优先线索和0目标CVE。不能把“原始关键词结果相同”作为可承诺的验收结果，也不能把元数据计数称为目标漏洞数量。

Shodan实际查询`https://cvedb.shodan.io/cves?product=http%20server&limit=10`返回404及`{"detail":"No information available"}`；仅该明确正文作为空结果，普通404/HTML错误仍为覆盖失败。

## 最终代码门禁

```text
dotnet format --verify-no-changes --no-restore
退出码0
dotnet build -c Release --verbosity quiet
0警告，0错误
dotnet test -c Release --no-build --verbosity quiet
Tools 523 + Agent 162 + Scanning 31 + API 30 = 746 passed
0 failed，0 skipped
python -m unittest discover -s scripts -p test_check_secrets.py
8 tests，OK
git diff --check
退出码0
```

新增26项测试。新增单测不依赖外网；上述真实目标复测独立记录，不混入单测数字。

本轮23个变更代码/测试文件的已提交内容未检出provider/GitHub key模式；新增4个文档/证据文件也单独检查，0命中。加入文档后的全工作树启发式检查545个文本文件、0读取错误，命中3处已有release-verification固定测试token（workflow和两份历史health日志），无provider-key命中；不能说扫描器“零命中”，也不声称本轮遍历了全部Git历史对象。本轮未跟踪的`.codex/`、`.workbuddy/`、`deliverables/`原样保留。

初始十项分别提交；真实复测发现的RPC证据、回环型号、DNS变化、OS矛盾、云源复用、窄终端IP问题有独立补充提交。整理中撤回了两笔仅本地的错误分块提交，重新核对暂存内容后再次全量测试；没有推送或改写远端历史。

## 诚实边界

本轮确认的是这些协议识别与呈现回归已处理并复测，不是“产品所有核心功能无缺陷”。仍不能凭空识别网关固件版本、用authd协议版本确认宿主漏洞、保证外部源永不超时、保证每台设备都有型号或用TTL百分百确认OS。
