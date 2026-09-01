# 可执行指纹的来源与边界

核实日期：2026-09-01。已把官方 Recog 的核心服务数据真正转换并嵌入运行时；仍不宣称具备 Nmap -A 的主动探测覆盖范围。

## HTTP / 服务表

来源：[Rapid7 Recog](https://github.com/rapid7/recog/tree/d3d20938da9f5f1e442c2419fe6c30cd651b6878/xml)，
固定提交 `d3d20938da9f5f1e442c2419fe6c30cd651b6878`，许可 BSD-2-Clause。
`tools/fingerprint-import/convert_recog.py` 从以下官方文件确定性转换 **950 条**带产品身份的规则：
`http_servers.xml`、`http_xpoweredby.xml`、`ssh_banners.xml`、`smtp_banners.xml`、
`pop_banners.xml`、`imap_banners.xml`、`dns_versionbind.xml`、`ftp_banners.xml`、
`mysql_banners.xml`。生成物为嵌入程序集的
`Vulnerability/Data/recog-service-fingerprints.json`，运行时由
`ServiceFingerprintMatcher` 读取并保留原文件、序号、描述、版本捕获位置和 CPE 模板。
每条 .NET 正则有 100ms 预算；当前 950/950 条均可由 .NET 编译。若未来上游引入
Oniguruma-only 构造，生成源仍保留该规则且运行时明确计入“导入但不可运行”，两项数量由测试审计。
Redis INFO 的 `redis_version:` 与 Windows RPC 的证据身份规则为独立实现，不计入 950 条。

运行链路：HTTP HEAD/GET → Server/X-Powered-By/meta generator，以及 SSH/DNS/FTP/SMTP/POP/IMAP/MySQL
协议 Banner → `ServiceFingerprintMatcher` → `CpeCatalog` 安全兜底 → CVE 查询。
SMB 方言仍仅由 SmbProbe 解码，不能把协议 3.1.1 当 Windows 软件版本。
产品词和版本都不存在时，不产生产品 CPE；产品可识别但版本未知时仍不得声称版本匹配。
Via 单独保存为代理线索，不用代理版本给源站匹配 CVE。

`Microsoft Windows RPC` 属于“服务已观测、版本未公开”的证据：显示 Windows RPC，但不伪造应用 CPE，
也不把 Windows 产品版本从端口或服务名猜出来。所有类似情况分成 `not_disclosed`（产品已识别）与
`observed_unparsed`（有 Banner、尚无可靠规则），不再笼统显示“未知”。

回归测试包含 Recog 形式的 nginx/Apache/IIS/Tomcat、OpenSSH/Dropbear、Postfix/Exim、
Dovecot、BIND、vsFTPd/ProFTPD、MySQL，以及 Windows RPC 无版本/无 CPE 边界。
版权声明在仓库根目录 `THIRD-PARTY-NOTICES.md`，分发时应一并保留。

## DNS

用户提到的 dns-version.nse，在当前 Nmap 对应
[dns-nsid.nse](https://github.com/nmap/nmap/blob/master/scripts/dns-nsid.nse)。
核对的是 `version.bind TXT CH` 和身份信息分离的探测思路，没有复制 NSE 实现。
本项目另外查询 `hostname.bind TXT CH`、目标反向区域 SOA IN；SOA 主服务器名称不是目标软件版本，
更不是设备型号。四个小查询并发且各有超时，单次 Agent 分析共享同一 DNS 快照。

返回每个查询的名字、类型、类、RCODE、状态和值：REFUSED、NXDOMAIN、无有效响应不能混称“目标不暴露”。
只有完整、相关的响应才作为证据；UDP 截断会使用同一查询走 DNS-over-TCP 回退，TCP 仍失败才标未知。

## 设备身份

后续真实输出修复增加 `HttpPageIdentity`：从最多 64KiB 的解压 HTTP 正文读取标题/显式 generator，
只保存公开身份字段，不保存正文、Cookie、会话值，不自动跟随重定向。
另从 [Recog http_wwwauth.xml](https://github.com/rapid7/recog/blob/d3d20938da9f5f1e442c2419fe6c30cd651b6878/xml/http_wwwauth.xml)
转换 **3 条** ZTE realm 规则（cpe@zte.com、ZXHN、ZXV），均有可运行回归测试。
这些是设备声明，不是软件版本规则；服务指纹的 950 条转换与这 3 条设备 realm 规则分别计数。
已拉取的 WhatWeb/Recog/Nmap 版本、许可证和使用边界见 [tools/README.md](../tools/README.md)。

mDNS 采用定向单播 PTR → 服务 PTR → TXT，最多 8 次查询、总预算 1.2 秒。
只接受目标地址的回复，并要求 TXT 与服务 PTR 关联；名称/型号仍是未经认证、可能被代理公告的线索。
未收到回复不证明设备没有广播。没有监听 DHCP，ARP/ip-neigh 也不含 DHCP Option，不能伪造 DHCP 结论。

OUI 只能辨认注册地址，不保证最终设备品牌，更无法确定型号；随机 MAC 不用于厂商推断。
原内置表 17 个前缀；本次从 [IEEE MA-L 官方 CSV](https://standards-oui.ieee.org/oui/oui.csv)
核实并补 00:17:9A、00:1B:11（D-Link）和 28:6C:07（XIAOMI），合计 20 个前缀。
已有 ZTE 7C:7D:21、Huawei 00:1E:10、TP-Link 18:D6:C7 / 3C:84:6A 亦与该表核对一致。
未把 64:16:66 当小米：本次官方表将其归为 Nest Labs Inc.。
这是常见厂商的少量离线兜底，不是厂商全量前缀覆盖。
Wireshark 的 [manuf 说明](https://www.wireshark.org/docs/man-pages/wireshark.html)同样使用 IEEE 注册数据；
本次直接取 IEEE 事实映射，没有复制 Wireshark 代码或整份数据库。
允许通过 LMIST_OUI_DB_PATH 加载离线 IEEE MA-L CSV 或通过已支持路径加载 Nmap 前缀文件。
