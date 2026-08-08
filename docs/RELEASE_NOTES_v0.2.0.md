# LucentMist v0.2.0 发布说明

> 发布日期: 2026-07-30 | 代码仓库: E:\LucentMist\

---

## 版本概述

v0.2.0 是 LucentMist 的第二个版本，重点在于**工具扩展、测试覆盖、CI/CD 集成和文档完善**。新增 UDP 端口扫描和 SSL 证书校验两大工具，测试从 13 增长到 105 个，引入 GitHub Actions 持续集成。

---

## 新功能

### UDP 端口扫描 (`udp_scan`)

- 支持 DNS/SNMP/NTP/DHCP/Syslog 等 11 种 UDP 服务探测
- 端口范围解析：支持逗号、范围、混合格式 (`53,67-69,161`)
- 协议特定探测包（DNS 查询、NTP 请求、SNMP GET）
- 并发控制（默认 20 并发）
- CLI 命令：`lmist scan <ip> --udp --ports 53,123,5353`

### SSL/TLS 证书校验 (`ssl_check`)

- 获取目标 SSL/TLS 证书完整信息
- 输出：颁发者、主题、有效期、剩余天数、过期状态
- 主题备用名称 (SAN) 解析
- SHA-1 + SHA-256 指纹
- 证书链信息
- CLI 命令：`lmist ssl-check baidu.com --port 443`

### Agent 层增强

- `ReActResponseParser` 公开化：JSON 解析、Markdown 剥离、正则兜底
- Agent 工具注册新增 `udp_scan` 和 `ssl_check`

---

## 改进

### 测试覆盖

| 层级 | v0.1.0 | v0.2.0 |
|------|:------:|:------:|
| Core | 13 | 13 |
| Tools | 0 | **53** |
| Agent | 0 | **39** |
| **总计** | **13** | **105** |

- JSON 解析测试 17 个（正常/损坏/Markdown/正则兜底）
- ReAct 引擎循环测试 8 个（Mock LLM + 真实工具）
- SSL 证书测试 14 个（字段完整/SAN/证书链/边界）
- 工具层全品类覆盖

### CI/CD

- GitHub Actions 流水线：push/PR 自动触发
- 双平台矩阵：ubuntu-latest + windows-latest
- .NET 8.0 + 10.0 SDK 支持
- TRX 测试报告 + Artifact 上传

### 文档

- 新增 CI/CD 指南、版本规划、贡献指南、更新日志
- 用户手册扩展：UDP 扫描 + SSL 证书章节
- API 设计文档补充：UDP + SSL 接口

---

## 修复的问题

| 问题 | 修复 |
|------|------|
| LLM 输出 Markdown 包裹 JSON | `ReActResponseParser` 自动剥离 ```json``` \[...\]\ ```\``` |
| `ParseReActResponse` 私有不可测试 | 提取为公开 `ReActResponseParser` 类 |
| Agent 层 0 测试 | 新增 25 个 ReAct 引擎 + JSON 解析测试 |

---

## 工具清单 (v0.2.0)

| 工具 | 类型 | 新增 |
|------|------|:--:|
| `ping_scan` | ICMP 存活探测 | — |
| `port_scan` | TCP 端口扫描 | — |
| `service_identify` | Banner + 服务识别 | — |
| `device_query` | 设备查询 | — |
| `udp_scan` | UDP 端口扫描 | ✅ |
| `ssl_check` | SSL/TLS 证书校验 | ✅ |

---

## 升级指南

```bash
# 从 v0.1.0 升级
cd E:\LucentMist
dotnet build              # 重新编译
dotnet test               # 验证 105 测试通过

# 试用新功能
dotnet run --project src/LucentMist.CLI -- ssl-check baidu.com
dotnet run --project src/LucentMist.CLI -- scan 127.0.0.1 --udp
```
