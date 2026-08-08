# LucentMist v0.4.0 发布说明

> 发布日期: 2026-08-03

---

## 版本概述

v0.4.0 是安全增强版本，新增 OS 指纹识别、多源 CVE 漏洞扫描、多格式报告导出，以及 Sirius Scan 外部扫描器集成。

---

## 新功能

### OS 指纹识别 (`os_fingerprint`)
- TTL 值推断（128→Windows, 64→Linux/macOS）
- TCP 窗口大小分析
- 开放端口特征匹配（135→RPC→Windows, 22→SSH→Linux）
- 置信度评分

### 漏洞扫描升级 (`vuln_scan`)
- **4 源 API 并行查询**: Shodan CVEDB + NVD + CVETodo + OSV.dev
- **Banner 抓取**: SMBv1/v2/v3、SSH、HTTP Server、MySQL 版本
- **CVE 验证**: SMBv1 探测包验证 EternalBlue
- **16 端口风险特征库**: 内置 CveDatabase 回退
- **API 优先策略**: 外部 API → 内置 DB → 端口兜底

### 报告导出 (`report`)
- **4 种格式**: HTML / Markdown / CSV / JSON
- **HTML 炫酷主题**: 霓虹渐变 + 玻璃卡片 + 风险色块 + 可折叠面板
- **OS 智能过滤**: 自动过滤不适用当前 OS 的历史 CVE
- **4 层结构**: 紧急摘要 → 严重高危卡片 → 分层表格 → 修复建议

### Sirius Scan 集成 (`sirius-scan`)
- REST API 客户端：提交 → 轮询 → 获取结果
- 结果自动转换为 LucentMist 报告格式
- 不可用时自动回退内置扫描引擎

---

## 文件统计

| 类别 | v0.3.0 | v0.4.0 |
|------|:------:|:------:|
| 测试 | 109 | **121** |
| Tools 测试 | 53 | **78** |
| Agent 测试 | 43 | 43 |
| 文档 | 27 | **30** |
| CLI 命令 | 8 | **11** |
| 编译 | 0 错误 | 0 错误 |

---

## 升级

```bash
cd E:\LucentMist
dotnet build
dotnet test  # 121/121
dotnet run --project src/LucentMist.CLI -- vuln-scan 127.0.0.1
```
