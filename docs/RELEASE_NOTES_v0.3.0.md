# LucentMist v0.3.0 发布说明

> 发布日期: 2026-08-02

---

## 版本概述

v0.3.0 新增 Web 管理界面，基于 Blazor Server + SignalR 实时通信。

---

## 新功能

### Web 管理界面 🆕

- **仪表板** (`/`) — 在线设备数、快速扫描、扫描计数
- **设备列表** (`/devices`) — 发现设备、搜索、端口扫描
- **扫描控制** (`/scan`) — TCP/UDP/Ping 扫描，支持自定义端口范围
- **SSL 证书** (`/ssl-check`) — 完整证书信息、SAN、证书链

技术栈：Blazor Server (.NET 10) + SignalR + 暗色主题 UI

### 状态保持

- `AppState` 单例服务 — 页面切换不丢失扫描结果
- 全局共享的扫描历史

---

## 改进

| 项 | 内容 |
|------|------|
| 服务识别 | `service_identify` 自动触发：port_scan 后引擎自动逐个识别服务 |
| JSON 解析 | `ReActResponseParser` 公开化，兼容对象/字符串双格式 |
| CLI scan | `--ports` 默认 TCP 扫描，`--udp` 切换 UDP，`--service` 识别服务 |
| CLI scan | 默认只显示开放端口，`--verbose` 显示全部 |
| CLI ssl-check | 新增 CLI 命令 |

---

## 文件统计

| 类别 | 数量 |
|------|:--:|
| 项目 | 8 个（+1 Web） |
| 测试 | 109 个 (Core 13 + Tools 53 + Agent 43) |
| 文档 | 27 份 |
| 编译 | 0 错误 0 警告 |

---

## 升级

```bash
cd E:\LucentMist
dotnet build
dotnet test  # 109/109
dotnet run --project src/LucentMist.Web
```
