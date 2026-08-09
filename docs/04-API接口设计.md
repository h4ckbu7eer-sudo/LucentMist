# LucentMist API 接口设计

## 1. 基础信息

- **Base URL**: `http://localhost:5050`
- **Content-Type**: `application/json`
- **认证**: 当前版本未启用鉴权（单用户工具），字段预留
- **版本**: v1

---

## 2. 扫描接口

### 2.1 创建扫描任务

```http
POST /api/v1/scan
Content-Type: application/json

{
  "target": "192.168.1.1",
  "scanType": "ping"
}
```

**响应**:
```json
{
  "taskId": "a1b2c3d4-...",
  "status": "pending",
  "message": "扫描任务已创建"
}
```

`scanType` 支持 `ping`、`tcp`、`udp`。TCP/UDP 默认扫描 `1-1000` 端口；API 当前未开放自定义端口参数，Web 页面使用进程内队列可直接指定端口。

### 2.2 查询扫描状态

```http
GET /api/v1/scan/{taskId}
```

**响应**:
```json
{
  "taskId": "a1b2c3d4-...",
  "target": "192.168.1.1",
  "scanType": "ping",
  "status": "completed",
  "createdAt": "2026-08-08T16:47:32.958Z",
  "startedAt": "2026-08-08T16:47:32.968Z",
  "completedAt": "2026-08-08T16:47:33.016Z",
  "totalDevices": 1,
  "result": {
    "target": "192.168.1.1",
    "scanType": "ping",
    "alive": 1,
    "devices": ["192.168.1.1"],
    "openPortsByIp": {},
    "durationSec": 0.05
  },
  "error": null
}
```

### 2.3 UDP 端口扫描

> 状态：`POST /api/v1/scan` 已支持 `scanType=udp`；专用端点暂未开放。

```http
POST /api/v1/scan
Content-Type: application/json

{
  "target": "192.168.1.1",
  "scanType": "udp"
}
```

返回任务状态后，`result` 中 `openPorts` 为探测到的 UDP 端口，默认端口范围 `1-1000`。

**UDP 服务识别表**：

| 端口 | 服务 | 探测方式 |
|------|------|----------|
| 53 | DNS | DNS 查询包 |
| 67-68 | DHCP | 空探测 |
| 69 | TFTP | 空探测 |
| 123 | NTP | NTP 请求 |
| 137 | NetBIOS-NS | 空探测 |
| 161 | SNMP | SNMP GET |
| 500 | IKE (IPSec) | 空探测 |
| 514 | Syslog | 空探测 |
| 1900 | SSDP | 空探测 |
| 5353 | mDNS | 空探测 |

### 2.4 SSL 证书校验

> 状态：SSL 校验在 CLI 与 Web 页面可用；API 暂未提供专用端点。

CLI 命令：`lmist ssl --target example.com --port 443`。
Web 页面：`/ssl-check`。

### 2.5 列出扫描历史

```http
GET /api/v1/scan?page=1&size=20
```

Web 历史页面：`/scan/history`，直接读取 SQLite，展示最近 50 条任务。

## 3. Agent 接口

### 3.1 发送消息（ReAct 对话）

```http
POST /api/v1/agent/chat
Content-Type: application/json

{
  "sessionId": "optional-existing-session-id",
  "message": "扫描我的网络并分析安全风险",
  "provider": "ollama",
  "model": "qwen2.5:7b",
  "target": null
}
```

当前请求只接受 `message` 和 `sessionId`。LLM Provider、模型与端点由服务端环境变量（`LMIST_LLM_*`）配置，客户端不能切换。传入 `sessionId` 可继续已有会话，否则自动创建新会话。

**响应 (SSE 流式)**:
```
event: thought
data: {"content": "分析用户请求，需要先进行网络扫描..."}

event: action
data: {"tool": "PingScanTool", "args": {"target": "192.168.1.0/24"}}

event: observation
data: {"result": "发现 15 台设备在线", "devices": [...]}

event: error
data: {"content": "Ollama 未运行，请执行 ollama serve", "done": true}

event: message
data: {"content": "扫描完成！发现 15 台在线设备，其中...", "done": true}
```

### 3.2 列出会话

```http
GET /api/v1/agent/sessions?page=1&size=20
```

返回历史会话列表（标题、模型、消息数、更新时间）。

### 3.3 获取会话详情

```http
GET /api/v1/agent/sessions/{sessionId}
```

返回会话详情与完整消息回放。

### 3.4 删除会话

```http
DELETE /api/v1/agent/sessions/{sessionId}
```

> 状态：规划中，当前未实现。

CLI 命令：

```bash
lmist agent --list
lmist agent --resume {id} "继续分析"
```

---

## 4. 配置接口

### 4.1 获取配置

```http
GET /api/v1/config
```

返回实际运行时 LLM 与扫描默认参数。

### 4.2 更新配置

```http
PUT /api/v1/config
Content-Type: application/json

{
  "llm": {
    "provider": "ollama",
    "model": "qwen2.5:7b",
    "endpoint": "http://localhost:11434"
  }
}
```

> 状态：规划中，当前未实现。

---

## 5. 健康检查

### 5.1 健康状态

```http
GET /api/v1/health
```

**响应**:
```json
{
  "status": "healthy",
  "version": "0.9.0",
  "uptime": "2h 15m"
}
```

---

## 6. 错误响应格式

```json
{
  "error": {
    "code": "SCAN_TIMEOUT",
    "message": "扫描超时，目标 192.168.1.0/24 过大",
    "details": "建议缩小扫描范围或增加超时时间",
    "timestamp": "2026-07-26T10:30:00Z"
  }
}
```

### 错误码

| 状态码 | 含义 |
|--------|------|
| 400 | 请求参数错误 |
| 401 | 未授权 |
| 404 | 资源不存在 |
| 408 | 扫描超时 |
| 429 | 请求过于频繁 |
| 500 | 服务器内部错误 |
| 503 | LLM 服务不可用 |

---

## 7. 未提供接口说明

- 漏洞扫描（`vuln_scan`）、报告生成（`report`）、Sirius 集成能力在 CLI 与 Tools 层可用，API 暂未暴露 HTTP 端点。
- Agent 会话持久化、配置更新、UDP/SSL 专用端点为规划中功能，当前请使用 CLI 或 Web 页面。
