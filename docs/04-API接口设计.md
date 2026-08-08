# LucentMist API 接口设计

## 1. 基础信息

- **Base URL**: `http://localhost:5050`
- **Content-Type**: `application/json`
- **认证**: Bearer Token (`Authorization: Bearer <token>`)
- **版本**: v1

---

## 2. 扫描接口

### 2.1 创建扫描任务

```http
POST /api/v1/scan
Content-Type: application/json

{
  "target": "192.168.1.0/24",
  "scanType": "full",
  "options": {
    "ports": "1-1000",
    "timeout": 5000,
    "concurrency": 100
  }
}
```

**响应**:
```json
{
  "taskId": "a1b2c3d4-...",
  "status": "pending",
  "message": "扫描任务已创建",
  "estimatedTime": "30s"
}
```

### 2.2 查询扫描状态

```http
GET /api/v1/scan/{taskId}
```

**响应**:
```json
{
  "taskId": "a1b2c3d4-...",
  "status": "running",
  "progress": {
    "scanned": 45,
    "total": 256,
    "percentage": 17.5,
    "alive": 12
  },
  "results": [...]
}
```

### 2.3 UDP 端口扫描

```http
POST /api/v1/scan/udp
Content-Type: application/json

{
  "target": "192.168.1.1",
  "ports": "53,123,161,500,514,1900",
  "timeout_ms": 3000,
  "concurrency": 20
}
```

**响应**:
```json
{
  "target": "192.168.1.1",
  "totalScanned": 6,
  "openPorts": [53],
  "services": { "53": "DNS" },
  "scanDuration": "00:00:01.234"
}
```

**端口格式**: 支持逗号分隔（`53,123,161`）和范围（`67-69`），可混合使用（`53,67-69,161`）。

**UDP 服务识别表**:

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

```http
POST /api/v1/scan/ssl
Content-Type: application/json

{
  "target": "example.com",
  "port": 443,
  "timeout_ms": 5000
}
```

**响应**:
```json
{
  "target": "example.com",
  "port": 443,
  "subject": "CN=*.example.com",
  "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1",
  "notBefore": "2026-01-01T00:00:00.0000000Z",
  "notAfter": "2027-01-01T23:59:59.0000000Z",
  "isExpired": false,
  "daysRemaining": 155,
  "thumbprint": "A1B2C3D4..."
}
```

### 2.5 列出扫描历史

```http
GET /api/v1/scan?page=1&size=20
```

---

## 3. Agent 接口

### 3.1 发送消息（ReAct 对话）

```http
POST /api/v1/agent/chat
Content-Type: application/json

{
  "sessionId": "optional-existing-session-id",
  "message": "扫描我的网络并分析安全风险",
  "provider": "ollama",
  "model": "qwen2.5:7b"
}
```

**响应 (SSE 流式)**:
```
event: thought
data: {"content": "分析用户请求，需要先进行网络扫描..."}

event: action
data: {"tool": "PingScanTool", "args": {"target": "192.168.1.0/24"}}

event: observation
data: {"result": "发现 15 台设备在线", "devices": [...]}

event: message
data: {"content": "扫描完成！发现 15 台在线设备，其中...", "done": true}
```

### 3.2 列出会话

```http
GET /api/v1/agent/sessions?page=1&size=20
```

### 3.3 获取会话详情

```http
GET /api/v1/agent/sessions/{sessionId}
```

### 3.4 删除会话

```http
DELETE /api/v1/agent/sessions/{sessionId}
```

---

## 4. 配置接口

### 4.1 获取配置

```http
GET /api/v1/config
```

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
  "version": "0.1.0",
  "uptime": "2h 15m",
  "llmProvider": "ollama",
  "database": "connected",
  "redis": "connected"
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
