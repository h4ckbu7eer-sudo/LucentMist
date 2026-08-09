# Ollama 500 故障诊断报告

> 日期: 2026-08-09 | 责任人: 开发 | 关联 WBS: 1.1.2

## 现象

- Ollama `/api/chat` 早期请求返回 500 / 超时。
- Agent CLI 端到端链路不可用。

## 排查过程

1. `ollama list`：`qwen2.5:7b`、`llama3.1:8b` 等模型均存在，无损坏迹象。
2. `GET /api/tags`：200，服务正常。
3. `POST /api/chat`（qwen2.5:7b）：首次 30 秒超时；延长到 120 秒后返回 200。

## 根因

模型首次加载耗时过长：

```json
{
  "load_duration": 92535970200,
  "total_duration": 93280317600
}
```

即加载约 92 秒，超过客户端常见 30 秒等待窗口，表现为超时/500。不是模型损坏，也不是 Ollama 服务不可达。

## 修复与验证

- 模型预热后，`/api/chat` 返回 200。
- `POST /api/v1/agent/chat` SSE 实测输出 `thought → action → observation` 完整推理流。
- 代码侧 `OllamaProvider` 已增加 `/api/tags` 可达性检查（2 秒超时），可区分“服务不可达”和“推理超时”。

## 建议

- 首次使用前执行 `ollama run qwen2.5:7b` 预热，或部署脚本中增加预热步骤。
- 大模型首次加载期间，客户端等待时间应放宽到 120 秒以上。
