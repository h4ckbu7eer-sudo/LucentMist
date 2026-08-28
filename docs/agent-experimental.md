# Agent 实验状态

Agent 深化位于 `codex/agent-v1` 分支，作为实验能力维护，不随 0.9.3 主分支发布承诺。

## 已实证

- WorkingMemory 精简摘要可将 eval 上下文字符减少约 76%
- `get_evidence` 可以按引用取回原始 observation
- 动态停止和契约降级警告机制已落地
- mock eval 在 10 个场景下通过

## 未实证

- 本地默认模型 `qwen2.5:7b` 在完整生产 prompt 下真实跑分为 0/10
- `get_evidence` 主动调用次数为 0
- Claude `claude-sonnet-4-6` 尚未在真实 API 环境下完成验证

## 用户预期

在 `codex/agent-v1` 分支上，Agent 会在模型不符合契约时明确提示“已降级为确定性摘要”。主分支 0.9.3 的旧版 Agent 没有该警告机制，仍可能静默返回摘要。不要将默认模型下的 Agent 输出视为经过验证的 AI 安全分析结论。

## 转正条件

Claude 完整 prompt 复测达到：

- 10 场景通过率 >= 7/10
- `openssh-version-cve` 至少 2/3 主动调用 `get_evidence`

达到前，Agent 定位保持为“实验性”，不写入正式产品承诺。
