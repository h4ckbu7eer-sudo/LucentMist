# LucentMist

> 基于 ReAct 模式的智能网络分析助手 — C# .NET 8/10 + ReAct + Ollama/Claude

## Agent skills

### Issue tracker

工单以本地 Markdown 文件存储在 `.scratch/<feature-slug>/` 下。详见 `docs/agents/issue-tracker.md`。

### Triage labels

使用默认的五标签体系：`needs-triage`、`needs-info`、`ready-for-agent`、`ready-for-human`、`wontfix`。详见 `docs/agents/triage-labels.md`。

### Domain docs

单上下文布局 — `CONTEXT.md` 与 `docs/adr/` 按 `docs/agents/domain.md` 惰性创建，当前不存在时不要报错。详见 `docs/agents/domain.md`。

## Team agents

项目维护一组 Claude Code subagents，位于 `.claude/agents/`。角色包括：
`project-manager`、`security-auditor`、`csharp-backend-engineer`、`blazor-frontend-engineer`、
`qa-engineer`、`devops-engineer`、`docs-writer`、`cve-researcher`、`react-architect`、
`issue-tracker`。使用方式和维护规则见 `.claude/agents/README.md`。
