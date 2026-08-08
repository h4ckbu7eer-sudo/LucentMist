# LucentMist Agent Team

本项目维护一组 Claude Code subagents。目录组织参考了 GitHub 上的
[`VoltAgent/awesome-claude-code-subagents`](https://github.com/VoltAgent/awesome-claude-code-subagents)
和 [`wshobson/agents`](https://github.com/wshobson/agents)，
但每个 agent 的职责、工作流和验收标准都按 LucentMist 的实际代码与约定定制。

## 角色列表

| Agent | 用途 |
| --- | --- |
| `project-manager` | 现状核实、任务拆解、范围与验收 |
| `security-auditor` | 密钥、输入边界、注入、异步泄漏、CVE 误报审计 |
| `csharp-backend-engineer` | Core / Agent / Tools / API 后端开发 |
| `blazor-frontend-engineer` | Blazor 页面、ScanService、SignalR |
| `qa-engineer` | 测试设计、边界条件、回归与性能检查 |
| `devops-engineer` | Docker、CI/CD、发布与部署 |
| `docs-writer` | README、状态文档、发布说明、规划文档 |
| `cve-researcher` | CVE 情报、CPE 匹配、Banner 版本解析、误报治理 |
| `react-architect` | ReAct 引擎与 LLM Provider 架构 |
| `issue-tracker` | 本地 Markdown 工单与 triage |

## 使用方式

Claude Code 会自动加载 `.claude/agents/` 下的 subagent。需要指定角色时直接说
“使用 `project-manager`”或通过 `@project-manager` 引用；也可以交给 Claude Code 根据
`description` 自动选择。

## 维护规则

- 一个角色一个文件，文件名即 agent 名，不要合并。
- 修改角色定义后，同步更新本 README 和根目录 `AGENTS.md` / `CLAUDE.md` 的角色清单。
- agent 描述要写“何时触发”，不要写空泛的“你是一个专家”。
- 不要在任何 agent 文件中写入 API Key、Token 或密码。
- agent 内容以项目真实路径为准；代码结构变化后应同步更新，避免引用过期路径。
- 外部来源的 agent 只能作为组织方式和思路参考，不允许未经审查直接整份复制进项目。
