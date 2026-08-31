# LucentMist 项目状态

> 最后更新：2026-08-31

当前本地有 0.9.6 发布后的网关收敛修复，尚未推送/发布：564 个 .NET 测试与 14 个 Python 测试通过。
真实 DeepSeek 四轮复现/复验共14次调用，最终提交版4轮收敛、0次完成度补查；修复越界端口断言、DNS无依据评级与呈现冗余。
[真实对话与边界](docs/gateway-deepseek-reproduction-20260831.md)；此前[脚本化 Provider 证据](docs/gateway-convergence-validation.md)保留为历史记录，不混称真实模型验证。
下列 0.9.6 CI/镜像信息仍是已发布版本的历史证据，不代表本地新增修复已发布。

## 当前版本：0.9.6（已发布，远端核验通过）

本地真实验证已完成；本次 main/tag CI 的 Windows、Ubuntu、GHCR 三 job 全部成功。
0.9.6 镜像实际拉取、摘要匹配、启动 health 200；旧 0.9.5 镜像仍保留。
最终发布证据集中在 [final-push-evidence](docs/final-push-evidence.md)。

| 项目 | 本地已确认 |
| --- | --- |
| Release 构建 | 0 警告、0 错误 |
| .NET 测试 | 533/533 |
| Python 检查器测试 | 14/14（不混入 .NET 数字） |
| 真实 DeepSeek | 四轮 77 次，最终严格契约 17/17；错误结论经护栏纠正后交付 |
| 网关分析 | 53/80/443、DNS/TLS；线索和建议，非确认漏洞 |
| 自用 | 手册、隔离启动、审计、备份与恢复演练已落地 |

## 使用与边界

- [0.9.6 发布说明](docs/RELEASE_0.9.6.md)
- [自用手册](docs/SELF_USE_GUIDE.md)
- [安全清单](docs/SECURITY_CHECKLIST.md)
- [真实复验](docs/deepseek-authorized-validation-20260831.md)
- [已知限制](docs/known-issues.md)

Ollama 默认为本地 provider；DeepSeek/Claude 需显式配置环境变量。
云端 Agent 会接收问题和工具观察，漏洞云源默认查询但可以关闭。
Agent 保持实验性，不把 JSON 契约合格等同于原始语义永不出错。

下一步是日常自用与问题复现，不新增扫描能力、不声称产品需求已验证。
