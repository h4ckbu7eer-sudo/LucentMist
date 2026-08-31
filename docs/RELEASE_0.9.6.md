# LucentMist 0.9.6 发布说明

日期：2026-08-31。状态：**已发布，远端 CI、GHCR 与独立镜像启动核验通过。**

## 为什么是新版本

0.9.5 的 Git 标签和 GHCR 版本镜像保持不变。本次用 **0.9.6** 标识累积修复，
不把新的 main/latest 镜像冒充旧 0.9.5 发布物。建议旧版自用者升级；回滚时固定旧版 manifest digest，
见 [0.9.5 历史发布说明](RELEASE_0.9.5.md)，升级前用 `backup` 备份数据库。

远端起点 `d52ca679`，待交付不止最新 8 个提交：还有其前置的 4 个自用手册/报告收尾提交。
按正常祖先链一起推送，不重写历史，不提交工作区预存的锁文件依赖变更。

## 面向用户的变化

1. **产品指纹更谨慎**：VMware Authentication Daemon 的协议标识不再被误当 Workstation 产品版本，
   泛厂商关键词结果不计为已定位的目标漏洞。
2. **证书结论有依据**：主体与签发者不同的叶证书不再任由模型断言“自签”；
   TLS 信任失败时，模型观察、最终核验事实和结论检查都要求核实身份，而不是建议绕过校验。
3. **错误的缓解建议受约束**：SMBGhost 的签名/压缩措施不再混淆，
   回环扫描不被说成已确认其它网卡的监听范围。
4. **空回答与误拦截修复**：空 `final_answer` 要重试；跨句 DNS 差异与“非自签”否定不会误触发降级。
5. **自用交付收尾**：报告总览不再把不完整扫描或 TLS 风险写成“安全”；
   自用手册覆盖授权、隔离启动、审计与备份恢复，增加可运行的密钥检查器。

这些归纳对应上一轮真实验证发现并修复的问题，不是新增加扫描功能或声称漏洞覆盖穷尽。

## 真实验证与边界

- 四轮真实 DeepSeek 共 **77 次调用**；2026-09-01 重复键勘误后严格契约为 **74/77**（旧统计 75/77 高估一次）；失败记录没有删除，见[勘误](upstream-device-remediation.md)。
- 最终生产修复轮 **16/17（94.12%，旧统计误写 17/17）**，主 IP、本机、网关 53/80/443 + DNS/TLS、REPL 复用全部完成；路径完成不代表首次模型契约全对。
- 模型中途仍出现过错误总结，经过证据护栏纠正后才交付；100% JSON 契约不是 100% 原始语义正确。
- 原始记录与逐项结论：[授权真实复验](deepseek-authorized-validation-20260831.md)、[自用演练](self-use-walkthrough.md)。
- 此发布的版本化只改变版本元数据及发布文档，不另行调用 DeepSeek；本任务只本地精确检查已授权 key。

真实网关仍只能给出**开放面、TLS 风险、线索与建议**。服务版本未知时不能确认具体 CVE；
云源限流、404、超时会降低覆盖；公网暴露、口令强度、设备补丁状态没有被本次内网观察自动证明。
Agent 仍为实验性，本次 CLI/REPL 复验不能冒充新版 Web 浏览器/SSE 全路径复验。
完整边界见 [known-issues](known-issues.md)。

## 自用启动与部署要求

1. 原生部署默认 loopback；Docker 自用叠加 `docker-compose.self-use.yml`，避免默认端口发布到所有接口。
2. DeepSeek key 由用户安全输入到环境，不写脚本、聊天或提交；本手册示例仅用 `<你的key>`。
3. 生产或非回环部署显式设置强 `LMIST_API_TOKEN`、`LMIST_WEB_USER`、`LMIST_WEB_PASSWORD`。
   Docker 自动随机凭据保存在受限权限数据卷文件，日志只说明位置，不打印值；仅适合隔离自用演示。
4. 首次跑 `agent "看看我的ip"` 核对主接口；日常优先 `scan`、`vuln-scan`、`ssl-check`、`report`，
   保留审计并定期 `backup`。SQLite 与导出报告是明文敏感网络数据。
5. 公网目标必须有真实授权且符合 `LMIST_ALLOWED_TARGETS`；明确授权不等于可以扫描任意网络。

照步骤执行见 [自用手册](SELF_USE_GUIDE.md) 与 [安全清单](SECURITY_CHECKLIST.md)。

## 本地与远端发布门禁

发布前基线：Release build 0 警告/0 错误；533 个 .NET 测试、14 个 Python 测试通过；
format、Compose 与 diff 检查通过。0.9.6 版本变更后已再次跑完整门禁，结果相同。

发布提交 `98666f8e862c5ec7eb59fe317991c916ae0e8e90`，标签 `v0.9.6`。
[main CI](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33380904957) 与
[tag CI](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33380904724) 的 Windows、Ubuntu、GHCR 三 job 均成功。
[独立验证](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33381558006) 拉取并核对 manifest 摘要，启动后收到
`{"status":"healthy","version":"0.9.6","uptime":"0h 0m"}`（HTTP 200）。

固定发布镜像：

```text
ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:418807fea37e771e2be7b829e8b6be7e885f8d311da910565d68a0805e6fdf37
```

`0.9.6`、`main`、`latest` 和旧 `0.9.5` 均已通过实际 `docker manifest inspect --verbose` 读取。
真实命令输出及中途代理失败记录见 [final-push-evidence](final-push-evidence.md)。
旧版本镜像不覆盖，main/latest 是可变引用，不适合作为唯一回滚依据。
