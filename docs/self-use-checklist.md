# LucentMist 自用资格清单

核验日期：2026-08-30。每一项均指向代码行为或可重复验证文档，不以产品口号代替证据。

- [x] **不上传扫描数据或遥测。** 默认无遥测、统计、更新检查或崩溃上报；扫描协议流量、DNS 和显式外部集成边界见 [隐私与网络出口审计](compliance-telemetry-audit.md)。
- [x] **误扫有护栏。** 公网目标在 CLI/Web 需要确认，API 需要显式授权标志；Agent 只允许 `LMIST_ALLOWED_TARGETS` 中的公网 IP、CIDR、域名或 `*.域名`，RFC1918/回环默认允许。
- [x] **审计日志可查。** SQLite `scan_audit` 记录时间、目标、发起者（CLI/API/Web/Agent）、操作、状态和限长摘要；`lmist audit --limit 50` 可查询，原始结果与凭据不写入审计摘要。
- [x] **数据存储状态已知。** 数据库为明文 SQLite，没有虚构加密开关；本机权限和全盘加密建议见 [数据安全与恢复](data-security-and-recovery.md)。
- [x] **备份/恢复可用。** `lmist backup` 覆盖 WAL checkpoint、在线快照和完整性检查；`lmist restore --yes` 校验备份并保留旧库及 sidecar 的可回滚副本。
- [x] **崩溃恢复可用。** 启动完整性检查会隔离损坏数据库；真正的数据恢复依赖经过检查的备份。
- [x] **默认安全姿态。** 非 Docker API/Web 默认只绑定 loopback；非回环监听缺少凭据会拒绝启动。Docker 以非 root 运行并生成随机凭据。
- [x] **无密钥泄露到报告/日志。** 报告模型没有凭据字段；容器只记录凭据文件位置，不记录 token/密码值；应用日志不记录认证请求头或 LLM API key。
- [x] **已知限制对当前自用范围可接受。** 外部 CVE 证据边界、UDP 推断、证书时区、候选漏洞与 Agent 实验性状态继续保留在 [known-issues.md](known-issues.md)。

## 每次自用前的最小操作

1. 只扫描自己拥有或获准测试的目标；公网自动化优先配置最小 `LMIST_ALLOWED_TARGETS`。
2. 若不希望数据交给云端，保持 Ollama loopback，关闭 `LMIST_CVE_EXTERNAL` 和 Sirius。
3. 确认 `data/`、`logs/`、`backups/` 与报告目录只有当前账户可读。
4. 扫描后运行 `lmist audit --limit 20`；重要数据定期运行 `lmist backup`。
5. 把漏洞命中理解为候选证据，不把“未发现”理解为绝对安全证明。
