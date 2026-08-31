# 自用安全清单

此清单由用户每次部署/分享前确认，不替用户预先全部打勾。适用于当前 main；
源码与旧镜像的区别、运行命令见 [自用手册](SELF_USE_GUIDE.md)。

## Key 和账户

- [ ] 曾出现在聊天、截图、日志或提交中的 key 已在**提供商控制台撤销**，不是仅从文件删掉。检查用量/账单及异常调用；创建替代 key，设置可用的消费限制。
- [ ] key 使用密码管理器/当前进程环境注入，不放命令行参数、不放代码/配置 JSON、不贴聊天。手册用隐藏输入，示例只有 `<你的key>`。
- [ ] 若选择 `.env`，理解它是**明文文件**，只授予运行账户读取；Docker Compose 会读取它，原生程序不会自动加载。不要用 `setx` 把临时验证 key 变成持久环境。
- [ ] 不把 key 放在 shell 历史里。完成后关闭相关子进程，再在当前 PowerShell `Remove-Item Env:LMIST_LLM_APIKEY -ErrorAction SilentlyContinue`；这不撤销 key，也不会清除其他进程已有副本。
- [ ] 定期轮换并重启使用旧 key 的进程；具体撤销/新建入口以对应提供商当前控制台为准。Git 忽略/密钥扫描器不能替代撤销。

## 授权与网络出口

- [ ] 只扫描本人设备或获准目标；RFC1918 是地址类别，不是授权证明。
- [ ] Agent 公网目标列入最小 `LMIST_ALLOWED_TARGETS`，不用宽泛网段。CLI/Web 公网确认需人工理解，不能把 `--authorized` 当通用绕过开关。
- [ ] 知道允许列表当前只约束公网，不是禁止其他私网的严格隔离机制；需要严格隔离时由防火墙/容器网络落实。
- [ ] 知道云 CVE 默认开启，仅发送标准服务关键词/CPE/版本等；提供商仍能看到出口 IP。设 `LMIST_CVE_EXTERNAL=false` 关闭。
- [ ] 知道 DeepSeek 会接收对话和工具观察，可能含 IP/拓扑；`LMIST_INJECT_NETWORK_INFO` 未开不代表 Agent 观察不外发。不接受时不用云 LLM。
- [ ] 查看 [网络出口审计](compliance-telemetry-audit.md)，不声称“用了云端 Agent 仍全部数据不离家”。

## 数据和恢复

- [ ] 确认 `LMIST_DB` 绝对路径，CLI/API/Web 使用同一份预期数据库；默认相对 `data/lucentmist.db`，Docker `/app/data/lucentmist.db`。
- [ ] 数据库、审计、会话、报告、日志、备份及随机凭据文件都是明文；限制本机账户/共享目录权限，保护磁盘和备份介质。
- [ ] 报告是主动导出、不会自动分享；分享前删去不必要的 IP、MAC、主机名、端口拓扑、对话和内部路径。
- [ ] 使用 `backup`，不在运行中只拷 `.db`；最近一次备份曾恢复到**不同路径**并核对审计/会话。
- [ ] 覆盖恢复前停止所有写入者，保留备份和 `pre-restore-*`。数据库备份不包含报告、配置和凭据文件。

## 默认姿态与结果解读

- [ ] 原生 loopback；Docker 自用叠加 `docker-compose.self-use.yml`，确认宿主只绑定 127.0.0.1。默认 Compose 并不是只绑定本机。
- [ ] 当前源码生成的随机凭据在数据卷，日志不含值；旧发布镜像行为不同。只在私密终端读取，不贴到问题单。
- [ ] 非回环有强 API token/Web 密码；远程使用配置 TLS 和防火墙，不把 Basic Auth 明文 HTTP 暴露到公网。
- [ ] 未发现漏洞不等于安全；未知版本、失败、候选、版本验证、确认是不同证据等级。命令 exit 0/审计 completed 也不能单独证明检查成功。
- [ ] 监控超时去扫描历史核对；Agent 实验性回答按原始证据复核。

## 可重复的密钥卫生检查

在仓库根目录，需要 Python 3.12+ 和 Git：

```powershell
# 默认检查已跟踪 + 未忽略的未跟踪文件，不输出匹配内容。
python -B scripts/check-secrets.py
# 私下检查 .env、日志等被 Git 忽略的本地文本。
python -B scripts/check-secrets.py --include-ignored
# 测试检查器本身（离线，合成样本，不使用有效凭据）。
python -B -m unittest discover -s scripts -p test_check_secrets.py
```

只输出文件、行号和规则名，绝不输出匹配值。退出码 0=已扫描范围未命中，1=潜在凭据需检查，
2=读取/大小/枚举受限，检查不完整。没有自动删除文件或自动撤销 key。

检测 provider key、GitHub token、AWS access ID、私钥标记和较长明文 secret 赋值。
误报可能是测试数据；在本机人工复核，不要把匹配原文发给别人。发现真 key：先撤销，
再移出版本管理、检查暂存差异；已推送历史的清理需单独协商，不能以重写历史替代撤销。

**边界：** 默认不扫描 `.env` 等忽略文件；加参数才扫描。两种模式均不解码 SQLite/压缩包/二进制，
不扫描 `.git` 历史及 bin/obj/node_modules/虚拟环境缓存；超过 16 MiB 的文件显式报告检查不完整。
不跟随目录链接/联接；文件链接会报告未扫描。低熵密码、未知格式、编码后的 key 可能漏检。
“未命中”只表示此版本规则在该范围未发现模式，不是全机器/聊天/历史零泄露的证明。
提交前另用 `git diff --cached --stat` 核对范围，并私下人工检查暂存内容。

本轮默认扫描仍会命中 `.github/workflows/release-verification.yml` 的固定 CI 测试 token：
它只用于隔离发布验证容器，不是用户/云提供商凭据。保留可见警告而不是添加宽泛忽略规则；
退出码 1 需要人确认。扩大到忽略目录还会命中本地 Sirius 示例，不能据此宣称整个磁盘已排除所有秘密。
