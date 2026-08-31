# 0.9.7 发布产物复现与通用性验证

日期：2026-08-31。状态：远端CI/GHCR/health通过，**产物真实对话发现事实矛盾，语义验收未通过**。保留本次完整记录；修复另发0.9.8，不覆盖标签或选择性删除失败输出。

## 版本和代码身份

- 发布提交：`689090d1926372614dd0f21afc3469203c9d271b`。
- 标签：`v0.9.7`，保留旧版本标签，不移动 `v0.9.6`。
- 镜像：`ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.7`。
- manifest：`sha256:9eb19f0ea1c199af9e5f5127b3aebb27b5206c7b63afc7bced2b3222f0f2e0d3`（Linux/amd64）。
- 本次推送包含从远端旧 main 到此版本的13个提交：已有10个依赖/修复提交，以及通用范围守卫、镜像验证支持、版本化三个新提交。没有只推最后三条而遗漏依赖。

## 远端门禁

执行 `git push --atomic origin main v0.9.7` 后，分别通过真实命令核查：

```text
$ gh run view 33406021723
✓ main CI · 33406021723
✓ Build & Test (ubuntu-latest) in 1m15s
✓ Build & Test (windows-latest) in 3m25s
✓ Build & Push GHCR in 1m34s

$ gh run view 33406021516
✓ v0.9.7 CI · 33406021516
✓ Build & Test (windows-latest) in 4m15s
✓ Build & Test (ubuntu-latest) in 1m11s
✓ Build & Push GHCR in 1m40s
```

[main CI](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33406021723)；[tag CI](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33406021516)。这些作业有 Node 20 action-runtime 退役提示，不是 .NET 编译警告，也没有忽略失败作业。

`docker manifest inspect --verbose ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.7` 首次在 GHCR token 请求时 TLS handshake timeout；原命令重试成功，返回上述 digest。第一次失败会保留在证据目录。命令记录器在 Windows GBK 控制台打印 `✓` 时曾编码失败；GitHub 命令本身成功且完整 UTF-8 文件已保存，修正记录器编码后继续。没有把记录器失败当 CI 失败或静默丢弃。

## 通用性，而非网关特例

- `PortScopeEvidence` 按目标合并真实扫描范围，支持任意1–65535数字端口及共享服务名目录，不再只检查RDP/SSH等四项。新增回归覆盖65001、65000、54321、PostgreSQL5432、中文无空格、全端口范围、重复扫描、多目标隔离；避免把IP/CVE编号或明确“未检查”当成端口关闭断言。
- DNS响应比并没有“2.1以下安全”的阈值。回归使用0.1、3.7、20，均拒绝仅凭单次响应比推出低风险；允许明确说明该数值不能推断风险。
- 精简呈现和云端线索最多5条是通用默认规则；不根据192.168.2.1硬编码特例。详细工具证据仍保留，`-v`可查看详细过程。
- 这些是有预算的防误导规则，不是对所有自然语言表达的数学证明。没有扫描的端口和扫描失败都不能据此宣称安全。

## 产物对话：先复现，再判定

使用拉取的不可变digest，`--pull=never`，只挂载新的验证数据目录，不挂载本地源码或DLL。DeepSeek凭据经隐藏输入进入父进程环境，再经stdin进入容器CLI进程环境；提供凭据前检查Docker配置不含该值。模型转发器只转发真实DeepSeek请求，不替代响应，原始响应和会话工具数据分别保留。

网关目标为用户授权的192.168.2.1；对照目标127.0.0.1是**容器自身**，不是Windows宿主机。

- [网关完整输出](validation-evidence/release-0.9.7/initial-gateway-gateway.txt)：3次真实模型调用，0次完成度补查，53/80/443全部分析，DNS共享同一evidenceId，TLS返回ChainErrors/NameMismatch/PartialChain；50条云线索只展示5条，20条历史线索折叠。
- 然而最终模型结论称“2026年到期”，实际`notAfterUtc=2031-07-10T01:32:15Z`；还称“范围外端口（如22、3389、8080）未检查”，但22在实际1–1000范围内。这两项使语义验收失败，即使命令exit=0、契约3/3。
- [容器回环完整输出](validation-evidence/release-0.9.7/initial-local-local.txt)：3次模型调用，0开放端口，范围外3389/6379明确未检查；DNS/TLS无开放服务，不适用。它验证了另一目标的收敛，不证明宿主机安全或所有自然语言表述正确。
- [原始模型响应](validation-evidence/release-0.9.7/model-responses.jsonl)与同目录session工具记录全部保留；本次6/6契约不是10次以上模型基准，也不是语义通过率。

### 本机下载故障与替代路径

本机Docker下载代理关闭，`docker pull ...:0.9.7`在600秒后超时；没有改全局代理或重新构建镜像。通过现有7897代理及Docker已保存的GHCR登录态下载发布manifest、config及15层，逐层验证SHA-256和大小，再以OCI归档`docker load`导入。匿名及不同凭据的尝试出现404/403，未取得镜像；最终使用Docker既有GHCR凭据成功，不绕过访问控制。Docker导入后`RepoDigests`与远端完全相同，OCI revision为`689090d1`，不是本地开发版。

独立[镜像health工作流](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33407072736)直接`docker pull`成功，digest一致，返回`{"status":"healthy","version":"0.9.7","uptime":"0h 0m"}`。这不替代本机真实网关语义验收。

### 修复方向

新增证书到期年份证据校验及确定性日期显示；端口范围守卫双向检查“未扫却断言关闭”和“已扫却称未检查”。补12个回归测试，全量590个.NET测试通过；本地修正版真实网关预检3轮、0次完成度补查，日期事实为2031年，范围外示例不含22。此预检仍不是0.9.8发布镜像验收，须再复验产物。

## 本地门禁

Release build 0警告0错误；578个.NET测试（Tools392、Agent127、Scanning31、API28）全部通过、0跳过；14个Python测试通过。`dotnet format --verify-no-changes --no-restore`、`docker compose config --quiet`、`git diff --check`通过。

本次发布前精确密钥检查工作树、暂存区、全部本地Git对象均为ABSENT；产物验证与证据提交后还须重新检查。保留用户原有Tools lock文件的364行依赖改动，不混入本次提交。
