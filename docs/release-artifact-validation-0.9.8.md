# 0.9.8 修正版发布产物复验

状态：**0.9.8发布产物复验通过本任务标准**。2026-08-31推送，2026-09-01（UTC+8）完成真实对话核验。main/tag CI、GHCR和独立health均通过；不是移用0.9.7或本地预检结果。

## 为什么不是直接宣布0.9.7完成

[0.9.7发布产物记录](release-artifact-validation-0.9.7.md)显示：3轮收敛、无补查、DNS一致、TLS完成、历史线索折叠都已实现，但模型仍把证书2031年到期说成2026年，把范围内22端口说成未检查。完整失败输出保留，因此没有把“CI成功/JSON成功”当成“结论正确”。

修复提交`a57a6e46`新增通用证书年份/反向范围校验和12个回归。发布提交`bb6f6a18d7fbfbdfa8b2f913c7dcee0aef05de80`，标签`v0.9.8`；旧`v0.9.7`不移动。

## 本地门禁与预检

```text
dotnet build -c Release
0 warnings, 0 errors

dotnet test -c Release --no-build --no-restore
Tools 392 + Agent 139 + Scanning 31 + API 28 = 590 passed
0 failed, 0 skipped

dotnet format --verify-no-changes --no-restore
exit 0
python -B -m unittest discover -s scripts -p 'test_*.py'
Ran 14 tests / OK
docker compose config --quiet
exit 0
git diff --check
exit 0
```

修复后的本地真实DeepSeek网关预检3轮、0次完成度补查，到期事实显示2031年，范围外举例不含22。这只是推送前预检，不是下面要求的发布产物复验。

## 远端核验

已执行`git push --atomic origin main v0.9.8`。[main CI](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33410263646)、[tag CI](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33410263371)均针对`bb6f6a18`，实际命令输出摘要：

```text
$ gh run view 33410263646
✓ main CI
✓ Build & Test (ubuntu-latest) in 1m16s
✓ Build & Test (windows-latest) in 3m9s
✓ Build & Push GHCR in 1m45s

$ gh run view 33410263371
✓ v0.9.8 CI
✓ Build & Test (windows-latest) in 2m44s
✓ Build & Test (ubuntu-latest) in 1m13s
✓ Build & Push GHCR in 1m37s

$ git ls-remote --tags origin v0.9.8 v0.9.8^{}
60beffff3318374a9ba317ade00fb186badf845e refs/tags/v0.9.8
bb6f6a18d7fbfbdfa8b2f913c7dcee0aef05de80 refs/tags/v0.9.8^{}
```

`docker manifest inspect --verbose ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.8`前两次TLS超时/EOF，第三次成功：`sha256:8040122220bc4fedca085a75cbc35ce5007cfe975b6eb0a191226f5a35fe2b2e`。与实际GHCR构建日志中的`containerimage.digest`完全相同；GH CLI读取也有两次EOF，重试后才取得上述成功记录。

通过现有代理、Docker已登录GHCR凭据下载原始15层并逐层验证大小/SHA-256，再`docker load`；本地没有重建。导入后的`docker image inspect`显示：

```text
RepoDigests=["ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:8040122220bc4fedca085a75cbc35ce5007cfe975b6eb0a191226f5a35fe2b2e"]
org.opencontainers.image.revision=bb6f6a18d7fbfbdfa8b2f913c7dcee0aef05de80
org.opencontainers.image.version=0.9.8
```

[独立发布镜像验证33411299128](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33411299128)实际`docker pull`、digest匹配、启动health成功（34秒）。真实响应：`{"status":"healthy","version":"0.9.8","uptime":"0h 0m"}`。health不是模型语义验证，下一节单独验收。Node 20 action-runtime退役提示仍存在，不是.NET编译警告。

## 真实产物复验

实际使用上述GHCR不可变digest和`--pull=never`，不挂载本地代码，分别执行真实DeepSeek网关和容器回环分析。只挂载新的验证数据目录；密钥经隐藏输入/进程环境/stdin传递，不放命令行、Docker配置或文档。`127.0.0.1`是容器自身，不能描述成Windows宿主机复测。

由私有环境凭据启动转发器后，执行验证器（下列参数不含key）：

```text
python -B scripts/validate-deepseek.py --scenario gateway --recorder-port 18357 --output <新的私有验证目录> --image ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:8040122220bc4fedca085a75cbc35ce5007cfe975b6eb0a191226f5a35fe2b2e
python -B scripts/validate-deepseek.py --scenario local --recorder-port 18357 --output <另一个新的私有验证目录> --image ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:8040122220bc4fedca085a75cbc35ce5007cfe975b6eb0a191226f5a35fe2b2e
```

镜像内真正执行`dotnet /app/cli/lmist.dll agent "分析 192.168.99.1 的安全风险"`及`agent "分析 127.0.0.1 的安全风险"`。请求转发至真实DeepSeek API，没有脚本化模型替代。

| 验收项 | 实际结果 | 判定 |
| --- | --- | --- |
| 网关收敛 | ping_scan → port_scan → vuln_scan → final_answer，共4次模型调用；0条analysis_completeness观察 | 通过 |
| 暴露面与复用 | TCP 1–1000发现53/80/443；vuln_scan输入`open_ports="53,80,443"`，checkedServices含全部三个端口 | 通过 |
| DNS一致 | service_identify与vuln_scan均`not_observed`，evidenceId同为`c72b4a5662f84ffd9d32c3ece8adf85f`，没有两个相反结论 | 通过 |
| DNS响应比边界 | 2.1仅单次观测，最终结论没有据此断言低风险/安全，未验证公网反射能力 | 通过 |
| TLS | 自动ssl_check成功，ChainErrors/NameMismatch/PartialChain进入结论；到期事实2031-07-10 01:32:15 UTC，无“必须指定目标” | 通过 |
| 云源与呈现 | 40条关键词线索，10条历史线索折叠，最多5条优先项；原始终端147行（含末尾空行），导出146行 | 通过 |
| 事实残留 | 不再误述2026年到期，不再把22列为未检查；未把TLS失败/版本未知当安全 | 通过 |
| 不同目标 | 同一镜像回环目标2轮、0补查，TCP 1–1000无开放端口；未额外执行无意义漏洞匹配，明确UDP/范围外未检查；原始50行，导出49行 | 通过（仅容器视角） |

这两次产物对话严格JSON/action/input契约6/6；它们是定向复现，**不是新的10次以上遵循率基准**。同目录单独标记的prepush是3次本地调用，不并入产物6次。原始模型偶有措辞粗糙（例如产品名称拼写），这不等于实验性Agent已能保证任意对话正确。

完整证据：[网关终端](validation-evidence/release-0.9.8/gateway-gateway.txt)、[回环终端](validation-evidence/release-0.9.8/local-local.txt)、[模型原文](validation-evidence/release-0.9.8/model-responses.jsonl)、[网关工具会话](validation-evidence/release-0.9.8/gateway-sessions.jsonl)、[契约统计](validation-evidence/release-0.9.8/contract-summary.json)、[网关镜像身份与密钥配置检查](validation-evidence/release-0.9.8/gateway-artifact.jsonl)。该目录同时保存CI、manifest失败重试、导入身份、health原始命令输出。

## 用户核心诉求

本次真实发布版可以给出有限但有用的网关评估：实际暴露53/80/443、HTTPS信任未通过、版本未知、需要登录管理端核实固件与证书链。**不能给出确认漏洞清单**：40条云源结果只是协议关键词线索；真实版本未公开，Shodan请求404、NVD节流造成覆盖限制。用户可据此排定核实顺序，不能把它当作网关已安全或已被攻破的证明。

## 通用性与边界

新增26个回归（首次14+残留12）覆盖任意数字端口、共享服务名、多目标范围隔离与合并、范围内外双向误述、多个证书年份、DNS不同响应比。没有针对192.168.99.1、3389或2.1硬编码成功条件。

规则有明确预算，并非覆盖所有自然语言的证明；模型仍属实验性。网关不公开固件/服务版本，云源关键词结果只能算线索，不是确认CVE。TLS信任失败是真实观察，但不等于正在遭受中间人攻击。DNS判断只限当前扫描视角；单次响应比不能判断公网反射攻击风险。没有新的Web浏览器或整网覆盖验证。

两次新产物对话结束后的精确key检查均为：workingTree/index/localGitHistoryAndObjects ABSENT（当时454个index对象、3145个本地Git对象）。最终证据暂存后再次检查也全为ABSENT，479个index对象、3176个本地Git对象（含不可达对象）；[不含key值的检查回执](validation-evidence/release-0.9.8/key-verification-precommit.json)。这是添加回执前的快照，不能自指包含自己的Git对象数；提交后会再次检查，结果在最终交付回执说明。

收尾为纯文档提交，不改变运行代码或重写v0.9.8标签。CI配置忽略docs/Markdown-only推送，因此生产代码的三job证据对应`bb6f6a18`，不是给后续文档提交冒认一个CI运行。仅保留任务前已有Tools lock文件364行依赖改动，以及`.codex/`、`.workbuddy/`、`deliverables/`未跟踪目录，不称这些是干净工作区。

本轮没有更改Docker全局代理。验证器创建的临时容器自动删除；扫描数据库和原始捕获在忽略的私有临时目录，不公开密钥或认证头。
