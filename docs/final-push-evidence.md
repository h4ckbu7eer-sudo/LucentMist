# 0.9.6 最终推送证据

日期：2026-08-31。**0.9.6 已发布：main/tag CI 全部成功，GHCR manifest 可读，独立拉起返回 health 200。**

## 发布范围与不可变版本

发布提交：`98666f8e862c5ec7eb59fe317991c916ae0e8e90`，标签 `v0.9.6`。
开始时 main 实际领先远端 12 个提交：用户关注的最新 8 个真实验证提交，及其前置 4 个自用收尾提交。
本次正常推送这 12 个祖先提交及 1 个版本化提交；没有重写历史，也没有挪动旧版标签。
后续纯 Markdown 证据提交不改变已验证的应用或镜像内容。

```text
$ git push --atomic origin main v0.9.6
To https://github.com/h4ckbu7eer-sudo/LucentMist.git
   d52ca679..98666f8e  main -> main
 * [new tag]           v0.9.6 -> v0.9.6
exit=0

$ git ls-remote --tags origin v0.9.6 v0.9.6^{}
84684f35ee2d429376390fd937b5117201cb4c54 refs/tags/v0.9.6
98666f8e862c5ec7eb59fe317991c916ae0e8e90 refs/tags/v0.9.6^{}
exit=0
```

## 本地门禁

版本化前和版本化后均执行完整门禁，结果相同。0.9.6 的测试 TRX 分项如下：

| 测试项目 | 通过 | 失败 | 跳过 |
| --- | ---: | ---: | ---: |
| Scanning | 31 | 0 | 0 |
| API | 28 | 0 | 0 |
| Agent | 95 | 0 | 0 |
| Tools | 379 | 0 | 0 |
| .NET 合计 | **533** | **0** | **0** |
| Python 检查器（独立统计） | **14** | **0** | **0** |

执行命令与结果：

```text
dotnet restore
dotnet build -c Release --no-restore
  0 Warning(s), 0 Error(s)
dotnet test -c Release --no-build --no-restore --logger "trx;LogFilePrefix=versioned" --results-directory .tmp/release-0.9.6/versioned-tests
  31 + 28 + 95 + 379 = 533 passed; 0 failed; 0 skipped
dotnet format --verify-no-changes --no-restore
  exit=0
python -B -m unittest discover -s scripts -p test_*.py
  Ran 14 tests; OK
docker compose config --quiet
  exit=0
docker compose -f docker-compose.yml -f docker-compose.self-use.yml config --quiet
  exit=0
git diff --check
  exit=0
git diff --cached --check
  exit=0
```

上面是命令结果摘要，不冒充逐行完整构建日志。533 是当前本地全量测试数，不包含 Python 的 14。

## 凭据与工作区保护

本轮未调用 DeepSeek。精确匹配器通过内存环境变量接收原授权 key，不把其写入参数、文件或输出。
发布提交和标签建立后、推送前，实际输出：

```json
{"workingTree":"ABSENT","index":"ABSENT","localGitHistoryAndObjects":"ABSENT","indexObjectsChecked":412,"gitObjectsChecked":2866}
```

范围包括隐藏/忽略/二进制工作树文件、暂存区、全部本地 Git 对象和 Git 元数据，不只搜索文本源码。
这说明本地可访问对象中未发现该精确 key，不代表撤销聊天中已经公开的 key，也不证明所有其它秘密均不存在。

远端核验完成、证据文档已暂存时再次精确检查：

```json
{"workingTree":"ABSENT","index":"ABSENT","localGitHistoryAndObjects":"ABSENT","indexObjectsChecked":413,"gitObjectsChecked":2873}
```

原有 `tests/LucentMist.Tools.Tests/packages.lock.json` 的 364 行依赖增量未提交；仅暂存其中旧 HEAD 的版本引用修改。
原有 `.codex/`、`.workbuddy/`、`deliverables/` 未跟踪目录也未混入提交。

## 远端 CI

本次提交对应两次独立 push CI，核验必须指向这两个运行，不沿用历史运行：

- [main CI 33380904957](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33380904957)
- [v0.9.6 CI 33380904724](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33380904724)

以下为实际 `gh run view` 输出的 run/jobs 摘录（其余 annotations/artifacts 不重复贴出）：

```text
$ gh run view 33380904957
✓ main CI · 33380904957
JOBS
✓ Build & Test (ubuntu-latest) in 1m17s (ID 99452816410)
✓ Build & Test (windows-latest) in 3m0s (ID 99452816556)
✓ Build & Push GHCR in 1m47s (ID 99453567062)
exit=0

$ gh run view 33380904724
✓ v0.9.6 CI · 33380904724
JOBS
✓ Build & Test (ubuntu-latest) in 1m15s (ID 99452814920)
✓ Build & Test (windows-latest) in 3m17s (ID 99452815119)
✓ Build & Push GHCR in 1m41s (ID 99453627851)
exit=0
```

两次 CI 均成功。Actions 仍提示若干 action 声明 Node 20、平台强制使用 Node 24 的维护警告；
这是工作流依赖维护提示，不是 .NET 构建警告，不将它隐去或写成测试失败。
中途一次 `gh run view` 发生代理 EOF，后续读取成功；读取失败不等于 workflow 失败。
随后收口的证据提交仅含 Markdown；`ci.yml` 的 paths-ignore 会排除这类 push。
因此本页 CI 证明的是发布提交 `98666f8e` 的生产内容，不虚构证据文档自身又跑了一轮 CI。

## GHCR 与回滚

本地 Docker 客户端为 29.6.2，网络请求走当前进程代理 `http://127.0.0.1:7897`。
没有修改用户的全局代理配置，没有禁用 TLS 校验。失败也记录：

```text
$ docker manifest inspect ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.5
Get ".../token?...": EOF
exit=1

$ docker manifest inspect ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.5
failed to configure transport: error pinging v2 registry: ... TLS handshake timeout
exit=1
```

后续一次普通模式返回 `unsupported manifest format`。改用详细读取模式后成功；不能把先前失败写成成功。
以下摘录实际 JSON 的 `Ref` / `Descriptor` 字段，省略 Raw 与 layers，并非完整 JSON：

```text
$ docker manifest inspect --verbose ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.5
Ref: ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.5
Descriptor.mediaType: application/vnd.docker.distribution.manifest.v2+json
Descriptor.digest: sha256:48271745e38a425340004bf5852e84f8fc08e2cc03a7795d5bf4feb89c9bb698
Descriptor.platform: linux/amd64
exit=0
```

成功命令同时使用仅当前进程的 `GODEBUG=http2client=0`；不能据一次成功断言全部网络故障的根因。
旧版本摘要与 [0.9.5 发布记录](RELEASE_0.9.5.md) 一致，仍可按该摘要回滚（恢复数据库前先按手册备份）。

0.9.6 第一次详细读取也出现过 `unsupported manifest format`；重试同一命令成功，
因此这里只记录观察到的间歇故障，不声称 `--verbose` 能根治错误。

```text
$ docker buildx imagetools inspect ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.6
Name:      ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.6
MediaType: application/vnd.docker.distribution.manifest.v2+json
Digest:    sha256:418807fea37e771e2be7b829e8b6be7e885f8d311da910565d68a0805e6fdf37
exit=0

$ docker manifest inspect --verbose ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.6
Ref: ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.6
Descriptor.digest: sha256:418807fea37e771e2be7b829e8b6be7e885f8d311da910565d68a0805e6fdf37
Descriptor.platform: linux/amd64
exit=0

$ docker manifest inspect --verbose ghcr.io/h4ckbu7eer-sudo/lucentmist:main
Ref: ghcr.io/h4ckbu7eer-sudo/lucentmist:main
Descriptor.digest: sha256:4ef4ec694b9600fd71ea297b0dd83bffc8d42d9ba0b14896618343734918fc7c
Descriptor.platform: linux/amd64
exit=0
```

上面 manifest inspect 仍为 JSON 字段摘录。main 与版本 tag 分别构建，摘要不同，不能互换为同一不可变镜像。
自用固定发布物建议使用 `ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:418807fea37e771e2be7b829e8b6be7e885f8d311da910565d68a0805e6fdf37`。

`latest` 前两次读取分别出现格式错误与 TLS 超时，最后一次成功（JSON 字段摘录）：

```text
$ docker manifest inspect --verbose ghcr.io/h4ckbu7eer-sudo/lucentmist:latest
Ref: ghcr.io/h4ckbu7eer-sudo/lucentmist:latest
Descriptor.digest: sha256:418807fea37e771e2be7b829e8b6be7e885f8d311da910565d68a0805e6fdf37
Descriptor.platform: linux/amd64
exit=0
```

此次观察中 latest 指向版本构建而不是 main 的摘要；两次工作流均可写可变标签，因此不要依赖 latest 作为固定发布点。

### 独立拉取与运行

[Release Image Verification 33381558006](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33381558006)
使用 GitHub Ubuntu runner，拉取已发布镜像，不本地重建替代：

```text
$ gh workflow run release-verification.yml --ref main -f image=ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.6 -f expected_manifest_digest=sha256:418807fea37e771e2be7b829e8b6be7e885f8d311da910565d68a0805e6fdf37
https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33381558006
exit=0

$ gh run view 33381558006
✓ main Release Image Verification · 33381558006
JOBS
✓ Pull, run, and check health in 16s (ID 99454847775)
exit=0

$ gh run view 33381558006 --log
```

最后一个命令的实际日志关键行摘录（保留 UTC 时间；省略 job/step 前缀、拉取进度和其它行）：

```text
2026-08-31T10:15:26.0611206Z Digest: sha256:418807fea37e771e2be7b829e8b6be7e885f8d311da910565d68a0805e6fdf37
2026-08-31T10:15:26.0971435Z Pulled image: ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:418807fea37e771e2be7b829e8b6be7e885f8d311da910565d68a0805e6fdf37
2026-08-31T10:15:28.5068933Z Health response: {"status":"healthy","version":"0.9.6","uptime":"0h 0m"}
2026-08-31T10:15:28.5614601Z       Setting HTTP status code 200.
exit=0
```

日志初次读取 TLS 超时，第二次成功。工作流的摘要不一致分支会退出 1，本次该步骤成功且输出期望摘要；
容器已由工作流清理。此验证证明 API 镜像能拉取启动，不冒充重新跑过 Web/DeepSeek/真实网关全路径。

## 用户核心诉求与使用边界

结论：**可在已授权网络内自用，但不是“自动确认所有漏洞”的工具。**
上一轮真实 DeepSeek 四轮共 77 次调用；经 2026-09-01 重复键勘误，严格契约总计 **74/77**、最终修复轮 **16/17**（原统计 75/77、17/17 高估一次）。见[复算证据](upstream-device-remediation.md)；该发布核验轮未消耗 key 重新跑模型。
详见 [真实复验记录](deepseek-authorized-validation-20260831.md)。
最终交付回答经过证据护栏纠正，JSON 合法不等于模型原始建议永远正确。

真实网关产出 53/80/443 开放面、DNS/TLS 观察、待核实线索和可操作建议；没有把版本未知的线索升级为确认 CVE。
Agent 仍为实验性，操作系统/固件补丁状态、公网暴露和全部安全配置不能靠这份内网报告自动证明。

自用启动：安全设置新 key 环境变量 → 按 [SELF_USE_GUIDE](SELF_USE_GUIDE.md) 隔离启动 →
`agent "看看我的ip"` 核对主接口 → `scan` / `vuln-scan` / `ssl-check` / `report` → 定期 `audit` / `backup`。
不要把旧聊天中的 key 继续当作未泄露凭据；本轮只检查仓库未残留，不替用户管理或撤销 key。
