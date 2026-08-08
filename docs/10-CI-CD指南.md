# LucentMist CI/CD 指南

> 版本: v0.2.0 | 更新: 2026-07-30

---

## 1. 概述

LucentMist 使用 **GitHub Actions** 作为 CI/CD 平台。每次推送代码或创建 Pull Request 时，自动触发编译和测试流水线。

### 流水线架构

```
Push / PR → GitHub Actions
                ├── ubuntu-latest: restore → build → test
                └── windows-latest: restore → build → test
```

---

## 2. 触发条件

| 事件 | 分支 | 说明 |
|------|------|------|
| `push` | `main`, `master`, `develop` | 推送代码即触发 |
| `pull_request` | `main`, `master` | PR 创建/更新时触发 |

---

## 3. 流水线步骤详解

配置文件：`.github/workflows/ci.yml`

### 3.1 Checkout

```yaml
- uses: actions/checkout@v4
```

拉取仓库代码到 CI 运行环境。

### 3.2 安装 .NET SDK

```yaml
- uses: actions/setup-dotnet@v4
  with:
    dotnet-version: |
      8.0.x
      10.0.x
```

安装 .NET 8.0（源项目目标框架）和 .NET 10.0（测试项目目标框架）两个 SDK。`.NET 10 SDK` 向下兼容编译 `net8.0` 项目。

### 3.3 还原依赖

```bash
dotnet restore
```

下载所有 NuGet 包依赖。

### 3.4 编译（Release 模式）

```bash
dotnet build -c Release --no-restore
```

以 Release 配置编译整个解决方案，`--no-restore` 跳过重复还原。

### 3.5 运行测试

```bash
dotnet test -c Release --no-build --verbosity normal \
  --logger "trx;LogFileName=test-results.trx"
```

- `--no-build`：跳过重复编译
- `--logger trx`：生成 VSTest 格式测试报告
- `continue-on-error: true`：测试失败不阻断流水线（仍会上传报告）

### 3.6 上传测试结果

```yaml
- uses: actions/upload-artifact@v4
  with:
    name: test-results-${{ matrix.os }}
    path: "**/TestResults/*.trx"
    retention-days: 7
```

测试报告以 artifact 形式上传，保留 7 天。可在 GitHub Actions 页面的 "Artifacts" 区域下载。

---

## 4. 策略矩阵

| 维度 | 可选值 | 当前 |
|------|--------|:--:|
| 操作系统 | `ubuntu-latest`, `windows-latest`, `macos-latest` | ubuntu + windows |

`fail-fast: false` 确保一个平台失败不影响其他平台继续运行。

### 添加 macOS 支持

在 `.github/workflows/ci.yml` 的 `matrix.os` 中添加 `macos-latest`：

```yaml
matrix:
  os: [ ubuntu-latest, windows-latest, macos-latest ]
```

---

## 5. 查看测试报告

### 在 GitHub 上

1. 进入仓库 → **Actions** 标签
2. 点击最近的 workflow run
3. 展开 **Run tests** 步骤查看控制台输出
4. 在 **Artifacts** 区域下载 `test-results-*` 文件
5. 使用 Visual Studio 或 `dotnet test` 打开 `.trx` 文件

### 使用 VS Code 扩展

安装 [.NET Test Explorer](https://marketplace.visualstudio.com/items?itemName=formulahendry.dotnet-test-explorer) 可直接在编辑器中查看 trx 报告。

---

## 6. 本地验证

### 一键检查脚本

**Windows (PowerShell)**:
```powershell
.\scripts\check.ps1
```

**Linux/macOS (Bash)**:
```bash
bash scripts/check.sh
```

### 手动执行

```bash
# 精确模拟 CI 步骤
dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build --verbosity normal
```

### 生成测试报告

```bash
dotnet test -c Release --no-build --verbosity normal \
  --logger "trx;LogFileName=test-results.trx"
# 报告位置: **/TestResults/test-results.trx
```

---

## 7. 常见问题

### Q: CI 编译失败，报 "NETSDK1045: 当前 .NET SDK 不支持将 .NET 10.0 设置为目标"

**原因**：CI 环境只安装了 .NET 8.0 SDK，但测试项目目标为 `net10.0`。

**解决**：
- 方案 A：在 `ci.yml` 的 `setup-dotnet` 中同时安装 `8.0.x` 和 `10.0.x`
- 方案 B：将测试项目的 `<TargetFramework>` 改为 `net8.0`

### Q: 测试超时

**原因**：UDP/端口扫描测试涉及网络操作，可能受 CI 网络环境影响。

**解决**：
- 本地运行：`dotnet test --filter "FullyQualifiedName!~UdpScan" ` 跳过网络测试
- 增加超时：在 `ci.yml` 测试步骤添加 `timeout-minutes: 15`

### Q: Windows Runner 上 Ping 测试失败

**原因**：GitHub Actions Windows runner 限制 ICMP 权限。

**解决**：Ping 扫描测试仅在 Linux runner 上运行，或使用 `[Fact(Skip = "Requires admin on Windows")]`

### Q: 如何添加代码覆盖率报告？

```bash
# 安装 coverlet
dotnet tool install -g coverlet.console

# 运行覆盖率测试
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=cobertura

# 上传到 Codecov（需额外配置）
- uses: codecov/codecov-action@v4
  with:
    files: "**/coverage.cobertura.xml"
```

### Q: PR 检查不通过，但本地正常

**排查步骤**：
1. 对比本地和 CI 的 .NET SDK 版本：`dotnet --version`
2. 确认所有文件已提交：`git status`
3. 本地完全模拟 CI：`dotnet clean && dotnet restore && dotnet build -c Release && dotnet test -c Release`
