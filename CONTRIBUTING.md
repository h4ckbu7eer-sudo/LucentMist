# Contributing to LucentMist

感谢你考虑为 LucentMist 贡献代码。

## 开始之前

1. 阅读 `README.md` 和 `docs/12-贡献指南.md`。
2. 在 `.scratch/<feature-slug>/` 创建或关联对应工单。
3. 使用标准 triage label 标记状态。

## 开发流程

1. Fork 项目并创建 feature 分支。
2. 本地运行：

```bash
dotnet build LucentMist.slnx -c Release
dotnet test LucentMist.slnx -c Release --no-build
```

3. 提交信息使用 Conventional Commits：`feat:`、`fix:`、`docs:`、`test:` 等。
4. 提交 PR 前确认构建 0 警告 0 错误，测试全部通过。

## 代码约定

- C# 使用 `.editorconfig` 中的格式约定。
- 工具实现必须通过 `ToolRegistryFactory` 注册，不要在 API/CLI 各写一套。
- 新增工具必须包含单元测试。
- 不要提交密钥、本地路径、`bin/obj` 或离线 NuGet 缓存。

## 安全报告

如果发现安全漏洞，请通过 Issue 私密披露，不要公开利用细节。
