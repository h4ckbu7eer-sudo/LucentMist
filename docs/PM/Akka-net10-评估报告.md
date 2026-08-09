# Akka.NET net10 兼容评估报告

> 日期: 2026-08-09 | 责任人: 开发 | 关联 WBS: 1.1.1

## 结论

**维持分层 TFM，不将纯库升级到 net10。**

## 评估依据

1. 当前 `Core/Tools/Agent/Scanning/CLI` 为 `net8.0`，由 .NET 10 SDK 统一编译，并在 Windows/Ubuntu CI 上全绿。
2. 现有离线测试 173/173 全部通过，其中 Core/Actor 相关测试在 net10 测试宿主下运行正常。
3. Akka.NET 1.5 官方未声明 net10 支持；直接升级存在未知运行时风险，且不阻塞发布目标。
4. CLI 独立为 net8 可执行程序，API/Web 继续 net10，两者通过 HTTP 接口交互，已满足 R1 预案 A 的架构。

## 决策

- API/Web/tests：`net10.0`，维持。
- Core/Tools/Agent/Scanning/CLI：`net8.0`，维持。
- Docker 使用 SDK 10.0 统一构建，运行时 `aspnet:10.0`，CLI 以 net8 + `RollForward=LatestMajor` 发布进镜像。
- v1.0.0-rc1 阶段重新评估是否升级。

## 风险

- 若后续 Akka.NET 官方发布 net10 支持并验证通过，再评估全量升级。
