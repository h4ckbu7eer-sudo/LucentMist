# 自用数据安全、备份与恢复

## 静态数据现状

LucentMist 使用普通 SQLite。默认数据库是 `data/lucentmist.db`（Docker 中为
`/app/data/lucentmist.db`），其中包含网络目标、开放端口、扫描结果、Agent 会话和审计记录。
**当前没有应用层数据库加密，也没有 `LMIST_DB_ENCRYPTION` 开关。** 能读取该文件的人可以读取这些数据。

自用建议：

- 使用 BitLocker、LUKS 或其他全盘加密；锁屏并保护系统账户。
- 只允许运行 LucentMist 的账户访问 `data/`、`logs/`、`backups/` 和导出报告。
- 不把数据库、报告、日志、`.env` 或容器数据卷提交到 Git/网盘公共目录。
- Docker 随机凭据存放在 `/app/data/lucentmist-*-token/password/user`，权限由 `umask 077` 和
  `chmod 600` 限制；值不会写入容器日志、仓库或镜像层。

报告包含同等敏感的拓扑信息。报告只在用户主动执行导出命令时写到指定路径，LucentMist 没有自动上传、
分享或打开报告的代码。

## 安全备份

不要在 WAL 模式下只复制 `.db`；尚未 checkpoint 的提交可能仍在 `.db-wal` 中。使用内置命令：

```powershell
lmist backup --output backups/lucentmist-20260830.db

# 从源码运行
dotnet run --project src/LucentMist.CLI -- backup --output backups/lucentmist-20260830.db
```

该命令执行完整 WAL checkpoint、SQLite 在线备份和 `quick_check`，然后原子替换目标文件。目标已存在时默认
拒绝覆盖；确认后可使用 `--force`。繁忙数据库无法完成 checkpoint 时命令会失败而不是生成可疑备份。

Docker 建议先暂停写入，再在挂载同一数据卷的 CLI 容器或宿主机工具中执行备份；不要直接复制正在使用的
volume 中的 `.db`。

## 恢复

先停止 API 和 Web，避免另一进程继续持有数据库：

```powershell
lmist restore backups/lucentmist-20260830.db --yes

# 自定义数据库位置
lmist restore backups/lucentmist-20260830.db --database D:\LucentMistData\lucentmist.db --yes
```

恢复会先对备份运行 `quick_check`，然后 checkpoint 当前数据库。旧 `.db`、`.db-wal` 和 `.db-shm` 会移动到
同目录的 `pre-restore-<UTC>-<id>/`，而不是删除；验证恢复成功后由用户决定何时清理。若替换失败，命令会尝试
把安全副本移回原位。

恢复后：

1. 启动 API/Web。
2. 运行 `lmist audit --limit 20`，确认历史审计记录可读。
3. 查看最近扫描历史与 Agent 会话。
4. 保留原备份和 `pre-restore-*`，直到功能核验完成。

## 崩溃恢复边界

启动时 SQLite `quick_check` 发现损坏会把 `.db/.db-wal/.db-shm` 隔离为 `.corrupt-<UTC>` 后创建新库。
这是让服务恢复运行的隔离机制，不是数据修复；应从最近一次通过完整性检查的备份恢复。
