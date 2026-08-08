# Sirius 漏洞扫描器 Windows Docker 部署完整指南

> 项目地址: https://github.com/SiriusScan/Sirius  
> 部署环境: Windows 11 + Docker Desktop 4.84.0 (WSL2)  
> 部署路径: `E:\LucentMist\Sirius`  
> 文档日期: 2026-08-04  
> 部署状态: ✅ 全部 6 个服务运行正常

---

## 目录

1. [项目概述](#1-项目概述)
2. [环境要求](#2-环境要求)
3. [部署步骤](#3-部署步骤)
4. [部署中的困难与解决方案](#4-部署中的困难与解决方案)
5. [服务状态验证](#5-服务状态验证)
6. [登录方式](#6-登录方式)
7. [常用管理命令](#7-常用管理命令)
8. [关键配置与日志位置](#8-关键配置与日志位置)
9. [架构概览](#9-架构概览)
10. [后续维护建议](#10-后续维护建议)

---

## 1. 项目概述

Sirius（天狼星）是一个开源通用漏洞扫描器，基于 Nmap NSE 脚本实现真实漏洞验证。

| 维度 | 详情 |
|------|------|
| 技术栈 | Go + Next.js + PostgreSQL + RabbitMQ + Valkey |
| 部署方式 | Docker Compose |
| Web UI | `http://localhost:3000` |
| REST API | `http://localhost:9001` |
| 部署路径 | `E:\LucentMist\Sirius` |

### 服务清单

| 服务 | 技术 | 端口 | 用途 |
|------|------|------|------|
| `sirius-ui` | Next.js | 3000 | Web 管理界面 |
| `sirius-api` | Go/Gin | 9001 | REST API |
| `sirius-engine` | Go | 5174, 50051 | 扫描引擎 |
| `sirius-postgres` | PostgreSQL | 5432 | 数据库 |
| `sirius-rabbitmq` | RabbitMQ | 5672, 15672 | 消息队列 |
| `sirius-valkey` | Valkey (Redis 兼容) | 6379 | 缓存 |

---

## 2. 环境要求

### 硬件

| 组件 | 最低 | 推荐 |
|------|------|------|
| CPU | 4 核 | 8 核 |
| 内存 | 8 GB | 16 GB |
| 磁盘 | 20 GB | 50 GB+ |

### 软件

| 软件 | 版本 | 必需 |
|------|------|:--:|
| Windows | 10/11 64-bit | ✅ |
| WSL2 | 内核 6.18+ | ✅ |
| Docker Desktop | 4.84+ | ✅ |
| Git | 2.40+ | 可选（可用 ZIP） |

### 网络

- 开放端口：3000、9001、5432、5672、6379
- 建议配置代理以加速镜像拉取（详见困难 2）

---

## 3. 部署步骤

### 3.1 获取源码

**方案 A：直接下载 ZIP（推荐）**

浏览器打开 `https://github.com/SiriusScan/Sirius` → Code → Download ZIP → 解压到 `E:\LucentMist\Sirius`

**方案 B：Git 克隆（需配置代理）**

```powershell
git config --global http.proxy http://127.0.0.1:7890
git config --global https.proxy http://127.0.0.1:7890
git config --global http.postBuffer 524288000
git clone https://github.com/SiriusScan/Sirius.git E:\LucentMist\Sirius
```

### 3.2 修改 Dockerfile（解决镜像拉取问题）

编辑 `E:\LucentMist\Sirius\installer\Dockerfile`：

```dockerfile
# 原始
FROM golang:1.24-alpine AS builder
FROM alpine:3.20

# 改为 DaoCloud 镜像源
FROM m.daocloud.io/docker.io/library/golang:1.24-alpine AS builder
FROM m.daocloud.io/docker.io/library/alpine:3.20
```

### 3.3 构建并启动

```powershell
cd E:\LucentMist\Sirius
docker compose -f docker-compose.installer.yaml run --rm sirius-installer
docker compose up -d
```

### 3.4 创建管理员用户

首次部署后数据库无用户，需手动插入：

```powershell
docker compose exec sirius-postgres psql -U postgres -d sirius -c "INSERT INTO users (created_at, updated_at, name) VALUES (NOW(), NOW(), 'admin');"
```

---

## 4. 部署中的困难与解决方案

### 困难 1：Git 克隆失败

**现象**：
```
fatal: unable to access '...': Recv failure: Connection was reset
error: RPC failed; curl 56 schannel: server closed abruptly
fatal: early EOF
fatal: fetch-pack: invalid index-pack output
```

**原因**：代理未配置 + 缓冲区太小 + 网络波动。

**尝试过程**：

| 尝试 | 结果 |
|------|------|
| 配置代理 + 增大缓冲区 | 仍因网络波动中断 |
| `git clone --depth 1` | 浅克隆，仍失败 |
| SSH 密钥克隆 | 配好密钥后速度仍慢 |

**最终方案**：放弃 Git，从 GitHub 页面直接下载 ZIP 包解压。

---

### 困难 2：Docker 拉取基础镜像失败

**现象**：
```
failed to do request: Head "https://registry-1.docker.io/v2/library/alpine/manifests/3.20": EOF
failed to fetch oauth token: Post "https://auth.docker.io/token": dial tcp ...:443: i/o timeout
```

**原因**：国内网络访问 Docker Hub 受限。

**尝试过程**：

| 方案 | 结果 |
|------|------|
| 阿里云镜像加速器 `https://i2sqslrg.mirror.aliyuncs.com` | 403 Forbidden |
| 中科大镜像加速器 `https://docker.mirrors.ustc.edu.cn` | EOF |
| Docker 代理指向 Clash (`127.0.0.1:7890`) | TLS 连接不稳定 |
| 多镜像源组合 | 均失败 |

**最终方案**：修改 `installer/Dockerfile`，将 `FROM` 指令替换为 DaoCloud 镜像源：

```dockerfile
FROM m.daocloud.io/docker.io/library/golang:1.24-alpine AS builder
FROM m.daocloud.io/docker.io/library/alpine:3.20
```

**DaoCloud 镜像源格式**：`m.daocloud.io/docker.io/library/<镜像名>:<标签>`

---

### 困难 3：Docker 代理与镜像加速器冲突

**现象**：配置 `registry-mirrors` 后，`docker info | findstr "registry.mirrors"` 始终为空。

**原因**：Docker 代理优先级 > 镜像加速器。Containers proxy 设为 Manual 时，所有流量走代理，registry-mirrors 被忽略。

**结论**：代理和镜像加速器**不可同时生效**。本项目最终放弃两者，直接改 Dockerfile 中的镜像地址。

---

### 困难 4：管理员用户无法登录（最关键）

**现象**：`http://localhost:3000` 登录页，使用 `admin@example.com` + 安装器生成密码，始终返回：
```
Invalid username or password. Please try again.
```

排查过程中尝试了 `admin@example.com`、`admin`、`user@example.com` 等多种组合，均失败。

**原因链**：

1. `docker-compose.yaml` 中 `sirius-api` 没有 `INITIAL_ADMIN_PASSWORD` 环境变量 → API 启动时未创建管理员
2. 添加环境变量后仍失败 → administrator 工具通过 RabbitMQ `admin_commands` 队列接收命令，需要 `target` 字段
3. 添加 `target` 后返回 `Unknown admin action: create_user` → 尝试 `add_user`/`new_user`/`register` 均失败
4. administrator 工具**不支持创建用户**

**最终方案**：直接操作 PostgreSQL 数据库：

```powershell
docker compose exec sirius-postgres psql -U postgres -d sirius -c "INSERT INTO users (created_at, updated_at, name) VALUES (NOW(), NOW(), 'admin');"
```

成功后用以下凭证登录：

| 字段 | 值 |
|------|------|
| 用户名 | `admin` |
| 密码 | `<替换为你的密码>` |

---

## 5. 服务状态验证

### 验证所有服务运行

```powershell
docker compose ps
```

期望输出：6 个服务均为 `running` 或 `healthy` 状态。

### 验证 Web UI

```powershell
curl http://localhost:3000
```

浏览器打开 `http://localhost:3000`，应显示登录页面。

### 验证 API

```powershell
curl http://localhost:9001/api/v1/health
```

### 验证数据库

```powershell
docker compose exec sirius-postgres psql -U postgres -d sirius -c "\dt"
```

---

## 6. 登录方式

| 字段 | 值 |
|------|------|
| URL | `http://localhost:3000` |
| 用户名 | `admin` |
| 密码 | `<替换为你的密码>` |

### 关键凭证

| 凭证 | 值 |
|------|------|
| 管理员密码 | `<替换为你的密码>` |
| API Key | `<替换为你的 API Key>` |

---

## 7. 常用管理命令

### 服务管理

```powershell
# 启动
docker compose up -d

# 停止
docker compose down

# 重启单个服务
docker compose restart sirius-api

# 查看所有服务状态
docker compose ps

# 查看日志
docker compose logs -f sirius-api
docker compose logs -f --tail 100
```

### 数据库操作

```powershell
# 进入 PostgreSQL
docker compose exec sirius-postgres psql -U postgres -d sirius

# 查看用户
SELECT * FROM users;

# 查看表结构
\d users
```

### 管理员日志

```powershell
docker compose exec sirius-api sh -c "cat /tmp/administrator.log"
docker compose exec sirius-api sh -c "tail -f /tmp/administrator.log"
```

---

## 8. 关键配置与日志位置

### 配置文件

| 文件 | 用途 |
|------|------|
| `E:\LucentMist\Sirius\docker-compose.yaml` | 服务编排 |
| `E:\LucentMist\Sirius\.env` | 环境变量 |
| `E:\LucentMist\Sirius\installer\Dockerfile` | 安装器构建 |

### 关键环境变量

```ini
# ⚠️ 请替换为你自己的随机值，不要使用示例值
INITIAL_ADMIN_PASSWORD=<替换为你的强密码>
API_KEY=<替换为你生成的 API Key，可用: openssl rand -hex 32>
POSTGRES_DB=sirius
POSTGRES_USER=postgres
```

---

## 9. 架构概览

```
                  ┌──────────────┐
                  │  sirius-ui   │  Next.js :3000
                  │  (前端)      │
                  └──────┬───────┘
                         │ HTTP
                  ┌──────▼───────┐
                  │  sirius-api  │  Go/Gin :9001
                  │  (后端)      │
                  └──┬───┬───┬───┘
                     │   │   │
          ┌──────────┘   │   └──────────┐
          ▼              ▼              ▼
   ┌────────────┐ ┌───────────┐ ┌───────────┐
   │ postgres   │ │ rabbitmq  │ │  valkey   │
   │ :5432      │ │ :5672     │ │  :6379    │
   └────────────┘ └───────────┘ └───────────┘
                     ▲
          ┌──────────┘
          ▼
   ┌────────────┐
   │  engine    │  Go :5174 :50051
   │  (扫描)    │
   └────────────┘
```

- **sirius-ui** 通过 HTTP 调用 **sirius-api**
- **sirius-api** 通过 RabbitMQ 向 **sirius-engine** 下发扫描任务
- **sirius-engine** 执行扫描后将结果写入 PostgreSQL
- **valkey** 作为缓存加速高频查询

---

## 10. 后续维护建议

### 日常维护

```powershell
# 定期备份数据库
docker compose exec sirius-postgres pg_dump -U postgres sirius > sirius_backup.sql

# 清理旧日志（镜像内）
docker compose exec sirius-api sh -c "> /tmp/administrator.log"

# 更新镜像（修改 Dockerfile 后）
docker compose build --no-cache
docker compose up -d
```

### 备份与恢复

```powershell
# 备份
docker compose exec sirius-postgres pg_dump -U postgres sirius > backup.sql

# 恢复
docker compose exec -T sirius-postgres psql -U postgres -d sirius < backup.sql
```

### 故障恢复

```powershell
# 完全重建
docker compose down -v
docker compose -f docker-compose.installer.yaml run --rm sirius-installer
docker compose up -d

# 重新创建管理员
docker compose exec sirius-postgres psql -U postgres -d sirius -c "INSERT INTO users (created_at, updated_at, name) VALUES (NOW(), NOW(), 'admin');"
```

---

## 困难汇总速查表

| 序号 | 困难 | 根本原因 | 最终方案 |
|:--:|------|------|------|
| 1 | Git 克隆失败 | 网络 + 代理 + 缓冲区 | 下载 ZIP 包 |
| 2 | Docker 拉取镜像失败 | 国内访问 Docker Hub 受限 | 修改 Dockerfile 使用 DaoCloud |
| 3 | 代理与镜像加速器冲突 | Docker 优先级机制 | 放弃代理，直接改镜像地址 |
| 4 | 管理员无法登录 | API 未收到环境变量，administrator 不支持创建用户 | 直接插入数据库 users 表 |

---

*文档生成时间: 2026-08-04 | 作者: LucentMist Team*
