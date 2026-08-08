# Sirius 项目 Windows Docker 部署问题排查与解决记录

> 日期: 2026-08-04 | 环境: Win11 + Docker Desktop 4.84.0 + Clash

---

## 一、环境信息

- 操作系统：Windows 11
- Docker：Docker Desktop 4.84.0，Engine v29.6.2
- 代理：Clash（7890）
- 网络：手机热点

---

## 二、问题与解决

### 问题 1：Git 克隆失败

**现象**：
```
fatal: unable to access 'https://github.com/SiriusScan/Sirius.git/': Recv failure
error: RPC failed; curl 56 schannel: server closed abruptly
```

**解决**：
```powershell
git config --global http.proxy http://127.0.0.1:7890
git config --global https.proxy http://127.0.0.1:7890
git config --global http.postBuffer 524288000
git config --global http.sslVerify false
```

### 问题 2：Docker 无法拉取基础镜像

**现象**：Docker Hub 超时、EOF。

**尝试过的方案**：
- 阿里云镜像加速器 → 403 Forbidden
- 中科大镜像加速器 → EOF
- Docker 代理指向 Clash → 仍然 EOF

### 问题 3：镜像加速器不生效

**原因**：代理设置优先级高于 registry-mirrors，两者冲突。

### 问题 4：最终方案 — DaoCloud 镜像源

直接在 Dockerfile 中替换 `FROM` 指令：

```dockerfile
# 修改前
FROM golang:1.24-alpine AS builder
FROM alpine:3.20

# 修改后
FROM m.daocloud.io/docker.io/library/golang:1.24-alpine AS builder
FROM m.daocloud.io/docker.io/library/alpine:3.20
```

---

## 三、部署流程

```powershell
cd E:\LucentMist\Sirius
docker compose -f docker-compose.installer.yaml run --rm sirius-installer
docker compose up -d
```

---

## 四、DaoCloud 镜像源参考

| 原始地址 | DaoCloud 地址 |
|------|------|
| `docker.io/library/alpine:3.20` | `m.daocloud.io/docker.io/library/alpine:3.20` |
| `docker.io/library/golang:1.24-alpine` | `m.daocloud.io/docker.io/library/golang:1.24-alpine` |
| 其他 `docker.io/*` | `m.daocloud.io/docker.io/*` |
