# Docker Desktop + WSL2 环境搭建记录

> 日期: 2026-08-03 | 版本: Docker Desktop 4.84.0 + WSL2 Ubuntu 22.04

---

## 1. WSL2 安装（E 盘）

### 1.1 启用 WSL 功能（管理员 PowerShell）
```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

### 1.2 重启后下载 WSL 内核（手动安装）
浏览器打开 `https://github.com/microsoft/WSL/releases/latest`，下载 `wsl.2.7.11.0.x64.msi`，双击安装。

### 1.3 下载 Ubuntu 22.04 包
```powershell
Invoke-WebRequest -Uri "https://aka.ms/wslubuntu2204" -OutFile "E:\ubuntu.appx"
```

### 1.4 解压并导入到 E 盘
```powershell
mkdir E:\WSL\Ubuntu-VM
tar -xf E:\ubuntu.appx -C E:\WSL\Ubuntu-VM
tar -xf E:\WSL\Ubuntu-VM\Ubuntu_2204.1.7.0_x64.appx -C E:\WSL\Ubuntu-VM
wsl --import Ubuntu E:\WSL\Ubuntu-VM E:\WSL\Ubuntu-VM\install.tar.gz
wsl -d Ubuntu
```

### 1.5 清理
```powershell
Remove-Item E:\ubuntu.appx -Force
Remove-Item E:\WSL\Ubuntu -Recurse -Force
```

---

## 2. Docker Desktop 安装

### 2.1 下载安装
```powershell
Invoke-WebRequest -Uri "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe" -OutFile "E:\DockerDesktop-Installer.exe"
```
双击 `E:\DockerDesktop-Installer.exe` 安装。

### 2.2 汉化（当前不可用）
Docker Desktop 4.84.0 **没有 Language 设置选项**，语言跟随 `app.asar` 内嵌文件。汉化包 `https://github.com/asxez/DockerDesktop-CN/releases` 替换后**会导致 Docker 无法启动**（完整性校验失败）。暂时使用英文原版。

### 2.3 重装恢复
如果 Docker 打不开，卸载重装（保留容器和镜像）：
```powershell
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop Installer.exe" -ArgumentList "uninstall" -Wait
# 然后重新下载安装包安装
```

---

## 3. 当前状态

| 组件 | 状态 | 位置 |
|------|:--:|------|
| WSL2 | ✅ 正常 | `E:\WSL\Ubuntu-VM\` |
| Ubuntu 22.04 | ✅ 正常 | 1TB 可用 |
| Docker Desktop 4.84.0 | ✅ 正常（英文） | `C:\Program Files\Docker\` |
| 汉化 | ❌ 不可用 | 等待作者更新 |

---

## 4. 常用命令

```bash
# WSL 进入 Ubuntu
wsl -d Ubuntu

# 查看 WSL 版本
wsl --version

# 查看 WSL 已安装发行版
wsl -l -v

# 重启 LxssManager 服务（WSL 出问题时）
net start LxssManager
```
