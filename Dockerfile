# LucentMist Dockerfile — 多阶段构建
# 使用: docker build -t lucentmist:0.5.0 .

# 国内网络构建可覆盖: docker build --build-arg NUGET_SOURCE=https://repo.huaweicloud.com/repository/nuget/v3/index.json
ARG NUGET_SOURCE=https://api.nuget.org/v3/index.json

# ============ 构建阶段 ============
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG NUGET_SOURCE=https://api.nuget.org/v3/index.json
WORKDIR /src

# 复制项目文件
COPY LucentMist.slnx ./
COPY src ./src/

# 还原依赖（只还原运行项目，测试由 CI 执行）
RUN cat > /tmp/NuGet.config <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="mirror" value="${NUGET_SOURCE}" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
  <config>
    <add key="httpRequestTimeout" value="30" />
  </config>
</configuration>
EOF
RUN dotnet restore src/LucentMist.API/LucentMist.API.csproj --configfile /tmp/NuGet.config \
 && dotnet restore src/LucentMist.API/LucentMist.API.csproj --configfile /tmp/NuGet.config \
 && dotnet restore src/LucentMist.API/LucentMist.API.csproj --configfile /tmp/NuGet.config
# 复制源码
COPY . .

# 编译运行项目
RUN dotnet build src/LucentMist.API/LucentMist.API.csproj -c Release --no-restore

# 发布 API
RUN dotnet publish src/LucentMist.API -c Release -o /app/api --no-restore

# ============ 运行阶段 ============
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# 安装 curl 用于健康检查（可选）
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制产物
COPY --from=build /app/api ./api

# 复制配置模板
COPY config/ ./config/

# 创建数据目录
RUN mkdir -p /app/data /app/logs

# 暴露 API 端口
EXPOSE 5050

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:5050/api/v1/health || exit 1

# 默认启动 API 服务
ENTRYPOINT ["dotnet", "api/LucentMist.API.dll"]
