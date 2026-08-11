# LucentMist Dockerfile — 多阶段构建
# 使用: docker build -t lucentmist:0.9.2 .

# 国内网络构建可覆盖: docker build --build-arg NUGET_SOURCE=https://repo.huaweicloud.com/repository/nuget/v3/index.json
ARG NUGET_SOURCE=https://api.nuget.org/v3/index.json

# ============ 构建阶段 ============
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG NUGET_SOURCE=https://api.nuget.org/v3/index.json
WORKDIR /src

# 复制项目文件
COPY Directory.Build.props ./
COPY Directory.Packages.props ./
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
RUN for i in 1 2 3; do dotnet restore src/LucentMist.API/LucentMist.API.csproj --configfile /tmp/NuGet.config && break; sleep 3; done
RUN for i in 1 2 3; do dotnet restore src/LucentMist.Web/LucentMist.Web.csproj --configfile /tmp/NuGet.config && break; sleep 3; done
RUN for i in 1 2 3; do dotnet restore src/LucentMist.CLI/LucentMist.CLI.csproj --configfile /tmp/NuGet.config && break; sleep 3; done

# 还原后再复制全部源码，避免代码改动使 NuGet 缓存层失效
COPY . .

# 编译运行项目
RUN dotnet build src/LucentMist.API/LucentMist.API.csproj -c Release --no-restore
RUN dotnet build src/LucentMist.Web/LucentMist.Web.csproj -c Release --no-restore
RUN dotnet build src/LucentMist.CLI/LucentMist.CLI.csproj -c Release --no-restore

# 发布 API
RUN dotnet publish src/LucentMist.API -c Release -o /app/api --no-restore

# 发布 Web
RUN dotnet publish src/LucentMist.Web -c Release -o /app/web --no-restore

# 发布 CLI
RUN dotnet publish src/LucentMist.CLI -c Release -o /app/cli --no-restore

# ============ 运行阶段 ============
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# 安装 curl 用于健康检查（可选）
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制产物
COPY --from=build --chown=app:app /app/api ./api
COPY --from=build --chown=app:app /app/web ./web
COPY --from=build --chown=app:app /app/cli ./cli

# 复制配置模板
COPY --chown=app:app config/ ./config/

# 创建数据目录
RUN mkdir -p /app/data /app/logs && chown app:app /app/data /app/logs

# 容器内默认监听所有接口，直接 docker run -p 也能访问
ENV LMIST_BIND_ADDRESS=0.0.0.0
ENV LMIST_WEB_BIND=0.0.0.0

# 非 root 运行，降低容器被攻破后的提权风险
USER app

# 暴露 API + Web 端口
EXPOSE 5050 5051

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:5050/api/v1/health || exit 1

# 默认启动 API 服务；Web 服务通过 command 覆盖为 web/LucentMist.Web.dll 5051
CMD ["dotnet", "api/LucentMist.API.dll"]
